# Frida & Objection

> Dynamic instrumentation toolkit (Frida) + curated mobile-pentest helpers (objection). Hook native + managed runtime methods on Android/iOS. Authorized testing only.

## TL;DR
- Frida ships a server agent (`frida-server`) running on the device + a host CLI (`frida`, `frida-trace`, `frida-ps`) that injects JS into the target process.
- Objection wraps Frida with pre-built bypasses: root/jailbreak detection, TLS pinning, biometric prompts, anti-debug.
- Two attach modes: spawn (`-f <pkg>`) for one-shot at process start, or attach (`-n <name>`) to an already-running process.
- Workflow: `objection explore` for quick wins → drop to bespoke Frida scripts when objection's bypass list misses a custom check.

## Setup
| Step | Command |
| --- | --- |
| Install host CLI | `pip install frida-tools objection` |
| Push Android frida-server | `adb push frida-server-<ver>-android-arm64 /data/local/tmp/fs && adb shell "chmod 755 /data/local/tmp/fs && /data/local/tmp/fs &"` |
| iOS frida-server | Install `re.frida.server` from Cydia/Sileo (jailbroken device) |
| Smoke test | `frida-ps -U` (USB) or `frida-ps -H <host>:<port>` (network) |

## Detection / Discovery
| Command | Description |
| --- | --- |
| `frida-ps -U` | List processes on USB-connected device |
| `frida-ls-devices` | Enumerate frida-discoverable devices |
| `frida-trace -U -f com.target -i 'open*' -i 'read*'` | Trace any function matching glob (POSIX-style on iOS; Java on Android with `-j`) |
| `objection -g com.target explore` | Interactive REPL — `env`, `ios info binary`, `android hooking list classes`, etc. |
| `objection -g com.target patchapk -s app.apk` | Build a Frida-gadget-injected APK (works without root) |

## Exploitation — common Frida one-liners

### Android: hook a Java method
```js
Java.perform(function () {
  var Crypto = Java.use('com.target.Crypto');
  Crypto.encrypt.implementation = function (data) {
    console.log('[encrypt input]', data);
    var out = this.encrypt(data);
    console.log('[encrypt output]', out);
    return out;
  };
});
```
Run: `frida -U -l hook.js -f com.target --no-pause`

### iOS: hook an Objective-C method
```js
var Crypto = ObjC.classes.Crypto;
Interceptor.attach(Crypto['- encrypt:'].implementation, {
  onEnter(args) {
    console.log('[encrypt input]', ObjC.Object(args[2]).toString());
  },
  onLeave(retval) {
    console.log('[encrypt output]', ObjC.Object(retval).toString());
  }
});
```

### Objection one-liners (pre-built bypasses)
| Command | Description |
| --- | --- |
| `android root disable` | Patch common root-detection checks |
| `ios jailbreak disable` | Patch common jailbreak-detection checks |
| `android sslpinning disable` | Patch OkHttp / TrustManager / WebView pinning |
| `ios sslpinning disable` | Patch URLSessionDelegate + low-level pinning (Cordova / Capacitor / Flutter variants in extra modules) |
| `ios ui biometrics_bypass` | Force `LAContext.evaluatePolicy` callback to success |
| `android keystore list` / `ios keychain dump` | Pull stored secrets |
| `memory dump all <output>` | Dump process memory (for token recovery) |

## Bypasses (when stock objection fails)
- App detects Frida by scanning `/proc/self/maps` for `frida-agent` — load via `frida-gadget` injected at link time (no agent in memory list) or rename the gadget.
- App checks port 27042 (default Frida-server port) — start frida-server with `-l 127.0.0.1:<custom>`.
- Anti-Frida via `dlopen` checks on `libfrida-gadget.so` — bundle as `libapp.so` instead.
- iOS jailbreak-detection via `dyld` symbol-list — strip / rename the embedded check function (`getJailbreakStatus`-style).

## Defence / Remediation (for app developers)
- **Anti-Frida** alone is a delay control (CWE-693 Protection Mechanism Failure). Combine with:
  - Server-side checks (Play Integrity / App Attest attestation tied to request).
  - Defence-in-depth around the data the hook would target — server-issued, short-lived, scope-narrow tokens; never long-lived secrets baked into the binary.
- **Don't rely on TLS pinning alone** to authenticate the app — pinning prevents MitM but not a Frida hook that reads the cleartext above the TLS layer. Sign sensitive requests with App Attest-issued keys.
- **Treat any control inside the app process as untrusted** for high-assurance flows; move those checks server-side.

## Sources
- Frida documentation: https://frida.re/docs/home/
- Frida JavaScript API: https://frida.re/docs/javascript-api/
- objection wiki: https://github.com/sensepost/objection/wiki
- OWASP MASTG — Tampering and Reverse Engineering: https://mas.owasp.org/MASTG/0x04c-Tampering-and-Reverse-Engineering/
- HackTricks Frida tutorial: https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/frida-tutorial/index.html
