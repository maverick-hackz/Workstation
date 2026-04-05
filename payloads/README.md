# Payloads

Drop-in attack payloads grouped by vector. Authorized testing only — payloads here trigger XSS, CSRF, SSRF, and PDF-borne attacks.

## Contents

| Directory | Purpose | Companion cheatsheet |
| --- | --- | --- |
| [csrf/](./csrf/) | Cross-Site Request Forgery HTML forms (auto-submit & user-interaction variants) | (Phase 6) `web/csrf.md` |
| [csv/](./csv/) | CSV-injection / formula-injection payloads | — |
| [pdf/](./pdf/) | PDF-borne XSS / SSRF / open-redirect / JS-execution samples | — |
| [ssrf/](./ssrf/) | SSRF templates (localhost, AWS EC2 metadata, LFI-from-XSS) | (Phase 6) `web/ssrf.md` |
| [xss/](./xss/) | XSS PoC pages (data grabbers, keylogger, CSS-based, post-message, markdown, SVG variants) | [../web/xss.md](../web/xss.md) |

## Usage notes
- These files **execute attack behaviour** when rendered in a browser. Open in a sandbox / isolated VM, never on a daily-driver profile.
- Replace placeholder hosts (`localhost`, `attacker.tld`, `OUR_IP`) with your authorized listener before delivery.
- CSV-injection payloads only fire when the consuming spreadsheet (Excel / LibreOffice / Google Sheets) auto-evaluates formulas — verify the target stack before using.

## Defence / Remediation (summary)
- CSV-injection: prefix any user-supplied cell starting with `=`, `+`, `-`, `@`, tab, or CR with a single quote on export; CWE-1236.
- XSS PoCs: see [../web/xss.md](../web/xss.md) defence section.
- CSRF: SameSite cookies + anti-CSRF tokens + Origin/Referer validation; OWASP Cheat Sheet.
- SSRF: deny-list + DNS-rebinding-aware fetcher + IMDSv2-equivalents in cloud (see Phase 6 cloud/).
- PDF payloads: server-side rasterization (`pdf2image`) before serving; never serve user-uploaded PDFs from the app origin.

## Sources
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- OWASP Cheat Sheet — CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet — SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- CWE-1236 Improper Neutralization of Formula Elements in a CSV File: https://cwe.mitre.org/data/definitions/1236.html
