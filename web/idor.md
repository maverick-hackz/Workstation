# IDOR — Insecure Direct Object Reference

> Authorization bypass via direct reference to internal objects (record IDs, filenames, keys) without per-object access checks. Authorized testing only.

## TL;DR
- IDOR = "the server trusts the client to ask for objects it's allowed to see".
- Probe by changing IDs (`?id=124` → `?id=125`), UUIDs (looking for guessable patterns), filenames, hashed references (decode and re-hash to neighbouring values).
- Common in API routes: `GET /api/users/{id}`, `GET /api/orders/{id}/invoice`.
- CWE-639 Authorization Bypass Through User-Controlled Key; OWASP API Top 10 #1: API1:2023 — Broken Object Level Authorization (BOLA).

## Detection / Discovery
Where to look (from the source notes):
- URL parameters & APIs
- AJAX calls
- Reference hashing/encoding (MD5/Base64 of predictable inputs)
- Comparison across user roles (login as A, request B's resources)

| Approach | Description |
| --- | --- |
| Burp Repeater / curl with auth-A cookies on auth-B resources | Cross-account check |
| Decode reference: `echo dXNlcl8x \| base64 -d` → `user_1` | Reveals predictable encoding |
| Hash space probe | If reference is `md5(user_id)`, attacker brute-forces neighbouring `md5(N)` values |

| Command | Description |
| --- | --- |
| `md5sum` | MD5-hash a string (probe candidate references) |
| `base64` | Base64 encode/decode a string |

## Exploitation
```bash
# Authenticated as user_1, fetch user_2's invoice
curl -H "Cookie: session=A1B2C3" https://target/api/users/2/invoice

# Decode a hashed reference, mutate, re-hash
echo -n "user_1" | md5sum   # baseline
echo -n "user_2" | md5sum   # neighbour
curl https://target/file?ref=$(echo -n user_2 | md5sum | cut -d' ' -f1)
```

## Bypasses
- IDs in headers (`X-User-Id`, `X-Account`) — try setting them.
- Method swap: `GET /api/order/123` may be auth-checked while `POST /api/order/lookup` with `{"id":123}` is not.
- Mass assignment + IDOR: `PATCH /api/me` with `{"role":"admin"}` (BOPLA = API3:2023).
- "Forgot password" / "share link" flows often expose object handles without re-checking the requester.

## Defence / Remediation
- **Object-level authorization on every request**, scoped to the authenticated principal. ABAC or RBAC enforced server-side; never trust client-supplied IDs of "scope".
- Use indirect references where possible (per-session opaque tokens that the server maps to real IDs) — but the authoritative check is still required.
- Centralize the check in a middleware/policy layer; unit-test "cross-user fetch" cases.
- Don't rely on UUIDs alone — UUIDv1 leaks timestamp/MAC; UUIDv4 is unpredictable but still a direct reference an unauthorised principal might possess.
- API: log per-object access; alert on cross-account access patterns.

## Sources
- OWASP WSTG-ATHZ-04 Test Insecure Direct Object References: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- OWASP API Security — API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- PortSwigger Access Control: https://portswigger.net/web-security/access-control
- PayloadsAllTheThings Insecure Direct Object References: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Insecure%20Direct%20Object%20References.md
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
