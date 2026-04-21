# OAuth 2.0 & SAML Attacks

> Authorization-flow abuse: redirect_uri manipulation, state CSRF, code/token leakage, SAML XML Signature Wrapping (XSW). Authorized testing only.

## TL;DR
- OAuth 2.0 is an *authorization* protocol — it doesn't say anything about authentication. OIDC layers ID tokens on top.
- Biggest OAuth issues: open `redirect_uri`, missing/weak `state` (CSRF), `code` interception via referrer leakage, implicit-flow token leakage in URL fragment, mix-up attacks across multiple IdPs.
- SAML's biggest issue: XML Signature Wrapping (XSW) — signatures cover one element, the parser reads a different element.
- Defence: PKCE for all clients (incl. confidential), strict `redirect_uri` allow-list, `state` enforced, SAML signature validation that pins which element is signed.

## OAuth 2.0

### Detection / Discovery
- Identify the IdP: Google, Okta, Auth0, Azure AD, Cognito, Keycloak — each has known quirks.
- Find the authorization endpoint (`/oauth/authorize` or `/.well-known/openid-configuration` lists it).
- Confirm grant type: `code` (Authorization Code; safest with PKCE), `token` (Implicit; deprecated by OAuth 2.1), `password` (ROPC; deprecated), `client_credentials` (server-to-server).
- Note `redirect_uri` value; check whether path validation is strict or substring/prefix-match.

### Exploitation — `redirect_uri` open redirect
The IdP returns `code` to whatever URL is in `redirect_uri` after validating it against the client's registered list. Validation bugs:
| Bug | Payload |
| --- | --- |
| Substring match | `https://app.com.attacker.com/cb` |
| Prefix match | `https://app.com/cb/../../@attacker.com` |
| Fragment append | `https://app.com/cb#@attacker.com/` |
| Open redirect on `app.com` chained | `https://app.com/cb?next=https://attacker.com/` then code-bearer redirected |
| Localhost dev exception | `http://localhost:port/cb` registered for dev; race on a public network |
| Whitespace / unicode quirks | `https://app.com/cb%09@attacker.com/` |

Once `code` reaches attacker → exchange at the token endpoint → access token → game over.

### Exploitation — missing/static `state`
`state` is a nonce that binds the authorization request to the session. If missing or static, attacker initiates flow, sends victim a link with attacker's `code`, victim's browser exchanges → attacker now logged into victim's account ("CSRF on login").

### Exploitation — `code` interception
- HTTP-referrer leakage: callback page includes a 3rd-party script (analytics, ad pixel) — `Referer` carries the URL containing `?code=...`.
- Browser-cache: callback URL stored in history. Useful only on shared devices.
- Mobile: custom URL schemes (`com.app:/cb`) registerable by any app — install a malicious app on the device, register the same scheme → intercept callback.
- Mitigation for mobile: use App Links / Universal Links (verified by domain ownership) + PKCE.

### Exploitation — PKCE downgrade
Some IdPs accept requests without PKCE even for public clients that should use it. Strip the `code_challenge`, intercept the `code`, exchange it at the token endpoint (no `code_verifier` required → succeeds).

### Exploitation — Implicit flow token leakage
`token` returned in URL fragment (`#access_token=...`). Fragment survives referrer-policy = strict-origin but leaks to:
- JavaScript on the callback page (XSS on the callback page → token theft).
- Browser history.
- Logging.

OAuth 2.1 deprecates Implicit; new apps should use Authorization Code + PKCE.

### Exploitation — mix-up / multi-IdP
App supports multiple IdPs. Attacker initiates flow with IdP-A, swaps the response to point at the IdP-B callback. App sees a valid code/token from "some IdP" and links it to whichever account the attacker controls.

### Defence / Remediation (OAuth)
- **PKCE everywhere** (RFC 7636) — `S256` challenge, never `plain`.
- **`state` mandatory** + bound to session; reject if missing or doesn't match server-stored value.
- **`redirect_uri` exact match** (no substring, no prefix). HTTPS-only for production clients.
- **No fragment-based grant types** for new flows (kill Implicit).
- **Refresh-token rotation** + revocation on detection of reuse (sentinel-pattern detection).
- **Confidential client**: client_secret in secure storage; never in JS. Public clients (SPAs, mobile) must use PKCE.
- **JWT access tokens**: validate signature, `aud`, `iss`, `exp` server-side per request — see [./jwt-attacks.md](./jwt-attacks.md).

## SAML

### Detection / Discovery
- Find the SP's SAML AuthnRequest endpoint (`/saml/login`, `/saml2/login`) and ACS (`/saml/acs`).
- Get the SP metadata: `/saml/metadata` — exposes entity ID, ACS URL, signing/encryption requirements, supported NameID format.
- Capture an unmodified SAML response with SAML Raider Burp extension or proxy with response decoding (responses are base64-encoded XML).

### Exploitation — XML Signature Wrapping (XSW)
The signature in a SAML response covers a specific element (typically the assertion). The XML parser may then read a *different* element if attacker arranges the document so the un-signed element appears earlier / nested differently.
- **XSW 1-8** variants — SAML Raider has them as one-click attacks.
- Classic: original signed Assertion present (passes signature verification), but a duplicate Assertion with attacker-controlled NameID is what the SP business-logic reads.

### Exploitation — XML External Entity (XXE) in SAML
SAML responses are XML. If the SP parses with external-entity resolution enabled → XXE (see [./xxe.md](./xxe.md)).

### Exploitation — IdP-initiated SSO
SP accepts unsolicited SAML responses (no AuthnRequest in flight). Attacker logged into the IdP can craft a response to a victim SP. Defence: SPs should require an `InResponseTo` matching a stored AuthnRequest ID.

### Exploitation — comment injection in NameID / SAML attribute
Some XML parsers handle `<!-- -->` comments inconsistently. `user@example.com<!--evil-->@victim.com` may be parsed as `user@example.com` by one component and the full value by another (Auth0 fixed an instance in 2018).

### Exploitation — accepts unsigned assertion
SP misconfigured to not require signature → attacker forges responses entirely.

### Defence / Remediation (SAML)
- **Sign the assertion**, not just the response; require both at the SP if your IdP supports it.
- **Validate the XML before signature check** — parse with secure defaults (DTD disabled, no external entity resolution, no external schema fetch). XSW exploits the gap between parse and verify; close it by pinning which element is signed and checking after.
- **`InResponseTo` enforced** + nonce store with TTL on the SP.
- **Encrypt assertions** (SAML EncryptedAssertion) for sensitive attribute data.
- **Use a maintained SAML library** (Shibboleth, OneLogin's `python3-saml`, `ruby-saml`); avoid bespoke XML signature verification.

## Sources
- OAuth 2.0 Security Best Current Practice (RFC 9700, supersedes 8252 BCP): https://datatracker.ietf.org/doc/html/rfc9700
- OAuth 2.1 draft: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
- PortSwigger — OAuth: https://portswigger.net/web-security/oauth
- PortSwigger — OpenID: https://portswigger.net/web-security/oauth/openid
- OWASP Cheat Sheet — SAML Security: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- OWASP Cheat Sheet — OAuth 2.0: https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Security_Cheat_Sheet.html
- SAML Raider (Burp extension): https://github.com/PortSwigger/saml-raider
- PayloadsAllTheThings OAuth Misconfiguration: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth%20Misconfiguration
- Duo Labs — XML Signature Wrapping (XSW) reference: https://duo.com/labs/research
- HackTricks SAML: https://book.hacktricks.wiki/en/pentesting-web/saml-attacks/index.html
