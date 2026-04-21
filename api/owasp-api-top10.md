# OWASP API Security Top 10 (2023)

> Reference summary of OWASP API Security Project's 2023 edition. Authoritative source: owasp.org/API-Security. Authorized testing only.

## TL;DR
- Released Feb 2023; supersedes the 2019 list. New entries: BOPLA (API3), SSRF (API7); merged entries; renamed clarity.
- Per-risk template below: short description, attack pattern, defence.
- Map findings against this list in API pentest reports; pair with WSTG / ASVS for control mapping.

## API1:2023 — Broken Object Level Authorization (BOLA)
- **Description**: API doesn't verify that the authenticated principal can act on the specific object referenced (vs verifying only that the principal is authenticated).
- **Pattern**: `GET /api/users/{id}` where `{id}` belongs to another tenant; principal auth check passes, object-level check missing.
- **Defence**: per-object ACL check on every request; never trust client-supplied scope. See [../web/idor.md](../web/idor.md). CWE-639.

## API2:2023 — Broken Authentication
- **Description**: weakness in auth mechanism (credential stuffing exposure, weak password reset, JWT alg confusion, missing rate limit on login).
- **Pattern**: `POST /auth/login` accepts unlimited attempts; `POST /auth/forgot-password` reveals user existence; JWT verification accepts `alg=none`.
- **Defence**: MFA, password-spray rate limit, refresh-token rotation, JWT-spec-compliant verification ([../web/jwt-attacks.md](../web/jwt-attacks.md)).

## API3:2023 — Broken Object Property Level Authorization (BOPLA)
- **Description**: API exposes fields the principal shouldn't see, or accepts fields they shouldn't write (mass assignment).
- **Pattern**: `PATCH /api/users/me` body `{"role":"admin"}` accepted; `GET /api/users/{me}` returns `salary`, `ssn`.
- **Defence**: explicit DTOs (input + output schemas); never bind raw request body to model; field-level ACL.

## API4:2023 — Unrestricted Resource Consumption
- **Description**: API doesn't bound expensive operations — file upload size, page size, recursion depth, query complexity (GraphQL), regex (ReDoS), thumbnail generation.
- **Pattern**: `GET /api/products?limit=999999999`; GraphQL nested query 10 levels deep; deeply nested JSON.
- **Defence**: per-resource quotas (size, page-limit, time-limit, complexity-limit); GraphQL `complexity` plugin; ReDoS-safe regex / `re2`. CWE-400.

## API5:2023 — Broken Function Level Authorization (BFLA)
- **Description**: principal can call admin / privileged endpoints they're not entitled to.
- **Pattern**: regular user can `POST /api/admin/users/delete` because the admin route exists and ACL is only on the UI.
- **Defence**: ACL at endpoint level; positive-model permission check; consistent role enforcement across REST / GraphQL / RPC.

## API6:2023 — Unrestricted Access to Sensitive Business Flows
- **Description**: business flow exposed without protections appropriate to its risk (bulk order, ticket purchase, free trial abuse, automated comment posting).
- **Pattern**: `POST /api/order` lets a bot purchase 10000 concert tickets in 30s.
- **Defence**: anti-automation (CAPTCHA, device fingerprinting, behavioral analytics), rate-limit per-flow not per-endpoint, business-logic-aware throttling. Maps loosely to OWASP Automated Threats (OAT).

## API7:2023 — Server-Side Request Forgery (SSRF)
- **Description**: API fetches an attacker-controlled URL — webhook URL, image-by-URL upload, document fetch, SVG renderer, cloud-instance integration.
- **Pattern**: `POST /api/import {"url":"http://169.254.169.254/..."}` (cloud IMDS).
- **Defence**: hostname allow-list, DNS-pinning, block private/link-local on resolved IP, no HTTP redirects across resolution. See [../cloud/ssrf-cloud-metadata.md](../cloud/ssrf-cloud-metadata.md). CWE-918.

## API8:2023 — Security Misconfiguration
- **Description**: CORS too permissive, missing TLS, default credentials, verbose errors, missing security headers, debug endpoints exposed (`/actuator/heapdump`, `/api/v1/debug`).
- **Pattern**: `Access-Control-Allow-Origin: *` on credentialed endpoint; Spring Boot Actuator `heapdump` reveals creds; default Tomcat manager creds.
- **Defence**: security baseline per-stack (Spring Actuator: ship `info,health` only, all else off; Nginx: hardened config — see [../cheatsheets/nginx.md](../cheatsheets/nginx.md)); CIS-Benchmarks-aligned image; OWASP Secure Headers Project.

## API9:2023 — Improper Inventory Management
- **Description**: deprecated API versions still reachable, staging API on the same domain, undocumented endpoints exposed, third-party API integrations not catalogued.
- **Pattern**: `/api/v1/` deprecated but no auth; `/api/internal/` reachable from internet; OAS spec on a public URL exposes shadow endpoints.
- **Defence**: API inventory (Akamai API Discovery, Salt, Noname, or open-source `kiterunner`), retire-and-block legacy versions, schema-as-source-of-truth (OpenAPI / GraphQL SDL) with admission control rejecting undocumented routes.

## API10:2023 — Unsafe Consumption of APIs
- **Description**: consumer treats third-party API responses as trusted (no validation, no rate-limit on responses, blind redirects).
- **Pattern**: integration with a partner API; the partner is breached and returns malicious payloads; consumer renders them in user pages without escape → XSS.
- **Defence**: validate every cross-boundary response (schema + content); same SSRF/XSS controls apply outbound; rate-limit + circuit breaker; sign and verify exchange where the partner supports it.

## Quick mapping

| Risk | WSTG | CWE |
| --- | --- | --- |
| API1 BOLA | WSTG-ATHZ-04 | CWE-639 |
| API2 Broken Auth | WSTG-ATHN-* | CWE-287 |
| API3 BOPLA | — | CWE-915, CWE-732 |
| API4 Unrestricted Resource | — | CWE-400, CWE-770 |
| API5 BFLA | WSTG-ATHZ-02 | CWE-285 |
| API6 Unrestricted Business Flow | OWASP OAT | CWE-840 |
| API7 SSRF | WSTG-INPV-19 | CWE-918 |
| API8 Misconfig | WSTG-CONF-* | CWE-16 |
| API9 Inventory | — | CWE-1059 |
| API10 Unsafe Consumption | — | CWE-829 |

## Sources
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- OWASP Application Security Verification Standard (ASVS): https://owasp.org/www-project-application-security-verification-standard/
- OWASP Automated Threats (OAT): https://owasp.org/www-project-automated-threats-to-web-applications/
- HackTricks API pentest: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/rest-api-pentesting.html
- PayloadsAllTheThings API: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API
