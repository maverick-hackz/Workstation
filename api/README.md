# API

REST / GraphQL / gRPC pentest cheatsheets. Authorized testing only.

## Index

| File | WSTG | OWASP API Top 10 | MITRE ATT&CK |
| --- | --- | --- | --- |
| [rest.md](./rest.md) | [WSTG-APIT-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL) (closest WSTG match — GraphQL section) | API1-API10 (2023) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |

## Planned (Phase 6)
- `graphql.md` — introspection, batch query abuse, alias-based brute force.
- `owasp-api-top10.md` — BOLA, BUA, BOPLA, UCC, BFLA, server-side request forgery, etc.
- `grpc.md` — reflection, proto enumeration, transport-level attacks.

## Sources
- OWASP API Security Project: https://owasp.org/www-project-api-security/
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x00-header/
- REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- HackTricks API: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/rest-api-pentesting.html
