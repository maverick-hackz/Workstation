# API

REST / GraphQL / gRPC pentest cheatsheets + OWASP API Security Top 10 reference. Authorized testing only.

## Index

| File | WSTG / API Top 10 | MITRE ATT&CK |
| --- | --- | --- |
| [grpc.md](./grpc.md) | API Top 10 (full); see [./owasp-api-top10.md](./owasp-api-top10.md) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [owasp-api-top10.md](./owasp-api-top10.md) | API1..API10 (2023) | — |
| [rest.md](./rest.md) | API Top 10 (full) + [WSTG-APIT-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |

## Still planned
- `graphql.md` — introspection, batch query abuse, alias-based brute force.

## Sources
- OWASP API Security Project: https://owasp.org/www-project-api-security/
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x00-header/
- REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- HackTricks API: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/rest-api-pentesting.html
- HackTricks gRPC: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-grpc-protobuf.html
