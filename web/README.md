# Web

Application-layer vulnerability cheatsheets — detection, exploitation, bypass, and remediation guidance for each class. Sources cite OWASP WSTG, PortSwigger Academy, OWASP Cheat Sheet Series, PayloadsAllTheThings, and HackTricks.

## Index

| File | WSTG | MITRE ATT&CK |
| --- | --- | --- |
| [checklist.md](./checklist.md) | [WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/) | — |
| [http-verb-tampering.md](./http-verb-tampering.md) | [WSTG-CONF-06](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods) | — |
| [idor.md](./idor.md) | [WSTG-ATHZ-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) | — |
| [lfi-rfi.md](./lfi-rfi.md) | [WSTG-INPV-11](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) / [WSTG-INPV-12](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [sqli.md](./sqli.md) | [WSTG-INPV-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [xss.md](./xss.md) | [WSTG-INPV-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting) / [WSTG-INPV-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting) | [T1059.007 JavaScript](https://attack.mitre.org/techniques/T1059/007/) |
| [xxe.md](./xxe.md) | [WSTG-INPV-07](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |

## Planned (Phase 6)
- `jwt-attacks.md` — `alg=none`, key confusion, `kid` injection, JWK injection.
- `oauth-saml.md` — flow abuse, redirect_uri tricks, XML Signature Wrapping.
- `http-request-smuggling.md` — CL.TE, TE.CL, H2.CL, H2.TE.
- `prototype-pollution.md` — server- and client-side.
- `deserialization.md` — Java ysoserial, Python pickle, .NET, PHP.
- `csrf.md`, `ssrf.md`, `upload-bypass.md` — listed in target taxonomy.

## Sources
- OWASP Web Security Testing Guide v4.2: https://owasp.org/www-project-web-security-testing-guide/v42/
- OWASP Top 10 (2021): https://owasp.org/Top10/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- HackTricks Pentesting Web: https://book.hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology.html
