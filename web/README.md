# Web

Application-layer vulnerability cheatsheets — detection, exploitation, bypass, and remediation guidance for each class. Sources cite OWASP WSTG, PortSwigger Academy, OWASP Cheat Sheet Series, PayloadsAllTheThings, and HackTricks.

## Index

| File | WSTG | MITRE ATT&CK |
| --- | --- | --- |
| [cache-deception.md](./cache-deception.md) | — | — |
| [checklist.md](./checklist.md) | [WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/) | — |
| [command-injection.md](./command-injection.md) | [WSTG-INPV-12](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection) | [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| [cors.md](./cors.md) | [WSTG-CONF-07](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_Cross_Origin_Resource_Sharing) | — |
| [crlf-header-injection.md](./crlf-header-injection.md) | [WSTG-INPV-15](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling) | — |
| [csrf.md](./csrf.md) | [WSTG-SESS-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery) | — |
| [deserialization.md](./deserialization.md) | [WSTG-INPV-11](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [dom-clobbering.md](./dom-clobbering.md) | — | — |
| [http-request-smuggling.md](./http-request-smuggling.md) | [WSTG-INPV-15](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [http-verb-tampering.md](./http-verb-tampering.md) | [WSTG-CONF-06](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods) | — |
| [idor.md](./idor.md) | [WSTG-ATHZ-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) | — |
| [jwt-attacks.md](./jwt-attacks.md) | [WSTG-SESS-10](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens) | — |
| [ldap-injection.md](./ldap-injection.md) | [WSTG-INPV-06](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection) | — |
| [lfi-rfi.md](./lfi-rfi.md) | [WSTG-INPV-11](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) / [WSTG-INPV-12](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [nosqli.md](./nosqli.md) | — | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [oauth-saml.md](./oauth-saml.md) | [WSTG-ATHN-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel) | [T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) |
| [open-redirect.md](./open-redirect.md) | [WSTG-CLNT-04](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect) | — |
| [prototype-pollution.md](./prototype-pollution.md) | — | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [race-conditions.md](./race-conditions.md) | — | — |
| [sqli.md](./sqli.md) | [WSTG-INPV-05](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [ssrf.md](./ssrf.md) | [WSTG-INPV-19](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [ssti.md](./ssti.md) | [WSTG-INPV-18](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| [upload-bypass.md](./upload-bypass.md) | [WSTG-BUSL-09](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Unexpected_File_Types) | [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| [xss.md](./xss.md) | [WSTG-INPV-01](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting) / [WSTG-INPV-02](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting) | [T1059.007 JavaScript](https://attack.mitre.org/techniques/T1059/007/) |
| [xxe.md](./xxe.md) | [WSTG-INPV-07](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection) | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |

## Framework deep-dives
Phase 9j adds a `web/frameworks/` subdirectory with Spring Boot Actuator, WordPress, Jenkins, GitLab, Laravel, Django admin cheatsheets.

## Sources
- OWASP Web Security Testing Guide v4.2: https://owasp.org/www-project-web-security-testing-guide/v42/
- OWASP Top 10 (2021): https://owasp.org/Top10/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- HackTricks Pentesting Web: https://book.hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology.html
