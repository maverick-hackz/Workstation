# nginx

> Reference paths for nginx config layout on Debian/Ubuntu. Used as a quick-lookup during web-server pentests and post-compromise review. Authorized testing only.

## TL;DR
- `nginx.conf` is the root; `sites-available/` holds defined vhosts; `sites-enabled/` symlinks the active ones.
- Verify which file actually drives behavior with `nginx -T` (dump merged config) — not the on-disk file you happen to be reading.
- Path-traversal and `alias` misconfigurations are the highest-impact nginx issues; see Defence section.

## Detection / Discovery (config paths)

<!-- Russian descriptions preserved verbatim per repo language policy -->

| Path | Description |
| --- | --- |
| `/etc/nginx/nginx.conf` | главный файл конфигурации nginx. |
| `/etc/nginx/sites-available` | каталог с конфигурациями виртуальных хостов, т.е. каждый файл, находящийся в этом каталоге, содержит информацию о конкретном сайте — его имени, IP адресе, рабочей директории и многое другое. |
| `/etc/nginx/sites-enabled` | в этом каталоге содержатся конфигурации сайтов, обслуживаемых nginx, т.е. активных, как правило, это символические ссылки `sites-available` конфигураций, что очень удобно для оперативного включения и отключения сайтов. |

| Command | Description |
| --- | --- |
| `nginx -t` | Validate syntax of the active config |
| `nginx -T` | Print the fully-merged active configuration |
| `nginx -V` | Show compiled-in modules and build flags |

## Defence / Remediation
- **`alias` traversal**: `location /foo { alias /var/www/; }` (no trailing slash) allows `/foo../etc/passwd`. Always pair trailing slash on both `location` and `alias`. (CVE class CWE-22 Path Traversal.)
- **Off-by-one regex on `location`**: `location ~ /foo` matches anywhere; anchor with `^` and use exact (`=`) match where possible.
- Disable `server_tokens` and `autoindex` on production.
- Apply `add_header Strict-Transport-Security`, `X-Content-Type-Options nosniff`, `Content-Security-Policy …` (OWASP Secure Headers Project).
- Run worker as a non-root user; bind privileged ports via capabilities or systemd socket activation.

## Sources
- nginx documentation: https://nginx.org/en/docs/
- Detectify on nginx config pitfalls: https://blog.detectify.com/best-practices/common-nginx-misconfigurations/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
