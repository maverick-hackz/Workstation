# Subdomain Enumeration

> Discover all subdomains of an in-scope domain — passive (third-party sources) and active (DNS brute force, virtual-host fuzz). Authorized testing only.

## TL;DR
- Passive first (cheap, target-invisible): certificate-transparency logs, search engines, threat-intel feeds. Sources: `crt.sh`, `subfinder`, `amass enum -passive`, `chaos-client`, `securitytrails`.
- Active second (target-visible): DNS brute force with `puredns`/`shuffledns`/`amass enum -active`, virtual-host fuzzing with `ffuf -H 'Host: FUZZ.target.tld'`.
- Probe + resolve + validate workflow: `subfinder | httpx -title -tech-detect -status-code -ports 80,443,8080,8443`.
- Defence: same continuous-recon posture (see [./osint.md](./osint.md)); restrict wildcard DNS in production zones; CT-log monitoring.

## Detection / Discovery

### Passive
| Tool | What |
| --- | --- |
| `subfinder -d target.tld` | Aggregates 20+ passive sources (CT, search engines, Shodan, VirusTotal). |
| `amass enum -passive -d target.tld` | OWASP project; deeper aggregation; slower. |
| `assetfinder --subs-only target.tld` | Lighter alternative; tomnomnom maintained. |
| `findomain -t target.tld` | Rust, very fast. |
| `chaos-client -d target.tld` | ProjectDiscovery's CT/passive dataset. |
| `crt.sh` API (curl JSON) | Manual baseline; what every tool ingests. |

```bash
# Combine sources, dedupe
( subfinder -silent -d target.tld
  amass enum -passive -d target.tld
  assetfinder --subs-only target.tld
  curl -s "https://crt.sh/?q=%25.target.tld&output=json" | jq -r '.[].name_value'
) | sort -u > subs.txt
wc -l subs.txt
```

### Active — DNS brute force
| Tool | What |
| --- | --- |
| `puredns bruteforce wordlist.txt target.tld` | Fastest; uses pre-vetted resolver list; handles wildcards. |
| `shuffledns -d target.tld -w wordlist.txt -r resolvers.txt` | ProjectDiscovery; integrates with httpx. |
| `amass enum -brute -d target.tld -w wordlist.txt` | Built-in. |
| `dnscan -d target.tld -w wordlist.txt` | Simple. |

Resolver list — use a vetted list (`puredns` ships with one) or self-host (massdns / `trickest/resolvers`). Bad resolvers return false positives.

Wordlists:
- `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt`
- `assetnote.io/resources/best-dns-wordlist.txt` (curated)
- Combine with permutations: `altdns -i subs.txt -w permutations.txt -o permuted.txt` then resolve.

### Active — virtual-host (vhost) fuzz
DNS may resolve `*.target.tld` to the same IP, but the web server returns different content per `Host:` header:
```bash
ffuf -w wordlist.txt:FUZZ -u https://target.tld/ \
     -H "Host: FUZZ.target.tld" \
     -fs <baseline-content-length>
```
See [../cheatsheets/ffuf.md](../cheatsheets/ffuf.md) for ffuf details.

### Probe alive + fingerprint
```bash
# After enumeration, probe HTTP(S) and fingerprint
cat subs.txt | httpx -silent -title -tech-detect -status-code -ports 80,443,8000,8080,8443,9000

# Take screenshots for triage
cat subs.txt | gowitness scan file -f -
# Or aquatone (deprecated but classic)

# Active CVE scan once in-scope (do NOT run against random discovery)
cat in-scope.txt | nuclei -t cves/ -severity critical,high
```

## Exploitation
Subdomain enumeration is recon; output feeds:
- Per-host scoping for the active test phase.
- Discovery of forgotten staging / dev / CMS instances (often weakly-authenticated).
- Subdomain takeover candidates (CNAME → unclaimed third-party service).

### Subdomain takeover detection
```bash
# Find subdomains pointing at third-party services (Heroku, Azure, GitHub Pages, S3, etc.)
# where the resource is no longer owned -> attacker claims it -> serves content under target's domain.

# subjack / subzy / takeover.py
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v -o takeovers.txt
nuclei -t takeovers/ -l subs.txt
```
Vulnerable fingerprints catalog: https://github.com/EdOverflow/can-i-take-over-xyz

## Bypasses (against incomplete blue-team posture)
- DNS wildcard `*.target.tld → 1.2.3.4` masks brute force results — `puredns` and `shuffledns` detect and strip wildcard responses.
- CT logs only cover **public** CAs — internal subdomains (`*.internal.target.tld`) signed by internal CA aren't on crt.sh. Find via passive DNS / leaked internal docs.
- Cloudflare / CDN proxying hides origin IPs from passive DNS; use `crimeflare`/`CloudFail`/historical CT for origin discovery.

## Defence / Remediation
- **CT-log monitoring** for the org's domain — `cert-spotter` / Sectigo CT alerts. Catch unauthorised cert issuance early.
- **Subdomain inventory** owned by the org centrally (CMDB / spreadsheet). Decommission proceedure must include DNS-record removal — most takeovers are dangling DNS to a deprovisioned cloud resource.
- **Disable wildcard DNS** in production zones unless explicitly needed; wildcards mask new subdomain creation.
- **DNSSEC** on org zones — closes spoofing attack class.
- **Provisioning workflow** that creates DNS records *after* claiming the underlying resource (cloud bucket / SaaS-app) — kills dangling-record takeover.
- **Continuous external scan** — same tools run by blue team weekly; new asset within 24h appears in the inventory.

## Sources
- ProjectDiscovery — subfinder, shuffledns, httpx, nuclei: https://github.com/projectdiscovery
- OWASP Amass: https://github.com/owasp-amass/amass
- puredns: https://github.com/d3mondev/puredns
- altdns (permutations): https://github.com/infosec-au/altdns
- Assetnote wordlists: https://wordlists.assetnote.io/
- can-i-take-over-xyz (subdomain takeover catalog): https://github.com/EdOverflow/can-i-take-over-xyz
- subjack: https://github.com/haccer/subjack
- gowitness: https://github.com/sensepost/gowitness
- HackTricks subdomain enum: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html#subdomains
- Tomnomnom toolchain (assetfinder, anew, gf, waybackurls): https://github.com/tomnomnom
