# OSINT — Open-Source Intelligence

> Passive collection of public-source information about a target before active testing. No probing the target's infrastructure. Authorized engagements only.

## TL;DR
- OSINT is **passive** — queries to third-party services (search engines, registrars, CT logs, threat feeds, social media) that the target can't see.
- Output: domain inventory, IP ranges, employee names + emails + roles, tech stack, leaked credentials, exposed cloud resources, historical attack surface.
- Tools chain by phase: identifier discovery → asset inventory → exposure check → leak corpus search.
- Defence (from defender side): scan your own attack surface with the same tools weekly; assume what you can see, attackers can too.

## Detection / Discovery

### Domain & DNS
| Source | What |
| --- | --- |
| `whois <domain>` | Registrar, registrant, contact emails (often privacy-redacted). |
| RDAP (https://rdap.org/) | Modern WHOIS replacement; structured JSON. |
| `dig` / `host` | Authoritative DNS records (A, AAAA, MX, NS, TXT, CAA, SPF, DMARC). |
| Certificate Transparency (CT) — `crt.sh`, `cert.sh`, `merklemap` | Every cert issued by a public CA. Best subdomain source. |
| `viewdns.info`, `securitytrails.com`, `dnsdumpster.com` | Aggregated historical DNS records. |
| `ipinfo.io`, `bgp.he.net`, `bgpview.io` | ASN inventory; map an org's IP ranges. |
| Reverse DNS sweep (`dig -x` per IP in ASN) | Find virtual hosts. |

```bash
# Certificate transparency for all subdomains
curl -s "https://crt.sh/?q=%25.target.tld&output=json" | jq -r '.[].name_value' | sort -u

# Shodan inventory by org / cert SAN / favicon hash
shodan search 'ssl.cert.subject.cn:"target.tld"'
shodan search 'http.favicon.hash:<favicon-hash>'   # mmh3 hash via mmh3 or favicon-hasher
```

### People & emails
| Source | What |
| --- | --- |
| LinkedIn (CSE / `linkedint` / Google dorks) | Employee names + roles. |
| `hunter.io` / `phonebook.cz` / `clearbit` | Org email format (`first.last@target.tld`). |
| `theHarvester` | Email harvesting via passive sources (Bing, Baidu, DuckDuckGo, Github, Hunter). |
| Microsoft Graph (when target Microsoft 365 is tenant-leaky) | `https://login.microsoftonline.com/getuserrealm.srf?login=<email>` reveals tenant federation. |
| `O365creeper` / `o365enum` | Validate emails against M365 / OWA — borderline-active (target sees the lookups). |

### Code & credentials
| Source | What |
| --- | --- |
| GitHub Code Search (`org:target` / `target.tld`) | Hard-coded secrets, repo names, employee usernames. |
| `gitleaks` / `trufflehog` against the org's public repos | Automated secret scan. |
| `Have I Been Pwned` (HIBP) | Breach corpora for emails. |
| `Dehashed` (commercial) / `IntelligenceX` (commercial) | Combined breach corpora + paste-bin search. |
| `gitlab.com search`, `pypi`, `npm` public packages from the org | Same secret-scan angle. |

```bash
# Github search via gh CLI
gh search code --owner target-org 'AWS_ACCESS_KEY'
gh search code 'target.tld smtp_password'
```

### Cloud resources
| Source | What |
| --- | --- |
| `GrayhatWarfare` (https://buckets.grayhatwarfare.com/) | Indexed public S3 / GCS / Azure containers. |
| `GCPBucketBrute`, `cloud_enum`, `s3scanner` | Active bucket-name brute (semi-active; cheap probes to cloud, not target). |
| Searx + dorks: `site:s3.amazonaws.com target` | Indexed public S3 content. |
| `azurewebsites.net`, `cloudapp.net`, `herokuapp.com` brute | App-hosting subdomain enumeration. |

### Document metadata
| Source | What |
| --- | --- |
| `FOCA` / `metagoofil` | Download public PDF/DOCX/XLS from the org and extract metadata (`Author`, `Producer`, internal paths). |
| `exiftool` on harvested files | Same, file-by-file. |

```bash
# Google dork for public docs from the org
# (Run searches manually; automation = ToS violation)
filetype:pdf site:target.tld
filetype:xls site:target.tld confidential
```

### Mobile / app stores
| Source | What |
| --- | --- |
| Google Play / Apple App Store | Published mobile apps. |
| `aapt dump badging` / `class-dump` on downloaded APK / IPA | Tech stack, embedded API hosts, hard-coded keys. |
| `apkmonk` / `apkpure` cache | Historical APK versions. |

### Continuous-recon platforms
- **`Amass`** (OWASP) — one-stop passive + active recon orchestrator.
- **`subfinder`** — passive subdomain enum only.
- **`assetfinder`**, **`findomain`** — passive crawl of multiple sources.
- **`recon-ng`** — modular framework (older but maintained).

## Exploitation
OSINT is recon, not exploitation. The output feeds:
- Target list for [./subdomain-enum.md](./subdomain-enum.md) active enumeration.
- Email list for phishing / password spray (in authorized engagements).
- Employee list for OSINT-driven access (USB drops, social engineering — within ROE).
- Tech-stack fingerprint for CVE searches (`cve.mitre.org`, `vulners.com`, `exploit-db.com`).
- Leaked credentials for **password reuse** checks on the in-scope endpoint.

## Defence / Remediation
- **Inventory your own attack surface** continuously. Same tools, run by the blue team weekly. Catch new exposures (cert issued for staging.target.tld, S3 bucket made public) within hours, not weeks.
- **Tighten WHOIS privacy** on every domain; use a privacy proxy at the registrar.
- **CT-log monitoring**: subscribe to `cert-spotter` / `Sectigo CT` alerts for `*.target.tld` — new certs flag.
- **Public-cloud bucket policies**: deny public ACLs at the account / org level (see [../cloud/aws.md](../cloud/aws.md) defence).
- **Secret-scanning in CI**: `gitleaks`/`trufflehog`/`detect-secrets` pre-commit + GitHub Push Protection.
- **Document-metadata scrub** on anything published from the org domain (LibreOffice → File → Properties → Reset; PDF → exiftool -all=).
- **MFA + rotation** of any credential surfaced in a breach corpus; assume breach-list reuse against your auth.
- **Disable email-existence oracles** in M365 (`Get-MsolCompanyInformation`-tuneable), self-service password reset, etc. — closes the user-enumeration angle.

## Sources
- OWASP WSTG-INFO — Information Gathering chapter: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/
- HackTricks External Recon: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html
- Bellingcat — OSINT toolkit & methodology: https://www.bellingcat.com/category/resources/
- OSINT Framework (link directory): https://osintframework.com/
- crt.sh: https://crt.sh/
- Amass: https://github.com/owasp-amass/amass
- subfinder: https://github.com/projectdiscovery/subfinder
- theHarvester: https://github.com/laramies/theHarvester
- recon-ng: https://github.com/lanmaster53/recon-ng
- gitleaks: https://github.com/gitleaks/gitleaks
- trufflehog: https://github.com/trufflesecurity/trufflehog
- HIBP: https://haveibeenpwned.com/
