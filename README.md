<div align="center">
  <img src="./banner.png" alt="Workstation">
</div>

# Workstation

Personal knowledge base and tooling for AppSec / pentest work — cheatsheets, payloads, scripts, and bundled third-party tools.

> ⚠️ **Authorized testing only.** Materials in this repository are intended for security testing on systems you own or have written authorization to test, education, AppSec research, and CTF competitions. See [DISCLAIMER.md](./DISCLAIMER.md).

## Repository Map

| Directory | Purpose |
| --- | --- |
| [cheatsheets/](./cheatsheets/) | Tool cheatsheets — nmap, ffuf, curl, hydra, find, chisel, nginx, scan, png-analyze |
| [recon/](./recon/) | Service enumeration (FTP, SMB, NFS, DNS, SMTP, SNMP, IMAP, MySQL, MSSQL, IPMI, SSH, RDP, WinRM) |
| [web/](./web/) | Web-application vulnerabilities — XSS, SQLi, XXE, LFI/RFI, IDOR, HTTP verb tampering, JWT, OAuth/SAML, request smuggling, prototype pollution, deserialization, checklist |
| [api/](./api/) | REST + gRPC pentest, OWASP API Top 10 (2023) |
| [mobile/](./mobile/) | Android, iOS, Frida/objection, TLS pinning bypass |
| [cloud/](./cloud/) | AWS, GCP, Azure, cross-provider cloud-metadata SSRF |
| [containers-k8s/](./containers-k8s/) | Docker escape paths, Kubernetes attack paths, image scanning (Trivy/Grype/Syft) |
| [cicd-supply-chain/](./cicd-supply-chain/) | GitHub Actions, Poisoned Pipeline Execution, dependency confusion, SBOM & Sigstore |
| [ad-infrastructure/](./ad-infrastructure/) | Active Directory enumeration, Kerberos, lateral movement |
| [llm-security/](./llm-security/) | Prompt injection, OWASP Top 10 for LLM Applications (2025) |
| [post-exploitation/](./post-exploitation/) | Reverse shells & TTY upgrade |
| [payloads/](./payloads/) | Drop-in payloads — XSS, CSRF, SSRF, CSV-injection, PDF |
| [scripts/](./scripts/) | Python helpers with `argparse` and proper error handling |
| [server-uploads/](./server-uploads/) | Helper binaries to drop on a target — chisel, linpeas, pspy64 + SHA256SUMS |
| [tools/](./tools/) | Bundled third-party tools (offline copies) — see [tools/README.md](./tools/README.md) |

## Main links

 - [Temp email](https://linux0.net/)
 - [Cyberchief](https://gchq.github.io/CyberChef/)
 - [JWT.io](https://jwt.io/)
 - [Request bin](https://requestbin.jumio.com/)
 - [Revshellgenerator](https://tex2e.github.io/reverse-shell-generator/index.html)
 - [SecLists](https://github.com/danielmiessler/SecLists)
 - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
 - [Chat GPT](https://chat.openai.com/)
 - [CVE archive](https://github.com/trickest/cve)
 - [Exploit DB](https://www.exploit-db.com/)
 - [Snyk DB](https://security.snyk.io/)

## Resourses for reading

 - [OWASP WSTG ENG](https://github.com/OWASP/wstg/tree/master/document)
 - [OWASP WSTG RUS](https://github.com/andrettv/WSTG/tree/master/WSTG-ru)
 - [OWASP ASVS RUS](https://github.com/andrettv/ASVS/tree/master/4.0/ru)
 - [OWASP MASTG (Mobile)](https://mas.owasp.org/MASTG/)
 - [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
 - [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
 - [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
 - [HackTricks](https://book.hacktricks.xyz/welcome/readme)
 - [MITRE ATT&CK](https://attack.mitre.org/)
 - [MITRE ATLAS (AI/ML)](https://atlas.mitre.org/)
 - [CodeBy Forum](https://codeby.net/)


# Academies

  - [PortSwigger](https://portswigger.net/)
  - [HackTheBox](https://www.hackthebox.com/)
  - [Hacker101](https://www.hacker101.com/)
  - [Codeby Games](https://codeby.games/categories)


## Tools

Bundled third-party tools live under [tools/](./tools/). Each one is kept in-repo for offline use; the [tools/README.md](./tools/README.md) index links every tool to its upstream and documents how to refresh.

## Download Burp

[CLICK THIS LINK](https://github.com/Maverick-25/Burp-Suite/releases/download/tool/Burp_Suite_Professional_2023.6.1_2023june15_repack-pwn3rzs.7z)

![Logo](https://media.giphy.com/media/DLm2IJPuLnMTS/giphy.gif)

## License & Disclaimer

- **License**: [MIT](./LICENSE) — applies to original content in this repository. Bundled third-party tools retain their upstream licenses.
- **Disclaimer**: [DISCLAIMER.md](./DISCLAIMER.md) — authorization, legal scope, responsibility.
- **Contributing**: [CONTRIBUTING.md](./CONTRIBUTING.md) — cheatsheet format, naming convention, sources requirement.
