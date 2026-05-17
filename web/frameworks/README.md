# Web Frameworks — Deep Dives

Framework-specific pentest cheatsheets. Per-framework default-misconfiguration patterns + known CVE classes + bundled debug-page exposures. Authorized testing only.

## Index

| File | Stack | Common high-impact path |
| --- | --- | --- |
| [spring-boot-actuator.md](./spring-boot-actuator.md) | Java / Spring Boot | `/actuator/heapdump` + `/jolokia` → JMX RCE; `/gateway/routes` CVE-2022-22947 |
| [wordpress.md](./wordpress.md) | PHP / WordPress | Plugin CVE → web shell; XML-RPC brute amplification; wp-config.php backup leak |
| [jenkins.md](./jenkins.md) | Java / Jenkins | Script Console Groovy RCE; credential dump; CVE-2024-23897 file read |
| [gitlab.md](./gitlab.md) | Ruby / GitLab | Account-takeover CVEs; runner-token leak; group-token over-scope |
| [laravel.md](./laravel.md) | PHP / Laravel | `.env` exposure → APP_KEY → cookie/queue forge; Ignition CVE-2021-3129 |
| [django-admin.md](./django-admin.md) | Python / Django | `DEBUG=True` SECRET_KEY leak; admin brute; signed-cookie session forge |

## Related
- General web vulns (apply to every framework) → [../README.md](../README.md)
- CI/CD pipeline attacks → [../../cicd-supply-chain/](../../cicd-supply-chain/)
- Methodology + reporting → [../../methodology/](../../methodology/)

## Sources
- Project advisories (per-framework): see each file's Sources section.
- HackTricks pentesting web: https://book.hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology.html
- nuclei templates (framework-specific): https://github.com/projectdiscovery/nuclei-templates
- PortSwigger Research blog: https://portswigger.net/research
