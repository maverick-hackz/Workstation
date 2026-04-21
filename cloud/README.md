# Cloud

AWS / GCP / Azure pentest cheatsheets + cross-provider SSRF→IMDS reference.

## Index

| File | Provider | MITRE ATT&CK (Cloud) |
| --- | --- | --- |
| [aws.md](./aws.md) | AWS | [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [T1552.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/) |
| [gcp.md](./gcp.md) | GCP | [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [T1552.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/) |
| [azure.md](./azure.md) | Azure / Entra ID | [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) |
| [ssrf-cloud-metadata.md](./ssrf-cloud-metadata.md) | All | [T1552.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/) |

## Sources
- hackingthe.cloud: https://hackingthe.cloud/
- HackTricks Pentesting Cloud: https://book.hacktricks.wiki/en/pentesting-cloud/pentesting-cloud-methodology.html
- AWS Security docs: https://docs.aws.amazon.com/security/
- GCP Security best practices: https://cloud.google.com/security/best-practices
- Azure Security docs: https://learn.microsoft.com/en-us/azure/security/
- MITRE ATT&CK for Cloud: https://attack.mitre.org/matrices/enterprise/cloud/
