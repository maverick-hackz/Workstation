# Containers & Kubernetes

Container-runtime + orchestrator pentest. Map: MITRE ATT&CK for Containers.

## Index

| File | MITRE ATT&CK |
| --- | --- |
| [docker-escape.md](./docker-escape.md) | [T1611 Escape to Host](https://attack.mitre.org/techniques/T1611/) |
| [kubernetes-attack-paths.md](./kubernetes-attack-paths.md) | [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610/), [T1613 Container and Resource Discovery](https://attack.mitre.org/techniques/T1613/), [T1525 Implant Internal Image](https://attack.mitre.org/techniques/T1525/) |
| [image-scanning.md](./image-scanning.md) | (Defence) — Trivy / Grype / Syft / Sigstore |

## Sources
- Kubernetes Security docs: https://kubernetes.io/docs/concepts/security/
- HackTricks Cloud / K8s: https://book.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/index.html
- NSA / CISA Kubernetes Hardening Guide: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- CIS Docker / Kubernetes Benchmarks: https://www.cisecurity.org/cis-benchmarks
- MITRE ATT&CK for Containers: https://attack.mitre.org/matrices/enterprise/containers/
