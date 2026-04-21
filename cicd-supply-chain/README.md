# CI/CD & Supply Chain

CI/CD pipeline pentest + supply-chain security. Map: OWASP Top 10 CI/CD Security Risks.

## Index

| File | OWASP CI/CD-SEC | MITRE ATT&CK |
| --- | --- | --- |
| [github-actions.md](./github-actions.md) | CI/CD-SEC-04 (PPE) | [T1195.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/) |
| [poisoned-pipeline-execution.md](./poisoned-pipeline-execution.md) | CI/CD-SEC-04 | [T1195.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/) |
| [dependency-confusion.md](./dependency-confusion.md) | CI/CD-SEC-03 (Dependency Chain Abuse) | [T1195.001 Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/) |
| [sbom-sigstore.md](./sbom-sigstore.md) | CI/CD-SEC-10 (Insufficient Logging & Visibility) — defence | — |

## Sources
- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- SLSA framework: https://slsa.dev/
- Sigstore: https://docs.sigstore.dev/
- NIST SSDF (SP 800-218): https://csrc.nist.gov/publications/detail/sp/800-218/final
- OpenSSF Best Practices: https://www.bestpractices.dev/
- MITRE ATT&CK Supply Chain (T1195): https://attack.mitre.org/techniques/T1195/
