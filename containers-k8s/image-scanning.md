# Container Image Scanning

> Detect CVEs, secrets, misconfigurations, and supply-chain issues in container images before they ship. Trivy / Grype / Syft are the canonical OSS triad. Authorized testing only.

## TL;DR
- **Trivy** — vuln scan (OS packages + language libs), config scan (Dockerfile, K8s, Terraform), secret scan, SBOM. One CLI for the whole stack.
- **Grype** — vuln scan (Anchore Engine successor). Pair with **Syft** which generates the SBOM Grype consumes.
- **Syft** — SBOM generator (SPDX, CycloneDX). Treat the SBOM as the artefact; scan the SBOM rather than the image when CI re-runs.
- **Cosign** + **Sigstore** for image signing/verification (see [../cicd-supply-chain/sbom-sigstore.md](../cicd-supply-chain/sbom-sigstore.md)).
- Scan three stages: build (pre-push), registry (continuous re-scan as new CVEs land), deploy (admission controller).

## Detection / Discovery — Trivy

```bash
# Scan a remote image for OS + library vulns
trivy image alpine:3.20

# Scan a local Dockerfile for misconfig
trivy config Dockerfile

# Scan a filesystem (built but not yet packaged)
trivy fs ./app

# Scan secrets in a repo
trivy fs --scanners secret ./

# Scan a Kubernetes cluster's running workloads (RBAC-restricted to read)
trivy k8s cluster --report summary

# Output formats
trivy image --format json -o report.json ubuntu:22.04
trivy image --format cyclonedx -o sbom.cdx.json ubuntu:22.04
trivy image --format spdx-json -o sbom.spdx.json ubuntu:22.04

# Severity gate (exit non-zero if HIGH/CRITICAL)
trivy image --exit-code 1 --severity HIGH,CRITICAL ubuntu:22.04
```

Configuration knobs:
- `--ignore-unfixed` — skip vulns with no fix available (separate "won't fix" from "unpatched").
- `.trivyignore` — per-repo CVE ignore list with expiry dates (audit regularly).
- `--db-repository` for air-gapped Trivy DB mirror.

## Detection / Discovery — Grype + Syft

```bash
# Generate SBOM
syft alpine:3.20 -o spdx-json=sbom.spdx.json
syft alpine:3.20 -o cyclonedx-json=sbom.cdx.json

# Scan SBOM (preferred — deterministic, fast in CI)
grype sbom:sbom.spdx.json --output table
grype sbom:sbom.cdx.json --output json --file report.json

# Or scan the image directly
grype alpine:3.20 --fail-on high
```

Why SBOM-first:
- Generate once at build, scan many times against changing vuln DBs.
- The SBOM is an audit artefact (regulators / customer SBOM requests under EO 14028 / CRA).
- Scans are reproducible — same SBOM → same vuln set for a given vuln DB snapshot.

## Detection / Discovery — admission control

OPA Gatekeeper / Kyverno can block deploy of images that fail a policy:
```yaml
# Kyverno ClusterPolicy fragment — block images without signature
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: { name: require-signed-images }
spec:
  validationFailureAction: enforce
  rules:
  - name: verify-cosign
    match: { any: [{ resources: { kinds: ["Pod"] } }] }
    verifyImages:
    - imageReferences: ["registry.acme.tld/*"]
      attestors:
      - entries:
        - keys:
            publicKeys: |
              -----BEGIN PUBLIC KEY-----
              <cosign.pub contents>
              -----END PUBLIC KEY-----
```

Trivy can also feed an admission decision via the `trivy-operator` (continuous in-cluster scanning).

## Exploitation — what an attacker looks for

| Finding | Why it matters |
| --- | --- |
| **HIGH/CRITICAL CVE in base image** | Pivot to known-exploit DBs (Exploit-DB, GitHub PoCs). |
| **Known supply-chain takeover** (npm/pypi) | Match against `osv-scanner` malicious-package feed. |
| **Embedded secrets** | AWS/GCP keys, SSH private keys, OAuth tokens in image layers. `dive` + `trivy --scanners secret` finds them. |
| **Outdated TLS / crypto lib** | OpenSSL 1.0.x in 2025 → high-confidence finding. |
| **`USER root` Dockerfile** | Combined with breakout primitives. |
| **Pinned-by-tag, not by digest** | Tag substitution; the image you scanned isn't the image deployed. Always pin by `@sha256:…`. |

## Bypasses (for blue team awareness)
- Multi-stage build that strips evidence from the final layer — Trivy still scans the final layer; scanners that traverse all layers (with `--list-all-pkgs`) catch artifacts in non-final layers.
- "Vendored" binaries copied in via `COPY` from a build stage — package managers don't see them; Syft/Trivy still fingerprint by file content (Go module databases, Java JAR manifest, Python wheels).
- Custom-built C binaries with no package metadata — invisible to vuln scanners; rely on SAST + SCA at source level.

## Defence / Remediation
- **Pin by digest** (`@sha256:…`) in every Dockerfile FROM, every K8s manifest, every Helm values file. Tag-pinning is rebase-able by the registry owner; digest-pinning is not.
- **Distroless / chiselled base images** — drop the package manager / shell / debug tools from production images. Vuln surface shrinks proportionally.
- **Multi-stage** with a build stage and a slim runtime stage; copy only what runs.
- **Run as non-root** (`USER nobody` or a numeric UID); drop `CAP_SYS_*`; read-only root FS.
- **Re-scan in registry continuously** — the CVE found 4 months after build isn't visible at build time. Set up Harbor / ECR / GAR scan-on-push + daily re-scan.
- **Block admission** of unsigned or vuln-laden images (Kyverno / Gatekeeper / trivy-operator).
- **SBOM as ship artefact** — every release has an SBOM stored, signed, and queryable.
- **Patch cadence** — measure mean time to patch CRITICAL CVE in base image. EU CRA penalises slow patching of products shipped with known CVEs.

## Sources
- Trivy documentation: https://aquasecurity.github.io/trivy/
- Grype: https://github.com/anchore/grype
- Syft: https://github.com/anchore/syft
- Sigstore (cosign): https://docs.sigstore.dev/
- Kyverno: https://kyverno.io/
- OPA Gatekeeper: https://open-policy-agent.github.io/gatekeeper/
- CISA — Securing the Software Supply Chain: https://www.cisa.gov/sites/default/files/2023-04/secure-by-design.pdf
- EU Cyber Resilience Act (CRA) overview: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- US Executive Order 14028 — Software Supply Chain: https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
