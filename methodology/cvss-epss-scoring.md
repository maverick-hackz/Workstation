# CVSS & EPSS — Vulnerability Scoring

> Standardised scoring schemes for vulnerability severity (CVSS) and real-world exploit-likelihood (EPSS). Used in pentest reports for severity columns and remediation prioritisation. Authorized testing only.

## TL;DR
- **CVSS v3.1**: most common in pentest reports today. Scores 0-10 via 8 base metrics + temporal + environmental.
- **CVSS v4.0** (FIRST released Nov 2023): finer-grained, replaces "Scope" with explicit Subsequent System Impact, adds Threat / Attack-Requirements / Provider/Consumer environmental metrics. Adoption growing through 2025.
- **EPSS** (FIRST, daily-refreshed): probability (0.0-1.0) that a CVE is exploited in the wild within next 30 days. Complements CVSS — CVSS tells you "how bad", EPSS tells you "how likely soon".
- For pentest findings (no CVE yet): score with CVSS, optionally note "no EPSS — not a published CVE" and reason about likelihood qualitatively.

## CVSS v3.1 (current de facto)

### Base metrics
| Metric | Values | Meaning |
| --- | --- | --- |
| AV — Attack Vector | N (Network) / A (Adjacent) / L (Local) / P (Physical) | Where the attacker has to be. |
| AC — Attack Complexity | L / H | Repeatable vs lucky-conditions. |
| PR — Privileges Required | N (None) / L (Low) / H (High) | Pre-existing access needed. |
| UI — User Interaction | N (None) / R (Required) | Does a user have to click? |
| S — Scope | U (Unchanged) / C (Changed) | Crosses a trust boundary? |
| C — Confidentiality | N / L / H | Data read impact. |
| I — Integrity | N / L / H | Data write impact. |
| A — Availability | N / L / H | Service uptime impact. |

Vector string format:
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H        → 9.8 Critical
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N        → 6.1 Medium (typical reflected XSS)
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H        → 7.8 High (local privesc)
CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N        → 2.0 Low
```

### Calculator
- FIRST's official calc: https://www.first.org/cvss/calculator/3.1
- Output: base score, temporal score (with vendor's E/RL/RC modifiers), environmental score (with your CIA-requirements + modified-base override).
- Most reports cite **base score** only (objective). Temporal / Environmental are useful for the client to internalise.

### Severity buckets
| Score | Severity |
| --- | --- |
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

### Anti-patterns
- **CVSS-only triage** for remediation prioritisation — CVSS doesn't model your business; a CVSS 9.8 on a dev sandbox is less urgent than a 7.5 on the auth path. Pair with environmental metrics or with EPSS.
- **Mismatched AC** — many testers mark `AC:L` reflexively. AC:H is reserved for race-condition / rare-config / target-specific-knowledge dependencies. Be honest.
- **`Scope: Changed` misuse** — Scope changes only when the vulnerable component and the impacted component are in different trust domains (e.g., XSS in a sandboxed iframe affects the parent → S:C; XSS in an app's own page → S:U).

## CVSS v4.0 (new; growing adoption)

### What changed from 3.1
- **Granularity**: Subsequent System metrics replace "Scope" — separate C/I/A impact on the vulnerable system and on subsequent systems.
- **Attack Requirements**: split from Attack Complexity. AC is now purely "no special conditions vs measurable luck"; AT covers "needs particular config / man-in-the-middle / etc."
- **Threat metrics**: Exploit Maturity (X / A / P / U) replaces Temporal "Exploit Code Maturity" / "Remediation Level" / "Report Confidence".
- **Provider Urgency**: optional vendor signal (Red / Amber / Green / Clear).
- **No formal severity buckets** in v4.0 spec — vendors map to their own scales.

### Vector string (illustrative)
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

### Calculator
- https://www.first.org/cvss/calculator/4.0
- Implementations in `nvd.nist.gov` (NVD) are migrating; expect both v3.1 and v4.0 vectors in 2025.

### When to use v3.1 vs v4.0
- v3.1: legacy reports, client-side risk frameworks not yet updated, NVD vulnerability databases (still mixed).
- v4.0: new pentest reports where the client / vendor accept it; vendor advisories from 2024+ increasingly use v4.0.
- **Best practice**: ship both vectors per finding for forward compatibility.

## EPSS — Exploit Prediction Scoring System

### What it is
- FIRST.org daily-refreshed model that predicts the **probability** (0.0-1.0) a CVE will be exploited in the wild within 30 days.
- Inputs: features of the CVE (CVSS, CWE, age, vendor) + threat-intel signals (chatter, exploit-code publication, etc.).
- Output: percentile rank + raw probability per CVE.

### Why pair with CVSS
- CVSS = "how bad if exploited" (severity).
- EPSS = "how likely to be exploited soon" (urgency).
- High CVSS + low EPSS = "patch in normal cycle".
- Low CVSS + high EPSS = "patch this week; defender attention is on it".
- High CVSS + high EPSS = "right now".

### Usage
```bash
# Query EPSS API for a CVE
curl 'https://api.first.org/data/v1/epss?cve=CVE-2024-21626'

# Bulk query CSV from https://www.first.org/epss/data_stats
curl -o epss.csv.gz https://epss.cyentia.com/epss_scores-current.csv.gz
```

### In a pentest report
- For each finding mapped to a published CVE: include `EPSS = 0.42 (87th percentile)`.
- For findings that are *not* yet CVEs (your discovered SQLi, etc.): EPSS doesn't apply — note "novel finding; no EPSS score". Use qualitative judgement on likelihood ("exposed to internet, no auth required → high likelihood").

## Pentest report integration

Per-finding row from [./pentest-report-template.md](./pentest-report-template.md):

| Field | Example |
| --- | --- |
| Severity | High |
| CVSS v3.1 | `7.5 / CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| CVSS v4.0 | `7.6 / CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| CVE | CVE-2024-12345 (if applicable) |
| EPSS | 0.42 (87th percentile) — if CVE-based |
| CWE | CWE-89 |

### Remediation priority calculation (simple)
```
priority_score = CVSS_base * (1 + EPSS_probability) * business_criticality_multiplier
```
Document the formula in the report appendix so the client can adapt it to their internal SLAs.

## Sources
- FIRST CVSS v3.1 specification: https://www.first.org/cvss/v3.1/specification-document
- FIRST CVSS v4.0 specification: https://www.first.org/cvss/v4.0/specification-document
- FIRST CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- FIRST CVSS v4.0 calculator: https://www.first.org/cvss/calculator/4.0
- FIRST EPSS overview: https://www.first.org/epss/model
- FIRST EPSS API & data: https://www.first.org/epss/data_stats
- NVD (vulnerability database): https://nvd.nist.gov/
- MITRE CWE: https://cwe.mitre.org/
- ENISA — risk management guidance: https://www.enisa.europa.eu/topics/risk-management
- NIST SP 800-30 — Guide for Conducting Risk Assessments: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
