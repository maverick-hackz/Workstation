# Rules of Engagement & Scoping

> Pre-engagement document defining what the tester may and may not do. Without a signed ROE there is no engagement. Authorized testing only.

## TL;DR
- Both parties sign before any packet leaves the tester's laptop.
- Two layers: **scope** (what's in/out of bounds) and **rules** (how testing is conducted, what's prohibited, escalation/IR contacts).
- Get the scope wrong → either wasted budget or out-of-bounds finding that lands you in legal trouble.
- Re-confirm in writing before each phase change (recon → exploitation → red team → physical).

## Scoping checklist

### Target inventory
| Item | Examples |
| --- | --- |
| In-scope IPs / CIDRs | `203.0.113.0/24`, `198.51.100.42` |
| In-scope domains / subdomains | `example.com`, `*.example.com`, `app.example.com` |
| In-scope URLs / endpoints | `https://api.example.com/v1/*` |
| In-scope cloud accounts | AWS account ID `123456789012`, GCP project `example-prod` |
| In-scope mobile apps | iOS bundle ID `com.example.app` v3.2.1, Android package `com.example.app` |
| In-scope user accounts | Test accounts provided + their permission levels |
| In-scope production data | Anything personally identifiable / payment / health → typically out |
| In-scope third-party integrations | Often out unless you have *their* written permission too |

### Out-of-scope items (be explicit)
- Production databases (read access OK, write NOT OK without prior approval).
- Customer accounts (test accounts only).
- Payment processing flows (often regulated under PCI-DSS test rules).
- Third-party APIs / SaaS the target depends on (you don't have *their* authorization).
- Physical entry / dumpster diving (separate ROE; often a different engagement).

### Test windows
| Phase | Window |
| --- | --- |
| Recon / vuln scan | YYYY-MM-DD HH:MM TZ to YYYY-MM-DD HH:MM TZ |
| Active exploitation | YYYY-MM-DD HH:MM TZ to YYYY-MM-DD HH:MM TZ |
| Post-exploit (if approved) | Day/hours |
| Re-test (post-fix) | Date window |

Outside-window contact for incidents → tester's phone + email + Signal; client's IR lead's same.

## Rules-of-Engagement language (copy-adapt)

```markdown
# Rules of Engagement

## Parties
- **Client**: <name>, <address>
- **Tester**: <company>, <address>
- **Authorized signers**: <name + title> (Client), <name + title> (Tester)

## Authority and authorization
The Client warrants that they own or are duly authorized to grant access to
the systems listed in §3 (Scope). This document constitutes written
authorization for the Tester to perform the testing activities described
in §4 (Activities) during the period defined in §5 (Test window).

Testing performed outside the agreed scope / activities / window is a
breach of this agreement; tester will immediately stop and notify the
Client's emergency contact (§7).

## 3. Scope
- **In scope**: [explicit list of IPs, hostnames, URLs, cloud accounts,
  applications, test accounts; or reference to an attached spreadsheet].
- **Out of scope**: [explicit list — anything not listed in-scope is
  implicitly out of scope and may not be tested].

## 4. Activities
### Permitted
- [ ] Passive reconnaissance (CT logs, search engines, public records)
- [ ] Active reconnaissance (port scanning, DNS enumeration)
- [ ] Vulnerability scanning (Nessus / Nuclei / Qualys)
- [ ] Manual exploitation of identified vulnerabilities
- [ ] Local privilege escalation on compromised hosts
- [ ] Pivoting to second-tier hosts (if reached from primary scope)
- [ ] Data extraction limited to proof-of-vulnerability (e.g., first row of
      sensitive table, with placeholders as evidence; no bulk exfil)
- [ ] Persistence mechanisms (only with explicit pre-approval)
- [ ] Phishing simulation against employee list [attached / not attached]
- [ ] Physical access attempt (separate ROE)

### Prohibited
- [ ] Denial-of-Service attacks (volumetric, application-layer, or
      authentication lockout)
- [ ] Destructive operations (DELETE / DROP TABLE / kernel exploits with
      crash risk)
- [ ] Use of production credentials (test accounts only)
- [ ] Modification of production data
- [ ] Social engineering against named individuals not on a pre-approved list
- [ ] Backup-rotation interference
- [ ] Dropping malware on systems

### Conditional (require explicit approval per occurrence)
- Live exploit-chain testing during business hours
- Use of public 0-day exploits not yet patched
- Brute-force attempts at scale on production auth endpoints

## 5. Test window
- Start: YYYY-MM-DD HH:MM <TZ>
- End:   YYYY-MM-DD HH:MM <TZ>
- Re-test window: YYYY-MM-DD to YYYY-MM-DD (one round, 5 business days max).
- Critical-finding exception: tester may notify Client immediately if a
  pre-deadline critical finding requires action.

## 6. Source IPs / VPN
- Tester source IPs: <list> (whitelist if WAF/Cloudflare is involved).
- Tester may use anonymizing infrastructure (VPN, Tor) for OSINT only,
  not for active testing.

## 7. Communications
- Primary channel: <Slack channel / email>
- Emergency contact (Client): <name>, <phone>, <Signal>
- Emergency contact (Tester): <name>, <phone>, <Signal>
- Incident response: if testing causes downtime, both parties communicate
  within 15 minutes.

## 8. Findings handling
- Tester delivers findings via [secure channel — encrypted PDF / SysReptor
  portal / encrypted Git repo]; no plaintext email of findings.
- Tester retains evidence for 90 days post-engagement, then securely
  destroys (NIST 800-88 sanitization).
- Critical findings: notified to Client within 4 business hours of discovery.

## 9. Legal
- This engagement does not transfer ownership of any IP discovered.
- Compliance: Tester complies with applicable laws (US CFAA, EU GDPR, etc.).
- Indemnification: as negotiated; default — tester not liable for production
  outage from a vulnerability whose exploitation followed agreed methodology.

## 10. Signatures
Client signer:  <name + role + date>
Tester signer:  <name + role + date>
```

## Common scoping mistakes

- **"All of the internet domain we own"** — sounds easy but the client may not actually own all of `*.example.com`. CT log review at scope-define time to verify.
- **Cloud account ID instead of "AWS"** — multi-account orgs need every account ID; otherwise scope ambiguity.
- **Mobile apps without app-store identifiers** — version drift mid-engagement is the difference between an in-scope and out-of-scope artefact.
- **No re-test included** — "did you fix it" requires a re-test; budget for it up-front.
- **No incident-response contact** — when a scan accidentally trips a fraud-detection rule, you need to be on the phone *yesterday*.
- **No regulatory carve-out** — testing PCI-scope systems requires a QSA-aware ROE; testing HIPAA-covered systems requires BAA; testing GDPR-covered systems requires data-protection terms.
- **"Black box" without sufficient assistance** — tester wastes 2 days re-doing what the client could have provided in 2 hours (architecture diagram, test account credentials).

## Sources
- PTES Pre-engagement Interactions: http://www.pentest-standard.org/index.php/Pre-engagement
- OWASP WSTG — Pre-engagement: https://owasp.org/www-project-web-security-testing-guide/v42/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies
- NIST SP 800-115 — §2 Establishing a Security Testing and Examination Policy: https://csrc.nist.gov/publications/detail/sp/800-115/final
- ISC2 — penetration testing ethics: https://www.isc2.org/
- SANS Penetration Testing Curriculum: https://www.sans.org/cyber-security-courses/?focus-area=penetration-testing
- CREST methodologies (UK / international): https://www.crest-approved.org/
- OffSec — engagement methodology: https://www.offsec.com/penetration-testing/
