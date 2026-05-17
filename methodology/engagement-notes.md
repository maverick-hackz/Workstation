# Engagement Note-Taking Structure

> File / folder structure for live note-taking during a pentest engagement. Saves you from "where was that finding again?" three weeks later at write-up time. Authorized testing only.

## TL;DR
- Set up the folder before the test starts; don't improvise mid-engagement.
- One folder per engagement, one file per host / target / finding.
- Timestamp + the exact request that demonstrated each finding go into the notes the moment you find it. Reproduction depends on it.
- Encrypt at rest; the loot folder probably contains things you wouldn't want to lose.
- Tools that work well: Obsidian / Logseq / VS Code with markdown + a daily-log plugin; KeepNote / CherryTree (older) ; Sysmon-like terminal recorders (`script`, `asciinema`) for replay.

## Folder layout

```text
engagement-<client>-<YYYY-MM>/
├── 00-engagement-meta/
│   ├── ROE.pdf                          # signed Rules of Engagement
│   ├── scope.csv                        # in-scope targets, one row each
│   ├── credentials.kdbx                 # test accounts (KeePass / pass)
│   ├── contacts.md                      # Slack / phone / Signal numbers
│   └── timeline.md                      # daily log of major events
├── 01-recon/
│   ├── crtsh-dump.txt
│   ├── subfinder.txt
│   ├── amass.json
│   ├── httpx-status.csv
│   ├── nmap-tcp-full.xml
│   ├── nmap-udp-top1000.xml
│   └── gowitness/                       # screenshot dir
├── 02-hosts/
│   ├── 10.0.0.10/
│   │   ├── notes.md                     # everything found on this host
│   │   ├── nmap.txt
│   │   ├── http-headers.txt
│   │   └── exploit-attempts.md
│   ├── 10.0.0.11/
│   └── app.example.com/
│       ├── notes.md
│       ├── burp-state.burp              # Burp project file
│       ├── requests/                    # raw .req files, one per session
│       └── responses/
├── 03-findings/
│   ├── F-001-sqli-on-login/
│   │   ├── README.md                    # the finding, paste-ready into the report
│   │   ├── request.txt
│   │   ├── response.txt
│   │   ├── screenshot.png
│   │   └── evidence-data.csv            # extracted-as-PoC data (sample only)
│   ├── F-002-stored-xss-comments/
│   └── F-003-...
├── 04-loot/                             # extracted creds / secrets (encrypted)
│   ├── hashes.txt
│   ├── ntds.dit                         # if AD-side engagement
│   └── README.md                        # what each loot file is
├── 05-attack-paths/
│   ├── bloodhound/
│   │   ├── ingest.zip
│   │   └── neo4j-db/                    # exported Neo4j DB
│   └── path-graph.md
├── 06-report/
│   ├── draft.md
│   ├── final.pdf
│   └── re-test.md
└── 99-misc/
    ├── tool-output/                     # raw tool dumps for reference
    └── screen-recordings/               # session recordings for replay
```

## Per-host `notes.md` skeleton

```markdown
# Host: <ip / hostname>

## Quick reference
- IP: 10.0.0.10
- Hostname: app01.target.tld
- OS (best guess): Linux Ubuntu 22.04
- Open ports: 22/tcp ssh, 80/tcp nginx, 443/tcp nginx, 8080/tcp tomcat
- Notable software: Apache Tomcat 9.0.62 (CVE-2022-25762 affected? check)
- Discovered: 2026-MM-DD HH:MM

## Service banners
### 22/tcp — OpenSSH 8.9p1
- `ssh-audit` output → notes/sshaudit-10.0.0.10.txt

### 8080/tcp — Tomcat 9.0.62
- `/manager/html` reachable, default Tomcat page
- `/host-manager/html` reachable
- Brute /manager/html with rockyou-shortlist — see exploit-attempts.md

## Findings on this host
- F-005 Tomcat Manager default creds → see ../03-findings/F-005/

## Timeline
- 2026-MM-DD 09:14  Initial nmap full
- 2026-MM-DD 09:42  Tomcat default creds successful — admin/admin
- 2026-MM-DD 10:05  WAR-file upload → JSP shell as `tomcat` user
- 2026-MM-DD 10:15  Lateral attempt 10.0.0.20 — failed (firewall)
```

## Per-finding `README.md` skeleton (paste-ready)

```markdown
# F-NNN — <Finding title>

## Severity
- High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8)

## OWASP / CWE
- OWASP A03:2021 — Injection
- CWE-89

## Affected
- https://app.target.tld/login (also api.target.tld/v1/login)

## Description
The login endpoint accepts SQL syntax in the `username` field and returns
unauthenticated access when an SQL truth-condition is appended. ...

## Reproduction
1. Browse to https://app.target.tld/login.
2. Submit:
   ```http
   POST /login HTTP/1.1
   Host: app.target.tld
   Content-Type: application/x-www-form-urlencoded

   username=' OR '1'='1' -- &password=anything
   ```
3. Server responds with `Set-Cookie: session=…; Path=/` and `302 -> /dashboard`.

(Full request/response captured in ./request.txt and ./response.txt.)

## Impact
- Any unauthenticated attacker logs in as the first user in the `users` table
  (typically the original admin during install).
- Database (PostgreSQL) is reachable from the app tier; attacker can pivot to
  read `customers` table (PII; estimated 50 k rows).

## Discovered
- Date: 2026-MM-DD 14:23 UTC
- Tester: <name>
- Tool: manual (Burp Repeater).

## Evidence
- ./request.txt
- ./response.txt
- ./screenshot-dashboard.png
- ./customers-sample.csv (5 rows, names + emails redacted)

## Remediation
- Switch to parameterised queries / prepared statements for the login query.
- Audit other endpoints for the same pattern.
- Database account used by the app: drop SELECT permission on tables not
  required by the login flow.

## References
- OWASP WSTG-INPV-05: <link>
- OWASP Cheat Sheet — SQL Injection Prevention: <link>

## Status
- 2026-MM-DD: Reported to client
- 2026-MM-DD: Client acknowledged
- 2026-MM-DD: Fix deployed (verified)
```

## Security & storage hygiene

- **Encrypt the engagement folder at rest** — encrypted disk (LUKS / FileVault), or store inside a VeraCrypt container. Don't sync to non-encrypted cloud.
- **Don't commit to GitHub during the engagement** unless it's a private encrypted-at-rest repo. Public is right out.
- **Retention policy**: per the ROE (commonly 90 days post-report); secure-delete (`shred -u` / `srm` on FS that supports it; physical destruction for spinning rust if highly sensitive).
- **Secrets in `04-loot/`**: encrypt with a per-engagement key; share with the client only if the ROE explicitly says so; otherwise prove-the-bug and delete the original.

## Tools

- **Obsidian** — markdown vault, graph view, daily notes plugin, vim mode. https://obsidian.md/
- **Logseq** — outliner-style with daily notes; open-source. https://logseq.com/
- **CherryTree** — older hierarchical note-taker; offline-first. https://www.giuspen.com/cherrytree/
- **Joplin** — open-source Evernote alternative; supports E2E sync. https://joplinapp.org/
- **asciinema** — terminal recording for reproducibility evidence. https://asciinema.org/
- **GNU `script`** — built-in terminal recorder: `script -t timing.log session.log` → replay with `scriptreplay timing.log session.log`.
- **autocompliance / PwnDoc** — engagement → report-generation pipeline. https://github.com/pwndoc/pwndoc
- **SysReptor** — modern pentest reporting platform (templates + automation). https://github.com/Syslifters/sysreptor

## Sources
- PTES — Reporting & Note-Taking: http://www.pentest-standard.org/index.php/Reporting
- NIST SP 800-115 — §5 Test Execution Documentation: https://csrc.nist.gov/publications/detail/sp/800-115/final
- OWASP Web Security Testing Guide v4.2: https://owasp.org/www-project-web-security-testing-guide/v42/
- Obsidian community vault — pentest notes templates: https://forum.obsidian.md/
- SANS poster — Pentesters Field Guide: https://www.sans.org/posters/
