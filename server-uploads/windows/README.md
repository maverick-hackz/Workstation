# Windows Server-Side Helpers — Reference (Not Bundled)

> Catalog of helper binaries / scripts to drop on Windows targets during authorized engagements. **No actual binaries bundled in this repo** — AV/EDR triggers on extraction and GitHub flag-as-malware risk. Fetch from upstream into a controlled engagement workspace.

## Why no binaries here

Several entries below are signature-detected by:
- Microsoft Defender (built-in Windows + ATP)
- Most commercial EDRs (CrowdStrike, SentinelOne, Carbon Black, Defender for Endpoint)
- VirusTotal (file appears flagged within seconds of upload)
- GitHub's "Sensitive Data Detection" / "Suspected Malware" flags

Including them in a public-ish git repo invites:
- Repository takedown notices (GitHub DMCA / TOS-violation channel).
- Clone-side AV quarantine (the repo can't even be checked out cleanly on a Defender-protected host).
- Endpoint-allow-list contamination for anyone who pulls the repo to a sandboxed test host.

The right pattern: **operator pulls the binary from upstream into an isolated engagement workstation** (Kali VM / Flare-VM / similar) per engagement, then drops onto the target via your normal delivery (SMB upload, web-shell, etc).

## Catalog

### Privilege escalation / enumeration

| Tool | Purpose | Upstream | Detection note |
| --- | --- | --- | --- |
| winPEAS (winPEASany.exe / .ps1 / .bat) | All-in-one Windows privesc enumeration | https://github.com/peass-ng/PEASS-ng | Defender flags `winPEAS.exe` on extraction; .ps1 form survives until AMSI sees the body. Run AMSI bypass first. |
| Seatbelt | Host situational-awareness data collection | https://github.com/GhostPack/Seatbelt | Defender signature; rename or recompile. |
| PrivescCheck | PowerShell modern PowerUp replacement | https://github.com/itm4n/PrivescCheck | Less detected than PowerUp; still scanned by ScriptBlock logging. |
| PowerUp (PowerSploit) | Older PS local-privesc finder | https://github.com/PowerShellMafia/PowerSploit | Archived; signature-flagged. |
| SharpUp | C# rewrite of PowerUp | https://github.com/GhostPack/SharpUp | Same lineage; AV-flagged. |

### Active Directory enumeration

| Tool | Purpose | Upstream | Detection note |
| --- | --- | --- | --- |
| SharpHound (.exe) | BloodHound collector | https://github.com/SpecterOps/SharpHound | Heavily flagged; recompile from source with renamed strings. |
| PowerView.ps1 | AD recon via PowerShell | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 | ScriptBlock-logged; AMSI bypass first. |
| ADRecon.ps1 | AD report-style enumeration | https://github.com/sense-of-security/ADRecon | Less-flagged than PowerView in current Defender. |
| Snaffler | File-share + content recon | https://github.com/SnaffCon/Snaffler | C# binary; renames help. |

### Kerberos

| Tool | Purpose | Upstream | Detection note |
| --- | --- | --- | --- |
| Rubeus.exe | Kerberos ticket / roast / PtT toolkit | https://github.com/GhostPack/Rubeus | Heavily flagged. Recompile + obfuscate strings. |
| kerbrute | User enumeration via Kerberos pre-auth | https://github.com/ropnop/kerbrute | Cross-platform; less flagged. |
| ASREPRoast.ps1 | AS-REP roasting in PS only | https://github.com/HarmJ0y/ASREPRoast | ScriptBlock-logged. |

### Credential extraction

| Tool | Purpose | Upstream | Detection note |
| --- | --- | --- | --- |
| Mimikatz | The LSASS-extraction toolkit | https://github.com/gentilkiwi/mimikatz | Universally flagged. Use procdump → offline pypykatz instead. |
| nanodump | Less-detected LSASS-dump BOF / standalone | https://github.com/fortra/nanodump | Better evasion than procdump+mimikatz pair; still scanned. |
| pypykatz | Python mimikatz reimplementation | https://github.com/skelsec/pypykatz | Runs OFFLINE on a minidump — no on-target Defender hit. |
| LaZagne | Browser / Wi-Fi / app password extractor | https://github.com/AlessandroZ/LaZagne | Defender signature. |
| SafetyKatz | Mimikatz wrapper with reduced detection | https://github.com/GhostPack/SafetyKatz | Decent for noisy environments; still scanned. |
| Procdump (Sysinternals) | Signed Microsoft binary that dumps any process | https://learn.microsoft.com/en-us/sysinternals/downloads/procdump | Signed → less alarming; behavioural detection on LSASS target. |

### Lateral movement / persistence

| Tool | Purpose | Upstream | Detection note |
| --- | --- | --- | --- |
| PsExec / PsExec64 (Sysinternals) | Service-install remote execution | https://learn.microsoft.com/en-us/sysinternals/downloads/psexec | Signed. Event 4697 + 7045 generated; very loud. |
| Impacket-style precompiled `psexec.exe` | Standalone (no Sysinternals) | (recompile from https://github.com/fortra/impacket) | Less common on disk. |
| nc.exe (Netcat for Windows) | Bind / reverse-shell catcher | https://github.com/diegocr/netcat (mirror), or "powercat" PS variant | Often flagged; rename or use powercat. |
| WSL nc | If the target has WSL | (built-in) | Bypasses Win-side EDR partially. |

### Misc

| Tool | Purpose | Upstream | Detection note |
| --- | --- | --- | --- |
| GhostPack Compile-It-Yourself suite | Rubeus / SharpHound / SharpUp / Seatbelt / Certify | https://github.com/GhostPack | Recompile from source with `Costura.Fody` for single-file output. |
| UACME | UAC bypass methods catalog | https://github.com/hfiref0x/UACME | Released as PoC; AV signature on shipped binaries. |
| Watson | Local-privesc CVE checker | https://github.com/rasta-mouse/Watson | Last update older — verify CVE list freshness. |

## Suggested operator workflow

1. **Build engagement workstation** off the production network (Flare-VM / dedicated Win10 ent VM with Defender on, AMSI on, ScriptBlock logging on — mirror production endpoint posture).
2. **Pull binaries fresh** per engagement (`git clone --depth=1`); compile C# tools from source with renamed strings (use `Invoke-Obfuscation` or hand-edit). Verify Defender does not quarantine your build artefact before you ship to target.
3. **Inventory + SHA256** every binary you intend to drop; record in engagement notes for IR-cooperation later.
4. **Stage on target** via your delivery path (web shell, SMB upload, BOF in-memory loader from a beacon).
5. **Don't leave artefacts** — cleanup after each test pass.

## Authorized testing only.

The mere presence of these tools on a host is often a high-fidelity IoC for SOCs. Coordinate with blue team if running detection-friendly tests; otherwise consider these IOCs themselves part of the test scope.

## Sources
- PEASS-ng: https://github.com/peass-ng/PEASS-ng
- GhostPack toolkit (Seatbelt, Rubeus, SharpHound, etc.): https://github.com/GhostPack
- SpecterOps SharpHound + BloodHound CE: https://github.com/SpecterOps/SharpHound
- Sysinternals: https://learn.microsoft.com/en-us/sysinternals/
- Mimikatz: https://github.com/gentilkiwi/mimikatz
- Impacket: https://github.com/fortra/impacket
- ropnop kerbrute: https://github.com/ropnop/kerbrute
- itm4n PrivescCheck / PrintSpoofer: https://github.com/itm4n
- LOLBAS Project (signed binaries with offensive uses): https://lolbas-project.github.io/
- HackTricks Windows binaries reference: https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation.html
