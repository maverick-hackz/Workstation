# Network

Layer-2 / Layer-3 attacks: name-resolution poisoning, ARP / DNS spoofing, Wi-Fi, VLAN hopping, IPv6 mitm6. Authorized testing only.

## Index

| File | MITRE ATT&CK |
| --- | --- |
| [arp-dns-spoofing.md](./arp-dns-spoofing.md) | [T1557.002 ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/), [T1557.003 DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003/) |
| [ipv6-mitm6.md](./ipv6-mitm6.md) | [T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/) |
| [llmnr-nbtns-responder.md](./llmnr-nbtns-responder.md) | [T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/) |
| [vlan-hopping.md](./vlan-hopping.md) | [T1599 Network Boundary Bridging](https://attack.mitre.org/techniques/T1599/) |
| [wifi.md](./wifi.md) | [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/), [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/) |

## Related
- AD-side relay targets → [../ad-infrastructure/lateral-movement.md](../ad-infrastructure/lateral-movement.md) (NTLM relay coverage)
- Recon precursors (passive subdomain / OSINT) → [../recon/](../recon/)
- Tunneling once inside → [../post-exploitation/pivoting.md](../post-exploitation/pivoting.md)

## Sources
- HackTricks pentesting network: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-network/index.html
- bettercap docs: https://www.bettercap.org/
- aircrack-ng / hcxtools: https://www.aircrack-ng.org/ , https://github.com/ZerBea/hcxtools
- Responder: https://github.com/lgandx/Responder
- mitm6: https://github.com/dirkjanm/mitm6
- Cisco network security configuration guides: https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html
- MITRE ATT&CK Adversary-in-the-Middle techniques: https://attack.mitre.org/techniques/T1557/
