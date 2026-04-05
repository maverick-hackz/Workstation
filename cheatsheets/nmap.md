# Nmap

> Network scanner — host discovery, port scanning, version & OS detection, NSE scripts. Authorized engagements only; sweep scans are loud and rate-shaping/IDS will trip on them.

## TL;DR
- Default scan is `-sS` (root) or `-sT` (unprivileged) over the top-1000 TCP ports — explicitly choose `-p-` when full coverage matters.
- Discovery is silent by default; `-Pn` skips host-up probing when ICMP is filtered.
- `-sV -sC -O` is the standard "info pass" but is also the noisiest; spread with `-T2` on production.
- Stream `-oA basename` to keep `nmap`, `gnmap`, and XML outputs in sync for downstream tooling.

## Detection / Discovery
| Option | Description |
| --- | --- |
| `10.10.10.0/24` | Target network range. |
| `-sn` | Disable port scanning (host discovery only). |
| `-Pn` | Skip host discovery (treat all as up). |
| `-n` | Skip DNS resolution. |
| `-PE` | ICMP Echo ping scan. |
| `--packet-trace` | Show all packets sent and received. |
| `--reason` | Display reason for each result. |
| `--disable-arp-ping` | Disable ARP ping (LAN scans). |
| `--top-ports=<num>` | Scan the N most-frequent ports. |
| `-p-` | Scan all 65 535 ports. |
| `-p22-110` | Scan range 22-110. |
| `-p22,25` | Scan specific ports. |
| `-F` | Fast scan, top 100 ports. |

## Exploitation (scan techniques)
| Option | Description |
| --- | --- |
| `-sS` | TCP SYN scan. |
| `-sA` | TCP ACK scan (firewall mapping). |
| `-sU` | UDP scan. |
| `-sV` | Service / version detection. |
| `-sC` | Default NSE script category. |
| `--script <script>` | Run specific NSE script(s). |
| `-O` | OS detection. |
| `-A` | OS detection + version + script + traceroute. |
| `-D RND:5` | Random decoys. |
| `-e <iface>` | Network interface. |
| `-S 10.10.10.200` | Spoof source IP. |
| `-g <port>` | Source port. |
| `--dns-server <ns>` | Use specific DNS server. |

## Output Options
| Option | Description |
| --- | --- |
| `-oA filename` | Store results in all formats. |
| `-oN filename` | Normal text. |
| `-oG filename` | Grepable. |
| `-oX filename` | XML. |

## Performance Options
| Option | Description |
| --- | --- |
| `--max-retries <num>` | Retries per port. |
| `--stats-every=5s` | Periodic status output. |
| `-v` / `-vv` | Verbose output. |
| `--initial-rtt-timeout 50ms` | Initial RTT timeout. |
| `--max-rtt-timeout 100ms` | Maximum RTT timeout. |
| `--min-rate 300` | Minimum packets/s. |
| `-T <0-5>` | Timing template (5 = insane, 2 = polite). |

## Defence / Remediation
- Network-level: segment, drop ICMP echo + TCP/UDP probes at the edge for unmanaged source IPs (CWE-200 Information Exposure).
- IDS/IPS rules (Suricata/Zeek) for SYN-flood, port-sweep, and NSE-script signatures; alert on `-sV` user-agents and known NSE banner strings.
- Don't expose internal management interfaces (SSH, RDP, IPMI, K8s API) to the internet — VPN/zero-trust gateway only.
- Treat anti-scan posture as a delay/detection tool, not a prevention; defenders must assume scans will succeed.

## Sources
- Nmap reference guide: https://nmap.org/book/man.html
- NSE script database: https://nmap.org/nsedoc/
- MITRE ATT&CK T1046 Network Service Discovery: https://attack.mitre.org/techniques/T1046/
