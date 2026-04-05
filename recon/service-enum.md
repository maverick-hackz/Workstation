# Service Enumeration

> Commands for protocol-level enumeration during external/internal pentests. Authorized testing only.

## TL;DR
- Start with port + version detection (`nmap -sV`); narrow with protocol-specific tooling.
- Many services support unauthenticated probes (FTP anon, SMB null session, SNMP public, IPMI v2.0 RAKP) — try those first; defenders should treat any unauth disclosure as a finding.
- Document banners, version strings, share names, and OIDs before pivoting to exploitation.

## Infrastructure-based Enumeration
| Command | Description |
| --- | --- |
| `curl -s https://crt.sh/\?q\=<target-domain>\&output\=json \| jq .` | Certificate transparency. |
| `for i in $(cat ip-addresses.txt);do shodan host $i;done` | Scan each IP address in a list using Shodan. |

## Host-based Enumeration

### FTP (21/tcp)
| Command | Description |
| --- | --- |
| `ftp <FQDN/IP>` | Interact with the FTP service on the target. |
| `nc -nv <FQDN/IP> 21` | Interact with the FTP service on the target. |
| `telnet <FQDN/IP> 21` | Interact with the FTP service on the target. |
| `openssl s_client -connect <FQDN/IP>:21 -starttls ftp` | Encrypted FTP interaction. |
| `wget -m --no-passive ftp://anonymous:anonymous@<target>` | Anonymous mirror download. |

### SMB (445/tcp)
| Command | Description |
| --- | --- |
| `smbclient -N -L //<FQDN/IP>` | Null session list shares. |
| `smbclient //<FQDN/IP>/<share>` | Connect to a specific share. |
| `rpcclient -U "" <FQDN/IP>` | RPC null session. |
| `samrdump.py <FQDN/IP>` | Username enumeration (Impacket). |
| `smbmap -H <FQDN/IP>` | Enumerate shares + permissions. |
| `crackmapexec smb <FQDN/IP> --shares -u '' -p ''` | Null-session share enum. |
| `enum4linux-ng.py <FQDN/IP> -A` | Comprehensive SMB enum. |

### NFS (2049/tcp)
| Command | Description |
| --- | --- |
| `showmount -e <FQDN/IP>` | Show available NFS shares. |
| `mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock` | Mount a share. |
| `umount ./target-NFS` | Unmount. |

### DNS (53/udp+tcp)
| Command | Description |
| --- | --- |
| `dig ns <domain.tld> @<nameserver>` | NS records from a specific NS. |
| `dig any <domain.tld> @<nameserver>` | ANY query (may be refused). |
| `dig axfr <domain.tld> @<nameserver>` | Zone transfer. |
| `dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>` | Subdomain brute force. |

### SMTP (25/tcp)
| Command | Description |
| --- | --- |
| `telnet <FQDN/IP> 25` | Manual banner / verb-set check. |

### IMAP/POP3 (143/993, 110/995)
| Command | Description |
| --- | --- |
| `curl -k 'imaps://<FQDN/IP>' --user <user>:<password>` | IMAPS login via cURL. |
| `openssl s_client -connect <FQDN/IP>:imaps` | IMAPS interaction. |
| `openssl s_client -connect <FQDN/IP>:pop3s` | POP3S interaction. |

### SNMP (161/udp)
| Command | Description |
| --- | --- |
| `snmpwalk -v2c -c <community string> <FQDN/IP>` | Walk OIDs. |
| `onesixtyone -c community-strings.list <FQDN/IP>` | Brute force community strings. |
| `braa <community string>@<FQDN/IP>:.1.*` | Brute force OIDs. |

### MySQL (3306/tcp)
| Command | Description |
| --- | --- |
| `mysql -u <user> -p<password> <FQDN/IP>` | Login. |

### MSSQL (1433/tcp)
| Command | Description |
| --- | --- |
| `mssqlclient.py <user>@<FQDN/IP> -windows-auth` | Login with Windows auth (Impacket). |

### IPMI (623/udp)
| Command | Description |
| --- | --- |
| `msf6 auxiliary(scanner/ipmi/ipmi_version)` | Version detection. |
| `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)` | Dump RAKP hashes (IPMI 2.0 CVE-2013-4786). |

### Linux Remote Management (SSH 22/tcp)
| Command | Description |
| --- | --- |
| `ssh-audit.py <FQDN/IP>` | Remote SSH security audit. |
| `ssh <user>@<FQDN/IP>` | Standard login. |
| `ssh -i private.key <user>@<FQDN/IP>` | Key login. |
| `ssh <user>@<FQDN/IP> -o PreferredAuthentications=password` | Force password auth. |

### Windows Remote Management (RDP 3389, WinRM 5985/5986)
| Command | Description |
| --- | --- |
| `rdp-sec-check.pl <FQDN/IP>` | RDP security check. |
| `xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>` | RDP from Linux. |
| `evil-winrm -i <FQDN/IP> -u <user> -p <password>` | WinRM login. |
| `wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"` | Execute via WMI (Impacket). |

## Defence / Remediation
- Network segmentation: never expose SMB/RDP/WinRM/MSSQL/SNMP/IPMI directly to the internet — VPN/zero-trust gateway only (CIS Control 12).
- Disable unauth probes: FTP anonymous, SMB null session (`RestrictNullSessAccess=1`), SNMP `public`/`private` community strings, IPMI v2.0 (cipher 0).
- DNS: disable AXFR for untrusted resolvers; use DNSSEC for zones.
- Patch & track CVEs for management interfaces — these tend to be high-impact (CVE-2020-0796 SMBGhost, CVE-2022-30190 Follina, IPMI RAKP).
- Banner-tightening helps detection but doesn't substitute for patching.

## Sources
- OWASP WSTG Information Gathering: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/
- HackTricks Pentesting Network: https://book.hacktricks.wiki/en/network-services-pentesting/index.html
- Impacket: https://github.com/fortra/impacket
- CrackMapExec / NetExec: https://github.com/Pennyw0rth/NetExec
- MITRE ATT&CK T1046 Network Service Discovery: https://attack.mitre.org/techniques/T1046/
