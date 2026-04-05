# ffuf

> Fast HTTP fuzzer — directory, file, parameter, vhost and value discovery. Authorized testing only.

## TL;DR
- `FUZZ` is the default placeholder; use `-w wordlist:KEY` to bind multiple keywords.
- Filter noise with `-fs <bytes>`, `-fc <status>`, `-fl <lines>`, `-fw <words>`, `-fr <regex>`.
- Recursion: `-recursion -recursion-depth N -e .php,.txt`.
- For vhosts, fuzz the `Host:` header; for parameter discovery, fuzz the query string with a sequence wordlist.

## Detection / Discovery
| Command | Description |
| --- | --- |
| `ffuf -h` | ffuf help |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ` | Directory Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ` | Extension Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php` | Page Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v` | Recursive Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/` | Sub-domain Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx` | VHost Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx` | Parameter Fuzzing — GET |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing — POST |
| `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Value Fuzzing |

## Wordlists
| Path | Purpose |
| --- | --- |
| `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory / page wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt` | Extensions wordlist |
| `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` | Subdomain wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt` | Parameter-name wordlist |

## Misc
| Command | Description |
| --- | --- |
| `sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'` | Add DNS entry |
| `for i in $(seq 1 1000); do echo $i >> ids.txt; done` | Create sequence wordlist |
| `curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'` | curl w/ POST equivalent |

## Defence / Remediation
- Rate-limit + bot-detection on unauthenticated discovery endpoints; CWE-799 Improper Control of Interaction Frequency.
- Remove default/backup files (`backup.zip`, `.git/`, `.env`, `phpinfo.php`) from production document roots.
- Generic error responses; consistent status codes so attackers cannot use response-size oracles.
- WAF/CDN rules to block requests with no `Referer`/`Origin` and high-rate path enumeration patterns.

## Sources
- ffuf upstream: https://github.com/ffuf/ffuf
- SecLists: https://github.com/danielmiessler/SecLists
- OWASP WSTG-INFO-08 Fingerprint web application framework: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework
