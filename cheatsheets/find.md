# find

> `find(1)` recipes for post-exploitation enumeration on Linux: SUID/SGID, writable paths, recent file changes, credential search. Authorized testing only.

## TL;DR
- SUID hunt: `find / -perm -4000 -type f 2>/dev/null`; then cross-reference against GTFOBins.
- Writable paths an unprivileged user owns: `find / -type d -writable 2>/dev/null`.
- Time-bounded change scope: `-newermt 'YYYY-MM-DD'` narrows audit window.
- Pipe to `2>/dev/null` to suppress permission noise; never to mask real errors during analysis.

## Detection / Discovery

### SUID binaries
| Command | Description |
| --- | --- |
| `find / -perm /4000 -type f -exec ls -ld {} \; 2>/dev/null` | List SUID files with `ls -ld` |
| `find / -perm -u=s -type f -exec ls -ld {} \; 2>/dev/null` | Equivalent using symbolic perm |
| `find / -perm -4000 2>/dev/null` | Bare paths only |
| `find / -perm -u=s -type f 2>/dev/null` | Symbolic, paths only |

### Files by owner
| Command | Description |
| --- | --- |
| `find / -type f -user yash 2>/dev/null` | All files owned by user `yash` |

### Writable directories
| Command | Description |
| --- | --- |
| `find / -type d -writable -print 2>/dev/null` | Directories writable by the current user |

### Credential / secret grep
| Command | Description |
| --- | --- |
| `grep -iR 'password' /etc/zabbix/ 2>/dev/null` | Recursive secret grep — replace path/keyword as needed |

### Recently modified files
| Command | Description |
| --- | --- |
| `find /usr/ -type f -newermt '2022-01-01' -ls 2>/dev/null` | All files in `/usr/` modified since date |
| `find /usr/ -type f -newermt '2022-02-01' -not -path "/usr/lib/*" -ls 2>/dev/null` | Same, excluding noisy path |

## Defence / Remediation
- Remove or constrain non-essential SUID binaries (review against the OS vendor's baseline) — CWE-250 Execution with Unnecessary Privileges.
- Mount `/tmp`, `/var/tmp`, `/dev/shm` with `nosuid,nodev,noexec` where compatible with workloads.
- File-integrity monitoring (AIDE / OSSEC / auditd `-a always,exit -F arch=b64 -S chmod -F a1&04000`) to alert on new SUID files.
- Never store cleartext credentials in world-readable config files; use a secrets manager.

## Sources
- `find` man page (GNU): https://man7.org/linux/man-pages/man1/find.1.html
- GTFOBins (SUID/sudo abuse catalog): https://gtfobins.github.io/
- MITRE ATT&CK T1083 File and Directory Discovery: https://attack.mitre.org/techniques/T1083/
- HackTricks Linux privilege escalation: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html
