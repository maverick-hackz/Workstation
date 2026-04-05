# Scan (Web/Network Discovery)

> Quick recipes for directory, content, and tech-stack discovery against authorized targets. For credential brute force see [hydra.md](./hydra.md); for reverse shells / TTY upgrade see [../post-exploitation/reverse-shells.md](../post-exploitation/reverse-shells.md).

## TL;DR
- Directory brute force: feroxbuster (recursive, Rust, fast) or ffuf (single-pass, scriptable). wfuzz is older but still useful for replay.
- Web fingerprint: `whatweb`, `nikto`, then targeted scans by stack.
- Subdomain discovery: `sublist3r` for passive enumeration; combine with CT-log queries (`crt.sh`).
- Don't use these against systems without written authorization.

## Detection / Discovery

### Directory / content scanners
| Command | Description |
| --- | --- |
| `feroxbuster -u <IP>` | Recursive directory brute force |
| `ffuf -w wordlist:FUZZ -u http://<IP>/FUZZ` | Single-pass directory brute force (see ffuf.md for details) |
| `wfuzz -w wordlist -u http://<IP>/FUZZ` | Web fuzzer (replay-oriented) |

### Web tech fingerprint
| Command | Description |
| --- | --- |
| `nikto -h <IP>` | Misconfig / known-issue web scan |
| `whatweb <IP>` | Tech-stack identification |
| `sublist3r -d <DOMAIN>` | Passive subdomain enumeration |

## Defence / Remediation
See [ffuf.md → Defence](./ffuf.md#defence--remediation). Same controls apply to all directory/content brute-force tools: rate-limit, generic error responses, removal of default/backup content, WAF/CDN rules.

## Sources
- feroxbuster upstream: https://github.com/epi052/feroxbuster
- nikto upstream: https://github.com/sullo/nikto
- whatweb upstream: https://github.com/urbanadventurer/WhatWeb
- sublist3r upstream: https://github.com/aboul3la/Sublist3r
- HackTricks pentesting web: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html
