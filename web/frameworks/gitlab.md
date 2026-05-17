# GitLab

> Source control + CI/CD + container registry + package registry — multi-surface target. Authorized testing only. Map: also [../../cicd-supply-chain/](../../cicd-supply-chain/).

## TL;DR
- GitLab consolidates several services into one self-hosted Omnibus / Kubernetes deployment. Each subsystem has its own attack surface.
- Top paths: account takeover via GitLab CVEs (frequent; 1-2/quarter critical), runner-token leakage, group-access token misuse, deploy-key reuse, SSO/SAML config flaws, Container Registry credential leaks.
- Self-hosted instances lag patches; SaaS (gitlab.com) generally current. Versions readily fingerprinted.
- Defence: aggressive patching (Critical CVE → 24h), 2FA enforced, group-level Access Tokens scoped + expiry, runner isolation, mandatory code review on protected branches.

## Detection / Discovery

### Fingerprint
```bash
# Version exposed in unauth API
curl -s https://target/api/v4/version | jq          # auth required (modern); used to be open
curl -s https://target/help | grep -iE 'gitlab .*[0-9]+\.[0-9]+\.[0-9]+'
curl -s https://target/users/sign_in | grep -i 'gitlab'

# Or visit /admin/dashboard (needs auth)
# Or check the meta tag: <meta name="csrf-token" content="..."> and reading version from JS bundles
```

### Public project / group enumeration (anon)
```bash
# Public projects
curl -s "https://target/explore/projects" | grep -oE 'data-project-id="[0-9]+"' | sort -u

# Public users (often readable)
curl -s https://target/api/v4/users | jq

# Public groups
curl -s https://target/api/v4/groups | jq
```

### Once authenticated — token / credential inventory
```bash
# List your access tokens / SSH keys / GPG keys (UI)  /-/profile/personal_access_tokens

# As admin: every user's tokens via API
GITLAB_TOKEN=glpat-...
curl -sH "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://target/api/v4/users?per_page=100" | jq -r '.[].id' | while read uid; do
  curl -sH "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://target/api/v4/users/$uid/impersonation_tokens"
done
```

## Exploitation

### CVE history (track current)
GitLab publishes critical CVEs roughly monthly. Track at https://about.gitlab.com/releases/categories/releases/. Past notable critical (sample):
- CVE-2023-7028 — account-takeover via password-reset email injection (unauth → any account).
- CVE-2024-0402 — arbitrary file write in workspace creation.
- CVE-2024-6385 — pipeline as another user (any user can trigger pipeline as victim).
- CVE-2024-2829 — DoS via complex GraphQL queries.

Always cross-check the running version against the advisory page; a Critical at version N usually has a patch at N.YY.Z.

### Account takeover paths
- CVE-2023-7028 chain (password-reset misrouted to attacker's email when target has multiple emails).
- 2FA bypass via SAML/OIDC SSO misconfig — IdP doesn't enforce 2FA → IdP-initiated SSO grants access without GitLab's local 2FA.
- Session-fixation via XSS in markdown rendering (historical; pipeline of markdown CVEs).

### Runner token leakage
GitLab Runners register with a token. If a token leaks (CI logs, public repo `.gitlab-ci.yml`, env var dump), attacker:
1. Registers an attacker-owned runner with the token.
2. The runner now receives jobs from the org — including jobs with secrets in environment variables.
3. Attacker runs jobs in their controlled environment with the secrets in-scope.

```bash
# Register attacker runner with leaked token
gitlab-runner register \
  --url https://target/ \
  --registration-token <leaked-token> \
  --executor shell

# Then trigger any pipeline; attacker runner picks it up; secrets visible in env
```

### Group / project access tokens
Group-level access tokens have `api` scope by default — full read/write across the group's projects. Leaked tokens land in:
- CI logs (printed via `set -x` in scripts).
- Container images (baked-in at build).
- Public repos (committed `.env` files).

```bash
# Verify a token's scope
curl -sH "PRIVATE-TOKEN: $TOKEN" https://target/api/v4/personal_access_tokens/self | jq
# Use it
curl -sH "PRIVATE-TOKEN: $TOKEN" https://target/api/v4/projects/<id>/repository/files/path%2Fto%2Fsecret.yml/raw
```

### Deploy-key reuse
A deploy key registered on one project that also has read access to others — attacker compromises the first project's deployment infrastructure → uses the same key to clone other repos.

### SAML / OIDC misconfig
- IdP-initiated SSO with no `RelayState` validation → attacker logs the victim into attacker's GitLab session (CSRF-on-login).
- SAML XML Signature Wrapping (see [../oauth-saml.md](../oauth-saml.md)) → attacker submits a SAML assertion claiming any user.

### Container Registry / Package Registry
- `/api/v4/projects/:id/registry/repositories` lists images.
- If `Registry` access tokens are scoped to `read_registry` for a CI job and the job is triggered by a fork PR → fork-author can read all images in scope (CI/CD-SEC-04 PPE; see [../../cicd-supply-chain/poisoned-pipeline-execution.md](../../cicd-supply-chain/poisoned-pipeline-execution.md)).

### `.gitlab-ci.yml` poisoning (analog to GH Actions)
See [../../cicd-supply-chain/github-actions.md](../../cicd-supply-chain/github-actions.md) — GitLab's equivalent is `pipeline_source: merge_request_event` running on the merge-request branch. Misconfigured rules let MR author code touch production secrets.

## Bypasses
- 2FA enforced but git-via-SSH not subject to 2FA → SSH-key access remains bypass channel until SSH-key 2FA-binding is enforced (GitLab 15.6+ optional).
- Personal Access Token rate-limit on /api/v4 → GraphQL endpoint (`/api/graphql`) often has different rate limits.

## Defence / Remediation
- **Patch cadence**: critical CVE → 24-72h max. GitLab publishes security patches monthly; track the release notes.
- **2FA enforced** for all users (group/project setting; for self-hosted, instance-wide). Block legacy push-by-SSH if not paired with key-2FA.
- **Group Access Tokens**: scope to minimum (`read_api` if write not needed); expiry ≤ 90 days; rotate.
- **Personal Access Tokens**: expiry mandatory (admin policy); scope-limited.
- **Runners**: dedicated per project / group; ephemeral; never on a host that has other production access. Strict CI variable masking + protection (only running on protected branches).
- **Branch protection** on `main` + `release/*` + `.gitlab-ci.yml` path-CODEOWNERS-style guard.
- **SAML/OIDC** + IdP-enforced 2FA; require `nonce` in SSO flow.
- **`hashes` lockfiles** required on all dependency manifests (npm `package-lock.json`, pip `--hash=`, Gradle verification metadata) — see [../../cicd-supply-chain/dependency-confusion.md](../../cicd-supply-chain/dependency-confusion.md).
- **Container Registry**: signed images (cosign / Notation; see [../../cicd-supply-chain/sbom-sigstore.md](../../cicd-supply-chain/sbom-sigstore.md)) verified at deploy.
- **Audit log** to SIEM: alert on token creation, runner registration, project transfer, SAML assertion replay.
- **Secret scanning**: GitLab's Secret Detection (default in Ultra) + gitleaks/trufflehog pre-commit.

## Sources
- GitLab releases & security: https://about.gitlab.com/releases/categories/releases/
- GitLab security advisories archive: https://about.gitlab.com/security/
- CVE-2023-7028 (account takeover): https://about.gitlab.com/releases/2024/01/11/security-release-gitlab-16-7-2-released/
- GitLab CI/CD security best practices: https://docs.gitlab.com/ee/ci/pipelines/cicd_minutes.html (and https://docs.gitlab.com/ee/topics/build_your_application.html)
- HackTricks GitLab: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/gitlab.html
- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- GitLab Runner security: https://docs.gitlab.com/runner/security/
