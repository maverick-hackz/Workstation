# Contributing

Thanks for considering a contribution. This repository is a personal AppSec / pentest knowledge base, but pull requests that improve accuracy, add citations, or extend cheatsheets are welcome.

## Cheatsheet format (Phase 3 template)

Every cheatsheet under `cheatsheets/`, `recon/`, `web/`, `api/`, `mobile/`, `cloud/`, `containers-k8s/`, `cicd-supply-chain/`, `ad-infrastructure/`, `llm-security/`, and `post-exploitation/` follows this skeleton:

~~~markdown
# <Topic>

> Brief 1-2 sentence description. Authorized testing only.

## TL;DR
- 3-5 bullet lines: what to look for, attack vector, defence.

## Detection / Discovery
| Command | Description |
| --- | --- |

## Exploitation
| Command | Description |
| --- | --- |

## Bypasses
(omit if not applicable)

## Defence / Remediation
- Bullet list. Cite CWE-ID and OWASP-ID where applicable.

## Sources
- Canonical reference 1
- Canonical reference 2
~~~

`## Defence / Remediation` and `## Sources` are **mandatory**. This is an AppSec repository, not an offensive-only collection — every payload must come paired with the control that prevents it.

## Naming convention

| Asset | Convention |
| --- | --- |
| Markdown files | `kebab-case.md` |
| Python scripts | `snake_case.py` (PEP 8) |
| Directories | `kebab-case/` (lowercase) |
| Top-level docs (`README.md`, `DISCLAIMER.md`, `LICENSE`, `CONTRIBUTING.md`) | English |
| Cheatsheet headings | English |

Existing Russian-language comments and descriptions (notably in [cheatsheets/nginx.md](./cheatsheets/nginx.md)) are preserved verbatim. Do not translate without discussion.

## Sources requirement

Every file that documents commands or payloads MUST end with `## Sources` containing **verifiable** references:

- Prefer canonical OWASP / MITRE / NIST / vendor documentation over blog mirrors.
- Tool docs go to the upstream repository or official website.
- Research papers and blog posts are cited by author + venue + year (e.g., "James Kettle — HTTP Desync Attacks, BlackHat 2019").
- If you cannot verify a fact at write time, mark it `<!-- TODO: verify -->` rather than guessing.

## What is not accepted

- Payloads targeting specific real-world systems by IP / hostname / company name.
- 0-day exploits or unpatched-vulnerability disclosures not yet coordinated with the affected vendor.
- Credentials, even for "test" / "demo" systems.
- Tools whose primary purpose is harassment, doxing, or destructive operations against systems you do not own.
- Auto-generated content without citations.

## Scripts

Python scripts under [scripts/](./scripts/) follow a common skeleton:

~~~python
#!/usr/bin/env python3
"""<one-line description>

Usage:
    python3 <name>.py [args]

Authorized testing only.
"""
import argparse


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    ...
    args = parser.parse_args()
    ...
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
~~~

- `KeyboardInterrupt` returns exit 130.
- `requests.exceptions.RequestException` caught at the boundary.
- No `eval()` on attacker-controlled input — use `ast.literal_eval` or a custom safe-evaluator.
- Lint with `ruff` before submitting:
  ~~~bash
  python3 -m venv .venv && source .venv/bin/activate
  pip install ruff
  ruff check scripts/
  ~~~

## Bundled third-party tools

The `tools/` directory bundles upstream projects under their original licenses (GPL, BSD, MIT, etc.). Bundled copies are **not** modified beyond removing leftover `.git/` directories. Refresh a bundled tool using the recipe in [tools/README.md](./tools/README.md):

~~~bash
rm -rf tools/<area>/<tool>
git clone --depth=1 <upstream-url> tools/<area>/<tool>
rm -rf tools/<area>/<tool>/.git
git add tools/<area>/<tool>
~~~

When adding a new bundled tool: add a row to the table in `tools/README.md` (tool name, purpose, upstream URL, bundled path).

## Commit messages

- Imperative mood, one short summary line ≤ 72 chars.
- Body explaining "why" (and "what surprised you"); leave "what" to the diff.
- Co-author trailers for AI assistance are welcome.

## Authorized testing only.
