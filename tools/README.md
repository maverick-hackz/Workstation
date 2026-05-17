# Tools

Bundled third-party tools. Sources kept in-repo for offline use. For latest versions, clone from upstream.

## Web

| Tool | Purpose | Upstream | Bundled path |
| --- | --- | --- | --- |
| XSStrike | XSS detection & exploitation | https://github.com/s0md3v/XSStrike | tools/web/XSStrike/ |
| GraphQLmap | GraphQL exploitation | https://github.com/swisskyrepo/GraphQLmap | tools/web/GraphQLmap/ |
| LFISuite | LFI exploitation | https://github.com/D35m0nd142/LFISuite | tools/web/LFISuite/ |
| Log4jUnifi | Log4Shell PoC against UniFi | https://github.com/puzzlepeaches/Log4jUnifi | tools/web/Log4jUnifi/ |
| NmapAutomator | Nmap-driven recon | https://github.com/21y4d/nmapAutomator | tools/web/NmapAutomator/ |
| Revshellgen | Reverse shell generator | https://github.com/t0thkr1s/revshellgen | tools/web/Revshellgen/ |
| GitTools | .git/ exposure exploitation | https://github.com/internetwache/GitTools | tools/web/GitTools/ |
| firefox_decrypt | Decrypt saved Firefox creds | https://github.com/unode/firefox_decrypt | tools/web/firefox_decrypt/ |
| weevely3 | PHP webshell framework | https://github.com/epinna/weevely3 | tools/web/weevely3/ |

## Reverse

| Tool | Purpose | Upstream | Bundled path |
| --- | --- | --- | --- |
| STEWS | WebSocket security testing | https://github.com/PalindromeLabs/STEWS | tools/reverse/STEWS/ |
| pyinstxtractor | PyInstaller exe extraction | https://github.com/extremecoders-re/pyinstxtractor | tools/reverse/pyinstxtractor/ |
| uncompyle6 | Python bytecode decompiler | https://github.com/rocky/python-uncompyle6 | tools/reverse/uncompyle6 |

> Note on `tools/reverse/uncompyle6`: this is a thin 231-byte entry-point script that imports `uncompyle6.bin.uncompile`. It is **not** the full package — install via `pip install uncompyle6` (Python ≤ 3.8) or `pip install decompyle3` (3.7-3.9 fork) to actually use it. See upstream for current Python version support.

> Note on `tools/reverse/pyinstxtractor/`: the upstream example target (`qreader.exe`, 87 MB Windows PyInstaller binary) was removed in Phase 9a to keep the repo lean. If you want an offline target sample for `pyinstxtractor.py`, fetch from upstream — https://github.com/pyinstxtractor/pyinstxtractor-test-binaries — or build your own with `pyinstaller --onefile`. History still carries the binary; a future `git filter-repo` pass can scrub it from `.git` pack if needed.

## Refreshing a bundled tool

```bash
# example: refresh XSStrike
rm -rf tools/web/XSStrike
git clone --depth=1 https://github.com/s0md3v/XSStrike tools/web/XSStrike
rm -rf tools/web/XSStrike/.git
git add tools/web/XSStrike
```

The `rm -rf .git` step is important — leftover `.git/` inside a bundled tool turns it into a nested git repo which `git submodule` does not track and breaks `git mv`.

## Audit

Last verification (Phase 0): no `.git/` directories inside any bundled tool. Run the check again before committing a refresh:

```bash
find tools/ -type d -name .git
```

## Authorized testing only.

All bundled tools are offensive-security utilities and are intended for authorized engagements, CTFs, and AppSec research. Upstream licences apply to each bundled copy — check the tool's repository for the specific terms.
