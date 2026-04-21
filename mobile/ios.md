# iOS Application Testing

> iOS app-pentest paths: IPA unpacking, plist/Info review, keychain access, IPC abuse, runtime hooks with Frida/objection. Requires jailbroken device or simulator. Authorized testing only. Map: OWASP MASTG.

## TL;DR
- IPAs are zip-wrapped `.app` bundles; binaries are FairPlay-encrypted unless pulled from a jailbroken device (clutch / frida-ios-dump).
- Most findings: hard-coded keys, insecure NSUserDefaults / Keychain access groups, insecure IPC via custom URL schemes / universal links, missing TLS pinning.
- Static: `class-dump`, `Hopper`/`Ghidra`/`IDA`, `otool`. Dynamic: Frida + objection, Cycript (deprecated on iOS 13+).
- MASVS-RESILIENCE controls (anti-jailbreak, anti-debug) are delay/detection — assume bypass; treat as defence-in-depth.

## Detection / Discovery
| Command | Description |
| --- | --- |
| `unzip app.ipa -d app/` | Unwrap IPA; binary in `app/Payload/<name>.app/<name>` |
| `plutil -convert xml1 Info.plist -o -` | Render Info.plist (URL schemes, ATS exemptions, capabilities) |
| `otool -h <binary>` / `otool -L <binary>` | Mach-O header + linked libs |
| `class-dump-z <binary>` | Objective-C class headers |
| `frida-ios-dump -l` then `dump.py <bundle_id>` | Decrypt FairPlay binary off a jailbroken device |
| `MobSF` | Static + dynamic IPA analysis |

Key Info.plist keys to flag:
- `NSAppTransportSecurity` → `NSAllowsArbitraryLoads = YES` (cleartext allowed)
- `CFBundleURLTypes` → custom URL scheme (deeplink surface)
- `com.apple.developer.associated-domains` → universal-link surface
- `NSCameraUsageDescription` / similar — privilege scope

## Exploitation

### Static reverse
- `strings -a <binary> | grep -E '(http|api|secret|token)'` — fast win.
- `class-dump` then look for `NSURLSession` delegate methods overriding `didReceiveChallenge` — likely TLS-pinning logic to bypass.
- Hard-coded keys are common in `+ (NSString*)apiKey` static methods.

### Keychain dump (jailbroken)
| Command | Description |
| --- | --- |
| `objection -g <bundle_id> explore` then `ios keychain dump` | Dump app's keychain entries |
| `ios pasteboard monitor` (objection) | Watch the global pasteboard for sensitive data leakage |

### IPC abuse
| Vector | Notes |
| --- | --- |
| Custom URL scheme (`myapp://...`) | Other apps can launch; verify destination handler validates source via `LSApplicationQueriesSchemes` + universal-link fallback |
| Universal links (`https://example.com/...`) | Apple-Site-Association file controls; XSS in the universal-link landing page can hijack flow |
| `UIPasteboard.general` | App-wide pasteboard; never put auth tokens here |

### Insecure storage paths
- `/var/mobile/Containers/Data/Application/<uuid>/Library/Preferences/<bundle>.plist` — NSUserDefaults
- `/var/mobile/Containers/Data/Application/<uuid>/Documents/` — Documents
- Keychain — query via objection (above); attributes `kSecAttrAccessibleAlways` / `kSecAttrAccessibleAfterFirstUnlock` weaken the threat model.

## Bypasses
- Jailbreak detection — see [./frida-objection.md](./frida-objection.md), `objection ios jailbreak disable`.
- TLS pinning — see [./tls-pinning-bypass.md](./tls-pinning-bypass.md); SSL Kill Switch 3 / objection `ios sslpinning disable`.
- Touch / Face ID — `objection ios ui biometrics_bypass` patches `LAContext.evaluatePolicy:` callbacks.

## Defence / Remediation
- **Keychain** with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for tokens; `Secure Enclave`-backed `SecKey` for cryptographic identities (MASVS-CRYPTO).
- **App Attest** (`DCAppAttestService`) for app integrity / anti-replay on backend calls (MASVS-RESILIENCE).
- **ATS strict mode** (`NSExceptionAllowsInsecureHTTPLoads = NO`) — never ship arbitrary-loads ON.
- **Certificate pinning**: implement in `URLSessionDelegate.urlSession(_:didReceive:completionHandler:)` against the SPKI hash of an intermediate cert; rotate via app update.
- **Validate** URL-scheme / universal-link inputs as attacker-controlled — no `eval`-like sinks, no token-bearing routes.
- **Disable `UIPasteboard` sharing** for sensitive screens with `UITextField.isSecureTextEntry = true`; iOS 14+ shows the pasteboard-read prompt automatically.

## Sources
- OWASP MASTG (iOS chapter): https://mas.owasp.org/MASTG/0x06-iOS-Testing-Guide/
- OWASP MASVS: https://mas.owasp.org/MASVS/
- HackTricks iOS pentesting: https://book.hacktricks.wiki/en/mobile-pentesting/ios-pentesting/index.html
- Apple Platform Security guide: https://support.apple.com/guide/security/welcome/web
- frida-ios-dump: https://github.com/AloneMonkey/frida-ios-dump
- SSL Kill Switch 3 (Frida): https://github.com/nabla-c0d3/ssl-kill-switch2
