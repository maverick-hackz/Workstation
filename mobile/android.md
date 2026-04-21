# Android Application Testing

> Common Android app-pentest paths: static review of the APK, dynamic instrumentation, IPC/component abuse, insecure storage. Authorized testing only. Map: OWASP MASTG.

## TL;DR
- Pull the APK (`adb shell pm path …` + `pull`), then unpack with `apktool` or `jadx`.
- Most findings: hard-coded secrets, debug-flag enabled, exported components, cleartext traffic, insecure storage in `/data/data/<pkg>/`.
- Dynamic: Frida + objection for runtime hooks; Burp + system-CA install (Android 7+ requires app `network_security_config` opt-in or a Frida bypass).
- MASTG / MASVS define the canonical control catalogue; cite Mxxx ID per finding.

## Detection / Discovery
| Command | Description |
| --- | --- |
| `adb devices -l` | List attached / emulator devices |
| `adb shell pm list packages -f -3` | List user-installed packages with their APK paths |
| `adb shell pm path <pkg>` then `adb pull <path>` | Pull the APK off the device |
| `apktool d app.apk -o app/` | Decode resources + `AndroidManifest.xml` |
| `jadx-gui app.apk` | Java decompiler with cross-refs |
| `aapt dump badging app.apk` | Manifest summary (permissions, components, target SDK) |
| `mobsf` (`opensecurity/mobile-security-framework-mobsf`) | Automated static + dynamic analysis |

## Exploitation

### Static review of `AndroidManifest.xml`
| Indicator | Why it matters |
| --- | --- |
| `android:debuggable="true"` | Anyone with adb can attach `jdb` and dump runtime state (CWE-489). |
| `android:allowBackup="true"` | `adb backup` extracts app private data without root. |
| `android:exported="true"` on activity/service/receiver/provider without permission | Cross-app IPC into the component. |
| `<uses-permission android:name="…"/>` with overbroad scope | Excess privilege; flag against ASVS / MASVS V1. |
| `usesCleartextTraffic="true"` or missing `network_security_config` | Plaintext HTTP allowed. |

### Component abuse
| Command | Description |
| --- | --- |
| `adb shell am start -n com.target/.SomeActivity --es key value` | Launch exported activity with extras |
| `adb shell am startservice -n com.target/.SomeService` | Start exported service |
| `adb shell am broadcast -a com.target.ACTION -n com.target/.Receiver` | Trigger exported broadcast receiver |
| `adb shell content query --uri content://com.target.provider/users` | Read from exported `ContentProvider` (IDOR class) |

### Insecure storage
| Path | Notes |
| --- | --- |
| `/data/data/<pkg>/shared_prefs/*.xml` | SharedPreferences (often plaintext secrets) |
| `/data/data/<pkg>/databases/*` | SQLite (grep for tokens, PII) |
| `/sdcard/Android/data/<pkg>/` | World-readable on legacy Android |

### WebView attack surface
- `setJavaScriptEnabled(true)` + `addJavascriptInterface(obj, "Bridge")` → attacker JS calls Bridge methods (CVE class CWE-749).
- `setAllowFileAccessFromFileURLs(true)` enables file:// JS → cross-origin file read.
- Deeplink hijacking via `intent://` URIs and `S.browser_fallback_url`.

## Bypasses
- Root detection — see [./frida-objection.md](./frida-objection.md), `objection android root disable`.
- TLS pinning — see [./tls-pinning-bypass.md](./tls-pinning-bypass.md).
- Network-security-config (Android 7+ system-CA opt-out) — repack APK with `apktool b` after adding `<base-config><trust-anchors><certificates src="user"/></trust-anchors></base-config>`, resign with `apksigner`.
- Emulator detection — patch the check or run on a physical device with Magisk.

## Defence / Remediation
- **Don't store secrets in the APK**. Android Keystore for cryptographic keys (`KeyGenParameterSpec` with hardware-backing where available). MASVS-STORAGE.
- **Disable cleartext traffic** via `network_security_config` (`cleartextTrafficPermitted="false"`), pin certificates correctly (don't pin to a leaf cert that rotates — pin the SPKI of an intermediate or use Google's `TrustKit`).
- **Strict exported components**. Default to `android:exported="false"`. If exported, gate by `android:permission` with a custom signature-level permission for caller-app verification.
- **WebView**: avoid `addJavascriptInterface` for untrusted content. Use `WebViewAssetLoader` to serve same-origin content from APK assets instead of `file://`.
- **Tamper / root detection** is delay-not-prevent; combine with Play Integrity API (MASVS-RESILIENCE) but assume bypass.
- **R8/ProGuard** obfuscation raises reverse-engineering cost; not a security boundary.

## Sources
- OWASP MASTG (Mobile Application Security Testing Guide): https://mas.owasp.org/MASTG/
- OWASP MASVS (Mobile App Security Verification Standard): https://mas.owasp.org/MASVS/
- HackTricks Android pentesting: https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/index.html
- Android Developers — `network_security_config`: https://developer.android.com/training/articles/security-config
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- Frida: https://frida.re/docs/home/
