# TLS Pinning Bypass

> Remove certificate pinning to MitM mobile-app traffic during authorized testing. Bypass technique depends on what pinning API the app uses.

## TL;DR
- Two cheap wins first: install Burp/mitmproxy CA into the device + adjust `network_security_config` (Android) / ATS (iOS).
- For app-enforced pinning, use objection's `sslpinning disable` — covers OkHttp/TrustManager/WebView (Android) and `URLSession`-level pinning (iOS), Cordova/Capacitor/Flutter via extras.
- For exotic pinners (Cronet, BoringSSL pinned at native level, Flutter `dart:io`), drop to a bespoke Frida script.
- Defenders: app pinning is delay; pair with App Attest / Play Integrity and short-lived server-issued tokens.

## Pre-bypass — install CA & route traffic

### Android
1. Burp/mitmproxy export root CA as DER (`.crt`).
2. Android 7+ requires the app to opt-in to user CAs via `network_security_config`. Either:
   - Repack with `apktool b` after adding:
     ```xml
     <network-security-config>
       <base-config>
         <trust-anchors>
           <certificates src="system"/>
           <certificates src="user"/>
         </trust-anchors>
       </base-config>
     </network-security-config>
     ```
     then re-sign (`apksigner sign --ks debug.keystore app.apk`).
   - Or push the CA to the system store on a Magisk-rooted device:
     `adb push burp.0 /sdcard/ && adb shell "su -c 'mv /sdcard/burp.0 /apex/com.android.conscrypt/cacerts/'"`.
3. Set proxy: `adb shell settings put global http_proxy <host>:8080`.

### iOS
1. AirDrop / iMessage the Burp/mitmproxy `.pem` to the device.
2. Install profile (Settings → General → VPN & Device Management).
3. **Trust** the root in Settings → General → About → Certificate Trust Settings.
4. Wi-Fi proxy: Settings → Wi-Fi → ⓘ → HTTP Proxy → Manual.

## Bypass — pinning APIs

### Android: OkHttp (`CertificatePinner`) + system TrustManager
Objection one-liner:
```
objection -g com.target explore
android sslpinning disable
```
Bespoke Frida (subset shown):
```js
Java.perform(function () {
  // OkHttp 3.x
  var CertificatePinner = Java.use('okhttp3.CertificatePinner');
  CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () { return; };

  // Custom X509TrustManager.checkServerTrusted
  var ArrayList = Java.use('java.util.ArrayList');
  var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
  TrustManagerImpl.verifyChain.implementation = function (untrustedChain) { return untrustedChain; };
});
```

### Android: WebView
WebView calls `WebViewClient.onReceivedSslError(WebView, SslErrorHandler, SslError)`. Apps that simply call `handler.proceed()` are pre-broken. Apps that call `handler.cancel()` after an extra-check, hook the override and force `proceed`:
```js
Java.perform(function () {
  var Client = Java.use('android.webkit.WebViewClient');
  Client.onReceivedSslError.implementation = function (view, handler, err) {
    handler.proceed();
  };
});
```

### iOS: `URLSession` delegate pinning
Objection: `ios sslpinning disable` (uses `SSL Kill Switch 3` style hooks). Bespoke:
```js
// Force NSURLSessionAuthChallengeUseCredential with the server-provided cert
var URLSession = ObjC.classes.NSURLSession;
Interceptor.attach(URLSession['- URLSession:didReceiveChallenge:completionHandler:'].implementation, {
  // pattern: override handler block to accept server credential
});
```
For low-level pinning via `SecTrustEvaluateWithError`, patch `SecTrustEvaluateWithError` to always return `true` (SSL Kill Switch's approach).

### Flutter / Dart `dart:io` HttpClient
`HttpClient` uses BoringSSL bundled into the Flutter engine — neither objection nor `network_security_config` apply. Use:
- `reFlutter` (https://github.com/Impact-I/reFlutter) — patches the Flutter engine to disable pinning + use system proxy.
- Or proxy via VPN-mode tools (PCAPdroid for Android) and inspect TLS material via SSLKEYLOG dumps when running on emulator with patched Flutter engine.

### React Native / Cordova / Capacitor
Standard Frida hooks cover the JS-bridge layer's `fetch` / XHR; native pinning libraries (e.g. `cordova-plugin-advanced-http`) usually drop to Android/iOS APIs covered above.

## Defence / Remediation
- **Pin to SPKI hashes of issuing intermediates**, not to leaf certs — rotation will break leaf-pinned apps.
- **Maintain a backup pin** (current + next rotation) so a single CA event does not brick the app.
- **App Attest / Play Integrity attestation** tied per-request to a short-lived nonce — a Frida hook that strips pinning will still fail attestation, raising the bar beyond pinning-alone.
- **Detect hook artefacts**: scan `/proc/self/maps` for `frida-agent`/`frida-gadget`; check for SSL Kill Switch's signature dylib; if Frida is present, refuse to load the auth token (combined with server-side anomaly detection).
- **Network logging**: backend should alert on the same auth token presenting from heterogeneous user-agents or impossible geographies — pinning bypass is silent on the device, noisy on the backend.

## Sources
- OWASP MASTG — Network Communication (MSTG-NETWORK): https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0067/
- objection wiki — SSL pinning bypass: https://github.com/sensepost/objection/wiki
- Frida CodeShare (community scripts): https://codeshare.frida.re/
- HackTricks Android SSL pinning bypass: https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/avd-android-virtual-device.html
- reFlutter (Flutter engine repacker): https://github.com/Impact-I/reFlutter
- Android `network_security_config` reference: https://developer.android.com/training/articles/security-config
