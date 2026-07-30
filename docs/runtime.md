# Runtime Protection Guide (Phase 4)

Module: `android-shield-runtime`

## Detectors

| Id | Config flag | Signals |
|----|-------------|---------|
| `debug` | `antiDebug` | JDWP, TracerPid, debuggable, timing |
| `tamper` | `antiTamper` | Signatures, sideload, integrity metadata |
| `hook` | `antiHook` | Frida/Xposed packages, maps, stack |
| `root` | `rootDetection` | su, Magisk, props, packages |
| `emulator` | `emulatorDetection` | Build props, files, packages |
| `device` | `runtimeProtection` / `antiDebug` | ADB, developer options, proxy, VPN |
| `rasp` | `runtimeProtection` | maps, threads, tmp injection |

## Public extras

```kotlin
AndroidShield.initialize(context, ShieldConfig())
val report = AndroidShield.verify()
AndroidShield.startMonitoring()
AndroidShield.protectScreen(activity)
AndroidShield.secureStorage().putString("token", secret)
AndroidShield.sslHostnameVerifier(listOf(SslPinningConfig("api.example.com", pins)))
AndroidShield.playIntegrity(context).requestToken()
```

Play Integrity strong/basic/device **verdicts** must be decrypted on your backend; use `PlayIntegrityClient.threatsFromVerdict(...)`.
