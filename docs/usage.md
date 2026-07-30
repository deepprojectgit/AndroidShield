# Usage Guide

## Runtime API

All hosts should go through `com.androidshield.runtime.api.AndroidShield`.

| Call | When |
|------|------|
| `initialize(context, config)` | Once in `Application.onCreate` |
| `verify()` | Cold start, resume, sensitive flows |
| `startMonitoring()` / `stopMonitoring()` | Continuous RASP |
| `getThreats()` / `generateReport()` | UI / telemetry |
| `isCompromised()` | Quick gate on last report |
| `protectScreen(activity)` | Sensitive screens |
| `secureStorage()` | Secrets / tokens |
| `clipboard()` | Auto-clear while monitoring |
| `sslHostnameVerifier(configs)` | Pinning helper |
| `playIntegrity(context, projectNumber)` | Play Integrity token helper |

Detail: [api.md](api.md) · [runtime.md](runtime.md)

## Configuration

`ShieldConfig` (runtime) and `androidShield { }` (build-time) are related but distinct:

- **Runtime config** enables/disables detectors and helpers at process start.
- **Gradle DSL** controls ASM transforms, resource encryption, integrity emission, R8 rules.

Prefer matching flags across both planes (e.g. `nativeProtection`).

## Report-only default (CRITICAL)

AndroidShield **does not** kill or lock the app when threats appear. Hosts decide:

```kotlin
val report = AndroidShield.verify()
when {
    report.threats.any { it.severity == Severity.CRITICAL } -> logout()
    !report.secure -> degradeSensitiveFeatures()
    else -> continueNormally()
}
```

`SecurityReport` JSON:

```json
{
  "secure": true,
  "score": 98,
  "threats": []
}
```

Scoring: `ScoringPolicy.DEFAULT` (HIGH/CRITICAL fail) or `STRICT` (also MEDIUM). See [core.md](core.md).

## Build-time protection

1. Apply `com.androidshield.gradle`
2. Annotate hot paths with `@ShieldProtect` / `@ShieldEncrypt`
3. Limit scope with `protectPackages` / `encryptAssetPatterns`
4. Ship integrity metadata produced under `build/androidshield/<variant>/`

Decrypt path for rewritten strings:

`ShieldStringDecryptor.decrypt(cipherText, iv)` ← installed via generated `BuildShieldSecrets`.

## Offline CI

```bash
android-shield-cli verify app-release.apk --policy strict --require-integrity --json
```

Exit `0` secure · `1` insecure · `2` error. See [cli.md](cli.md).

## Native bridge

```kotlin
if (NativeShield.isAvailable()) {
    val findings = NativeShield.evaluate()
    // findings.isClean / debuggerFlags / hookFlags / memoryFlags
}
```

When the `.so` is present, string decrypt / key unscramble prefer native AES-GCM. See [native.md](native.md).
