# Sample App

Compose host that demonstrates AndroidShield runtime features end-to-end.

**Package:** `com.androidshield.sample`  
**Application ID:** `com.androidshield.sample`

## What it shows

| Control | API |
|---------|-----|
| Verify | `AndroidShield.verify()` |
| Start / stop monitoring | `startMonitoring()` / `stopMonitoring()` |
| Secure storage round-trip | `secureStorage().putString` / `getString` |
| Report + JSON | `generateReport()` + `SecurityReportBuilder.toJson` |
| Screen protection | `protectScreen(activity)` on launch |
| Native status | `NativeShield.isAvailable()` / `evaluate()` |
| Annotations | `@ShieldProtect` / `@ShieldEncrypt` on `ProtectedSecrets` |

Policy remains **report-only** — the UI surfaces score / threats; it does not force-kill the process.

## Run

```bash
./gradlew :sample-app:assembleDebug
./gradlew :sample-app:installDebug
```

In Android Studio: open the `sample-app` run configuration.

## Notes

- Play Integrity is disabled in `SampleApplication` so the demo works without a cloud project.
- The Gradle plugin is **not** applied in-repo (see plugin docs); annotations are still present for consumer illustration.
- Emulators often report emulator / debug-related threats — that is expected.
