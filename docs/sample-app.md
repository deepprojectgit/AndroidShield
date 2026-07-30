# Example App

The in-repo sample lives at [`sample-app/`](../sample-app/).

See also: [sample-app/README.md](../sample-app/README.md).

## Purpose

A Compose dashboard that:

1. Initializes AndroidShield with a representative `ShieldConfig`
2. Runs `verify()` and shows score / threat list / JSON
3. Toggles RASP monitoring
4. Exercises `SecureStorage`
5. Surfaces `NativeShield` load status
6. Applies `protectScreen` (FLAG_SECURE)
7. Shows `@ShieldProtect` / `@ShieldEncrypt` annotation usage

## Build & install

```bash
./gradlew :sample-app:installDebug
```

## Expected behaviour

- Debuggable builds on emulators often surface emulator / debugger signals — that validates detectors, not a false failure of the framework.
- Play Integrity stays disabled so tokens are not required for the demo.
- The Gradle plugin is documented for consumers; in-repo plugin coverage is in `:android-shield-plugin:test`.
