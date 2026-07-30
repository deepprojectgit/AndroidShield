# AndroidShield

Commercial-grade, open-source Android application protection framework.

**Repository:** https://github.com/deepprojectgit/AndroidShield  
**Version:** `0.1.0` (Phases 1–8 complete)  
**Min SDK:** 24 · **AGP:** 8.7+ · **Kotlin:** 2.0+  
**License:** Apache License 2.0

Protect Android apps against reverse engineering, debugging, hooking, tampering, and runtime attacks — at **build time** and **runtime (RASP)**.

---

## Status

| Phase | Scope | Status |
|-------|--------|--------|
| 1 | Architecture, modules, build config | **Complete** |
| 2 | Gradle plugin (ASM, encryption, integrity) | **Complete** |
| 3 | Core library (crypto, integrity, scoring) | **Complete** |
| 4 | Runtime protection & RASP | **Complete** |
| 5 | Native (JNI) protection | **Complete** |
| 6 | CLI tool | **Complete** |
| 7 | Sample app | **Complete** |
| 8 | Documentation | **Complete** |

**Report-only by default** — hosts decide policy from `Threat` / `SecurityReport`.

---

## Modules

| Module | Artifact | Role |
|--------|----------|------|
| `android-shield-annotations` | JVM | `@ShieldProtect`, `@ShieldEncrypt` |
| `android-shield-core` | JVM | Models, crypto, integrity, scoring |
| `android-shield-runtime` | AAR | `AndroidShield` API, detectors, RASP |
| `android-shield-native` | AAR + `.so` | JNI anti-debug / integrity / decrypt |
| `android-shield-plugin` | Gradle plugin | `io.github.deepprojectgit.androidshield` + DSL |
| `android-shield-cli` | JVM app | Offline `inspect` / `verify` / `report` |
| `android-shield-testing` | JVM | Shared test fixtures |
| `sample-app` | App | Compose protection dashboard |
| `benchmark` | Android lib | Benchmark placeholders |

**Maven groupId:** `io.github.deepprojectgit.androidshield`  
**Packages:** `com.androidshield.*`

---

## Quick start

```kotlin
plugins {
    id("io.github.deepprojectgit.androidshield") version "0.1.0"
}

dependencies {
    implementation("io.github.deepprojectgit.androidshield:android-shield-runtime:0.1.0")
}

androidShield {
    antiDebug.set(true)
    antiTamper.set(true)
    stringEncryption.set(true)
    nativeProtection.set(true)
}
```

```kotlin
AndroidShield.initialize(context)
val report = AndroidShield.verify()
AndroidShield.startMonitoring()
```

Full steps: [docs/getting-started.md](docs/getting-started.md) · Publishing: [docs/publishing.md](docs/publishing.md).

Until artifacts are on Maven Central, use `mavenLocal()` / composite builds from this repo.  
The GitHub repository should remain **public** for Central OSS publishing.

---

## Build from source

Requirements: JDK 17+, Android SDK (compileSdk 35), NDK + CMake 3.22+.

```bash
./gradlew :android-shield-core:build
./gradlew :android-shield-runtime:assembleDebug
./gradlew :sample-app:assembleDebug
./gradlew :android-shield-cli:installDist
./gradlew test
```

---

## Architecture

Dual-plane design:

1. **Build-time** — Gradle plugin transforms bytecode, encrypts secrets/resources, emits integrity metadata.
2. **Runtime** — ThreatEngine + detectors + optional native checks → `Threat` / `SecurityReport` JSON.

See [docs/architecture.md](docs/architecture.md).

---

## Public API

```text
AndroidShield.initialize(context)
AndroidShield.verify()
AndroidShield.startMonitoring()
AndroidShield.stopMonitoring()
AndroidShield.getThreats()
AndroidShield.generateReport()
AndroidShield.isCompromised()
```

Extended helpers: `protectScreen`, `secureStorage`, `clipboard`, `sslHostnameVerifier`, `playIntegrity`.

---

## Documentation

Start at [docs/README.md](docs/README.md).

- [Getting started](docs/getting-started.md)
- [Usage](docs/usage.md)
- [Architecture](docs/architecture.md)
- [API](docs/api.md)
- [Gradle plugin](docs/gradle-plugin.md)
- [CLI](docs/cli.md)
- [Sample app](docs/sample-app.md)
- [Security design](docs/security-design.md)
- [Publishing](docs/publishing.md)
- [CI/CD](docs/ci-cd.md)
- [Contributing](docs/CONTRIBUTING.md)

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
