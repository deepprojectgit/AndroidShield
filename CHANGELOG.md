# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-08-05

### Changed

- Bump release version to **`0.1.1`** (Maven Central does not allow republishing existing `0.1.0` coordinates)
- Gradle plugin id is `io.github.deepprojectgit.androidshield` (Maven Central namespace requirement)

## [0.1.0] - 2026-07-30

### Added

- Initial public release to Maven Central (`io.github.deepprojectgit.androidshield`)
  - Removed Cloudflare R2 staging/sync flow
  - Unified **CI/CD** workflow: `.github/workflows/ci-cd.yml` (build/test + publish on `main`)
  - Secrets: `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `SIGNING_KEY`, `SIGNING_KEY_ID`, `SIGNING_PASSWORD`

### Added

- Maven Central auto-publish on `main` + `workflow_dispatch` (via CI/CD workflow)
- `androidshield.publishing` now uses vanniktech maven-publish (Central Portal + signing + automatic release)

- Phase 8 documentation hub
  - `docs/getting-started.md`, `docs/usage.md`, `docs/sample-app.md`
  - Expanded `docs/README.md` index and security-design / architecture notes
  - Root README marked Phases 1–8 complete

- Phase 7 sample app polish
  - Compose protection dashboard (verify, monitor, storage, report JSON, native status)
  - `@ShieldProtect` / `@ShieldEncrypt` demo (`ProtectedSecrets`)
  - `sample-app/README.md` + `docs/sample-app.md`

- Phase 6 CLI tool (`android-shield-cli`)
  - `inspect` — APK/AAR/AAB structure, shield markers, AS1 assets, integrity.json
  - `verify` — CI gate with ScoringPolicy (default/strict) + require-* flags
  - `report` — SecurityReport JSON to stdout/file with optional `--fail-on-threats`
  - Exit codes: 0 secure, 1 insecure, 2 error
  - Docs: `docs/cli.md`

- Phase 5 native JNI protection (`libandroidshield`)
  - Anti-debug: TracerPid, ptrace TRACEME, local debugger ports, timing
  - Anti-hook: Frida/Xposed maps, threads, artifact files
  - Memory: rwx mappings + suspicious SO names
  - Integrity: FNV-1a checksum + SHA-256
  - Crypto: native key unscramble + AES-GCM decrypt via `AesGcmCipher`
  - `NativeProtectionDetector` + runtime decrypt/unscramble prefer native when loaded
  - Docs: `docs/native.md`

- Phase 4 runtime protection & RASP
  - Detectors: anti-debug, anti-tamper, anti-hook, root, emulator, device security, RASP
  - `ThreatEngine` + `DetectorRegistry` with config-gated enablement
  - Monitoring loop updates threat list; clipboard auto-clear on monitor
  - `SecureStorage` (EncryptedSharedPreferences + EncryptedFile)
  - `SslPinning` / `SslPinningConfig` hostname verifier helpers
  - `ScreenProtection` (FLAG_SECURE, overlays, accessibility, tapjacking)
  - `ClipboardProtection`
  - `PlayIntegrityClient` token request + verdict → threats helper
  - Extended `AndroidShield` API (`protectScreen`, `secureStorage`, `sslHostnameVerifier`, …)
  - Docs: `docs/runtime.md`

- Phase 3 core library expansion (API level 2)
  - `ShieldCipher` façade (AES-GCM + ChaCha20-Poly1305)
  - `ChaCha20Cipher`, `EncryptedPayload`, `CryptoPolicy`, `StringEncryptionPolicy`
  - `ConstantEncryption` for Int/Long/Float/Double/Boolean/String
  - `ResourcePayloadCodec` (AS1 sealed resource format)
  - `DigestUtils`, `IntegrityVerifier`, `IntegrityMetadataCodec`
  - `ScoringPolicy` (DEFAULT / STRICT) for `SecurityReportBuilder`
  - `ShieldConfig.Builder`, `ShieldConfigCodec`, feature flag map
  - Runtime `ShieldResourceDecryptor`
  - Plugin now reuses core string policy + AS1 codec
- Docs: `docs/core.md`

- Phase 2 Gradle plugin implementation (`com.androidshield.gradle`)
  - AGP 8+ ASM instrumentation (`ShieldAsmFactory`)
  - String encryption (AES-GCM) rewriting `LDC` → `ShieldStringDecryptor.decrypt`
  - Metadata strip, dead-code insertion, opaque predicates, lightweight CFF
  - Per-build crypto material store + scrambled `BuildShieldSecrets` generator
  - Resource/asset encryption task (`AS1` container)
  - Integrity metadata + build fingerprint generation
  - R8 rule generation, native config JSON, security report, release validation
  - Mapping protection task
- Core crypto: `AesGcmCipher`, `KeyScrambler`, `IntegrityMetadata`
- Runtime decryptor façade: `ShieldStringDecryptor` / `BuildSecrets`
- Plugin unit tests for string transform and R8 rules
- Docs: `docs/gradle-plugin.md`

### Added (Phase 1)

- Multi-module Gradle Kotlin DSL scaffold
- Modules: annotations, core, runtime, native, plugin, cli, testing, sample-app, benchmark
- Convention plugins for Android library/app, JVM library, quality (Detekt/Ktlint), publishing
- Domain models: `Threat`, `Severity`, `SecurityReport`, `ShieldConfig`
- Public API façade `AndroidShield` (stub detectors)
- Native JNI stubs (`libandroidshield`) and separate native AAR
- CLI stub (`version`, `verify`, `report`)
- GitHub Actions CI workflow
- Initial documentation set under `docs/`

## [0.1.0-SNAPSHOT] - 2026-07-29

- Initial project structure (pre-release scaffold)
