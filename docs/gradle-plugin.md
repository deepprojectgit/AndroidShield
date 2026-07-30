# Gradle Plugin Guide

Plugin id: `io.github.deepprojectgit.androidshield`

> Maven Central requires the plugin id (marker group) to sit under your verified namespace  
> (`io.github.deepprojectgit…`). The old id `com.androidshield.gradle` is not allowed on Central.

## Apply

```kotlin
plugins {
    id("io.github.deepprojectgit.androidshield") version "0.1.0"
}

androidShield {
    enabled.set(true)
    stringEncryption.set(true)
    resourceEncryption.set(true)
    stripMetadata.set(true)
    deadCodeInsertion.set(true)
    opaquePredicates.set(true)
    controlFlowFlattening.set(false)
    obfuscationIntensity.set(2)
    protectPackages.add("com.example.app")
    encryptAssetPatterns.add("secrets/**")
    mappingProtection.set(true)
    releaseValidation.set(true)
    failOnValidationError.set(true)
}
```

In this monorepo the plugin is built as `:android-shield-plugin`. Consuming apps apply it after publish/`mavenLocal()`. In-repo verification uses `:android-shield-plugin:test` (ASM transform + R8 rule unit tests).

## What the plugin generates

| Task / output | Purpose |
|---------------|---------|
| ASM instrumentation | String encryption, metadata strip, dead code, opaque predicates, CFF (intensity 3) |
| `generateShieldArtifacts*` | Integrity JSON, fingerprint, R8 rules, native config, `BuildShieldSecrets` |
| `encryptShieldResources*` | AES-GCM encrypt matching assets (`AS1` container) |
| `generateShieldReport*` | Build-time security report JSON |
| `protectShieldMapping*` | Scramble/store mapping artifacts |

Artifacts land under `build/androidshield/<variant>/`.

## Runtime decrypt

Encrypted string literals call:

`com.androidshield.runtime.crypto.ShieldStringDecryptor.decrypt(byte[], byte[])`

Keys are installed through generated `BuildShieldSecrets` → `BuildSecrets.install`.
