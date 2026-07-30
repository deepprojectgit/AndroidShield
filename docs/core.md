# Core Library Guide

Module: `android-shield-core`  
Maven: `io.github.deepprojectgit.androidshield:android-shield-core`  
API level: `2` (Phase 3)

## Packages

| Package | Responsibility |
|---------|----------------|
| `com.androidshield.core.model` | `Threat`, `Severity`, `SecurityReport` |
| `com.androidshield.core.config` | `ShieldConfig`, builder, JSON codec |
| `com.androidshield.core.crypto` | AES-GCM, ChaCha20-Poly1305, policies, constants, AS1 resources |
| `com.androidshield.core.integrity` | Metadata, digests, verifier |
| `com.androidshield.core.report` | Scoring policy + report builder |

## Crypto

```kotlin
val key = ShieldCipher.generateKey(ShieldAlgorithm.AES_GCM)
val payload = ShieldCipher.encryptUtf8("https://api.example/token", key)
val plain = ShieldCipher.decryptUtf8(payload, key)

val sealed = ResourcePayloadCodec.seal(bytes, key) // AS1 container
val opened = ResourcePayloadCodec.open(sealed, key)

ConstantEncryption.encryptInt(42, key)
StringEncryptionPolicy.DEFAULT.shouldEncrypt("https://…")
```

## Integrity

```kotlin
val expected = IntegrityMetadataCodec.decode(json)
val result = IntegrityVerifier.verify(expected, observed)
if (!result.matches) { /* Critical threats in result.threats */ }
```

## Config & scoring

```kotlin
val config = ShieldConfig.builder()
    .playIntegrity(true)
    .obfuscationIntensity(2)
    .build()

val report = SecurityReportBuilder.fromThreats(threats, ScoringPolicy.STRICT)
```
