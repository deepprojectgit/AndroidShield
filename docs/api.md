# API Documentation

## Runtime

### `AndroidShield`

| Method | Description |
|--------|-------------|
| `initialize(context, config = ShieldConfig())` | One-time setup |
| `verify(): SecurityReport` | On-demand evaluation |
| `startMonitoring()` / `stopMonitoring()` | RASP loop |
| `getThreats(): List<Threat>` | Last findings |
| `generateReport(): SecurityReport` | Aggregate report |
| `isCompromised(): Boolean` | `!report.secure` |
| `isInitialized()` / `isMonitoring()` | Lifecycle gates |
| `config(): ShieldConfig` | Active runtime config |

### Crypto

- `ShieldStringDecryptor.decrypt(cipherText, iv)` — used by plugin-rewritten bytecode
- `ShieldResourceDecryptor.open(sealed)` — AS1 resource decrypt
- `BuildSecrets.install(scrambledKey, seed)` — installed by generated `BuildShieldSecrets`

### Runtime extras

- `protectScreen(activity)`, `secureStorage()`, `clipboard()`, `sslHostnameVerifier(...)`, `playIntegrity(...)`
- See [runtime.md](runtime.md) and [usage.md](usage.md)

### Models (`android-shield-core`)

- `Threat(id, title, severity, description, recommendation)`
- `Severity` — `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL`
- `SecurityReport(secure, score, threats)`
- `ShieldConfig` — feature flags (+ builder / JSON codec)
- `IntegrityMetadata` — build fingerprint + digests
- `ScoringPolicy` — DEFAULT / STRICT report scoring
- Crypto: `ShieldCipher`, `ConstantEncryption`, `ResourcePayloadCodec`
- Integrity: `IntegrityVerifier`, `DigestUtils`

See [core.md](core.md) for details.

### Report JSON shape

```json
{
  "secure": true,
  "score": 98,
  "threats": []
}
```

## Annotations

- `@ShieldProtect(intensity = 1)`
- `@ShieldEncrypt(algorithm = EncryptAlgorithm.AES_GCM)`

## Gradle DSL

Plugin id: `io.github.deepprojectgit.androidshield` — see [gradle-plugin.md](gradle-plugin.md).

```kotlin
androidShield {
    antiDebug.set(true)
    stringEncryption.set(true)
    resourceEncryption.set(true)
    obfuscationIntensity.set(2)
    protectPackages.add("com.example.app")
}
```

## CLI

`inspect` · `verify` · `report` · `version` — see [cli.md](cli.md).

## Native

`NativeShield.isAvailable()`, `evaluate()`, `nativeSelfCheck()`, checksums, unscramble, AES-GCM decrypt.

See [native.md](native.md).
