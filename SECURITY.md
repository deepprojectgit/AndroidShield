# Security Design

## Goals

- Raise the cost of reverse engineering and runtime compromise
- Provide auditable `Threat` / `SecurityReport` outputs for enterprise policy
- Keep consumer integration simple (`AndroidShield` + Gradle DSL + CLI)

## Non-goals (explicit)

- Perfect undetectability (adversarial arms race)
- Guarantees against a determined attacker with physical device control
- Copying proprietary commercial protectors

## Threat categories

| Category | Plane | Implementation |
|----------|-------|----------------|
| Debugger attachment | Runtime + Native | JDWP, TracerPid, ptrace, timing |
| Tampering / repackaging | Build metadata + Runtime | Integrity JSON, DEX markers, signature checks |
| Hooking frameworks | Runtime + Native | Frida / Xposed artifacts, maps, threads |
| Root / privileged env | Runtime | Multi-signal heuristics |
| Emulators | Runtime | Build props / files / sensors |
| Device security posture | Runtime | Dev options, USB debugging, OEM unlock, VPN/proxy hints |
| Dynamic code / RASP | Runtime | Suspicious loaders / maps signals |
| Network MITM | Runtime | Hostname verifier helpers (pinning configs) |
| UI / overlay abuse | Runtime | FLAG_SECURE, tapjacking guards, overlay signals |
| Secrets at rest | Runtime | Keystore-backed `SecureStorage` |
| Plaintext strings / assets | Build-time | AES-GCM string rewrite, AS1 resource containers |

## Trust boundaries

- Host app process is untrusted once compromised; native checks add friction, not absolute trust
- Integrity metadata generated at build time should be verified against installed content
- Decryption keys are per-build and scrambled; native unscramble prefers JNI when loaded

## Fail policy

Default: **report-only**. Hosts may escalate (kill, logout, degrade features) via their own policy on `Threat` severity.

CLI CI gates (`android-shield-cli verify`) exit non-zero on insecure posture for pipelines — that is a **build/CI** policy, not an in-process crash policy.

## Cryptography

- AES-GCM (primary) and ChaCha20-Poly1305 for payloads
- Per-build random material via plugin `CryptoMaterialStore`
- Android Keystore for `SecureStorage`
- Native AES-GCM decrypt bridge delegates AEAD to core `AesGcmCipher`

## Disclosure

This framework is intended for legitimate application hardening. Do not use it to conceal malware.
