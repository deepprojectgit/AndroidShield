# Native Protection Guide (Phase 5)

Module: `android-shield-native` (separate AAR + `libandroidshield.so`)

## JNI API (`NativeShield`)

| Method | Purpose |
|--------|---------|
| `isAvailable()` | `.so` loaded |
| `nativeSelfCheck()` | Packed bitmask (debug\|hook\|memory) |
| `nativeCheckDebugger()` | TracerPid, ptrace, ports, timing |
| `nativeCheckHooks()` | Frida/Xposed maps, threads, files |
| `nativeCheckMemory()` | rwx + suspicious map names |
| `nativeChecksum` / `nativeSha256` | Integrity fingerprints |
| `nativeUnscrambleKey` | Build-key unscramble (mirrors `KeyScrambler`) |
| `nativeDecryptAesGcm` | AES-GCM via core `AesGcmCipher` |

## Runtime wiring

When `ShieldConfig.nativeProtection = true`, `NativeProtectionDetector` maps native flags to `Threat`s.

String decrypt prefers native AES-GCM / unscramble when the library loads.

## Build

Requires NDK + CMake 3.22+. ABIs: `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`.
