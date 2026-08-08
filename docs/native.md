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

Requires **NDK 28.2.13676358** + CMake 3.22+. ABIs: `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`.

`libandroidshield.so` is linked for **16 KB page size** (Android 15 / Play):

- CMake: `-Wl,-z,max-page-size=16384` and `-Wl,-z,common-page-size=16384`
- NDK r28+: 16 KB page size by default; `-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON`
- STL: `c++_static` (no extra `libc++_shared.so`)

Verify after a native build:

```bash
./gradlew :android-shield-native:assembleRelease
python3 scripts/check-elf-16kb-alignment.py
```

Use AndroidShield **0.1.2+** if you enable `nativeProtection`. Older `0.1.1` `.so` files are 4 KB-aligned and trigger Play’s 16 KB warning.
