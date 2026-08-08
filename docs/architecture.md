# Architecture

AndroidShield is organized as a **dual-plane** protection system with Clean Architecture inside the runtime plane.

## Dual plane

| Plane | Modules | Responsibility |
|-------|---------|----------------|
| Build-time | `android-shield-plugin`, annotations | ASM transforms, encryption, integrity metadata, R8 rules, build reports |
| Runtime | `runtime`, `native`, `core` | RASP, detectors, ThreatEngine, secure APIs, JNI checks |

## Dependency graph

```
annotations ──► (compileOnly / API markers)
core ◄── runtime ◄── sample-app
 ▲         ▲
 │         └── native (separate AAR)
 ├── plugin
 └── cli
testing ── used by module tests
```

## Runtime layers

1. **API** — `AndroidShield` façade (stable)
2. **Engine** — `ThreatEngine`, `MonitorScheduler`
3. **Detectors** — anti-debug, anti-tamper, root, hook, emulator, … (Phase 4)
4. **Infrastructure** — Keystore, Play Integrity, SSL pinning, screen/clipboard (Phase 4)
5. **Native bridge** — `NativeShield` JNI (Phase 5)

## DI

Manual `ShieldRuntimeGraph` — no reflection DI, minimal startup cost.

## Packaging decisions

- **Native:** separate `android-shield-native` AAR (chosen)
- **Maven groupId:** `io.github.deepprojectgit.androidshield`
- **Packages:** `com.androidshield.*`
- **CRITICAL default:** report-only; host apps may observe `isCompromised()` / threats and decide policy

## Phase map

All delivery phases (1–8) are complete for `0.1.2`. See root [README](../README.md) status table.
