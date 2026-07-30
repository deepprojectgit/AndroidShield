# CLI Guide

Artifact: `android-shield-cli`  
Main class: `com.androidshield.cli.MainKt`

## Install / run

```bash
./gradlew :android-shield-cli:installDist
./android-shield-cli/build/install/android-shield-cli/bin/android-shield-cli --help
```

Or:

```bash
./gradlew :android-shield-cli:run --args="inspect app-release.apk -v"
```

## Commands

### `version`

Prints CLI + core API level.

### `inspect <file>`

Lists package structure and AndroidShield markers.

```bash
android-shield inspect app.apk -v
android-shield inspect app.apk --json
```

### `verify <file>`

CI gate — exits `1` when the report is insecure, `2` on I/O errors.

```bash
android-shield verify app-release.apk --policy strict --require-integrity --require-native --json
```

### `report <file>`

Writes `SecurityReport` JSON to stdout or `-o report.json`.

```bash
android-shield report app.apk -o build/security-report.json --fail-on-threats
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Secure / success |
| 1 | Insecure under scoring policy |
| 2 | Invalid input / exception |
