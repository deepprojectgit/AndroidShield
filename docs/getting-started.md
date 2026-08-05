# Getting Started

## Requirements

- JDK 17+
- Android SDK (compileSdk 35)
- Android NDK + CMake 3.22+ (for `android-shield-native`)
- AGP 8.7+ / Kotlin 2.0+

## Build this repository

```bash
./gradlew :android-shield-core:build \
  :android-shield-runtime:assembleDebug \
  :android-shield-native:assembleDebug \
  :android-shield-plugin:build \
  :android-shield-cli:build \
  :sample-app:assembleDebug
```

Smoke the CLI:

```bash
./gradlew :android-shield-cli:installDist
./android-shield-cli/build/install/android-shield-cli/bin/android-shield-cli version
```

## Add AndroidShield to your app

### 1. Dependencies

After publishing to Maven Central (or `mavenLocal()`):

```kotlin
// settings.gradle.kts — google() + mavenCentral() in pluginManagement / dependencyResolutionManagement

// app/build.gradle.kts
plugins {
    id("io.github.deepprojectgit.androidshield") version "0.1.1"
}

dependencies {
    implementation("io.github.deepprojectgit.androidshield:android-shield-runtime:0.1.1")
}
```

See [publishing.md](publishing.md) for Central credentials and keeping the GitHub repo **public**.

### 2. Gradle DSL

```kotlin
androidShield {
    enabled.set(true)
    antiDebug.set(true)
    antiTamper.set(true)
    stringEncryption.set(true)
    resourceEncryption.set(true)
    nativeProtection.set(true)
    protectPackages.add("com.example.app")
}
```

See [gradle-plugin.md](gradle-plugin.md) for the full flag set.

### 3. Initialize at process start

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        AndroidShield.initialize(
            this,
            ShieldConfig.Builder()
                .antiDebug(true)
                .antiTamper(true)
                .nativeProtection(true)
                .playIntegrity(false)
                .build(),
        )
    }
}
```

### 4. Verify or monitor

```kotlin
val report = AndroidShield.verify()
if (!report.secure) {
    // Host policy: logout, degrade features, telemetry — AndroidShield is report-only by default
}

AndroidShield.startMonitoring()
```

## Next

- [Usage guide](usage.md) — detectors, secure APIs, reports
- [Sample app](sample-app.md) — runnable dashboard
- [CLI](cli.md) — CI APK gates
- [Security design](security-design.md) — threat model & fail policy
