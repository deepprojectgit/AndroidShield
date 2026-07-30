# Publishing Guide

## Model

**Public GitHub repository + Maven Central**

- Repo must stay **public** for free OSS Central publishing and `io.github.*` namespace verification
- Consumers resolve via `mavenCentral()` — **no credentials**

## Coordinates

- **Group:** `io.github.deepprojectgit.androidshield`
- **Version:** `androidshield.version` in `gradle.properties` (SemVer)
- **Repository:** Maven Central (Sonatype Central Portal)

## Artifacts

| ArtifactId | Type |
|------------|------|
| `android-shield-annotations` | JAR |
| `android-shield-core` | JAR |
| `android-shield-runtime` | AAR |
| `android-shield-native` | AAR |
| `android-shield-plugin` | Gradle plugin marker + JAR |
| `android-shield-cli` | JAR |

## Consumer setup (no login)

```kotlin
repositories {
    google()
    mavenCentral()
}

dependencies {
    implementation("io.github.deepprojectgit.androidshield:android-shield-runtime:0.1.0-SNAPSHOT")
}
```

SNAPSHOT builds come from the Central Portal snapshot repository (Gradle/Maven Central tooling usually resolves them when the version ends in `-SNAPSHOT`).

## Local publish

```bash
./gradlew publishToMavenLocal
```

## Maven Central (automated)

Convention plugin `androidshield.publishing` uses [vanniktech maven-publish](https://github.com/vanniktech/gradle-maven-publish-plugin):

- Central Portal (`SonatypeHost.CENTRAL_PORTAL`)
- GPG signing (`signAllPublications`)
- Automatic release after successful validation (`automaticRelease = true`)

### GitHub repository visibility

1. Open https://github.com/deepprojectgit/AndroidShield  
2. **Settings → General → Danger Zone → Change repository visibility → Make public**

Keep it public while publishing under `io.github.deepprojectgit…`.

### Namespace + portal

1. Create / sign in: https://central.sonatype.com/  
2. Register namespace `io.github.deepprojectgit` (GitHub verification against this **public** repo)  
3. Generate a **user token**: https://central.sonatype.com/account  

### Required repository secrets

| Secret | Value |
|--------|--------|
| `MAVEN_CENTRAL_USERNAME` | Central Portal **user token** name |
| `MAVEN_CENTRAL_PASSWORD` | Central Portal **user token** password |
| `SIGNING_KEY` | ASCII-armored private GPG key (`gpg --export-secret-keys --armor <KEY_ID>`) |
| `SIGNING_KEY_ID` | Key id (optional but recommended) |
| `SIGNING_PASSWORD` | GPG passphrase (omit / empty if none) |

Publish the **public** GPG key to a keyserver (e.g. keys.openpgp.org) before the first release.

### GitHub Actions

Workflow: [`.github/workflows/ci-cd.yml`](../.github/workflows/ci-cd.yml)

Jobs:

1. **Build & Test** — always on push/PR to `main`/`develop`
2. **Publish to Maven Central** — only after a green build when pushing to `main`, or via `workflow_dispatch`

Triggers:

- Push / PR to `main` or `develop`
- Manual `workflow_dispatch` (runs build, then publish)

### Local / one-off publish

```bash
export ORG_GRADLE_PROJECT_mavenCentralUsername=...
export ORG_GRADLE_PROJECT_mavenCentralPassword=...
export ORG_GRADLE_PROJECT_signingInMemoryKey=...
export ORG_GRADLE_PROJECT_signingInMemoryKeyId=...
export ORG_GRADLE_PROJECT_signingInMemoryKeyPassword=...

./gradlew publishToMavenCentral --no-configuration-cache
```

- Version ending in `-SNAPSHOT` → Central Portal **snapshots** (available quickly)
- Release version (no `-SNAPSHOT`) → validated + auto-published (may take 10–30 minutes on Central)

## Release checklist

1. Confirm GitHub repo is **public**
2. Bump `androidshield.version` in `gradle.properties` (drop `-SNAPSHOT` for a release)
3. Update `CHANGELOG.md`
4. Merge to `main` (CI/CD builds then publishes) or run **CI/CD** manually
5. After a release, bump to the next `X.Y.Z-SNAPSHOT`

## Plugin Portal (optional)

Publish `com.androidshield.gradle` via the Gradle Plugin Portal separately if you want the short `plugins { id(...) version }` form without extra `pluginManagement` repos.
