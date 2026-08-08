# Publishing Guide

## Model

**Public GitHub repository + Maven Central**

- Repo must stay **public** for free OSS Central publishing and `io.github.*` namespace verification
- Consumers resolve via `mavenCentral()` — **no credentials**

## Coordinates

- **Group:** `io.github.deepprojectgit.androidshield`
- **Version:** `androidshield.version` in `gradle.properties` (SemVer release — **no `-SNAPSHOT`**)
- **Repository:** Maven Central (Sonatype Central Portal)

> Central Portal does **not** accept `*-SNAPSHOT` uploads. Use `0.1.2`, `0.1.3`, … for publish.

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
    implementation("io.github.deepprojectgit.androidshield:android-shield-runtime:0.1.2")
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
| `SIGNING_KEY` | Full ASCII-armored **private** key including `BEGIN/END PGP PRIVATE KEY BLOCK` |
| `SIGNING_KEY_ID` | Prefer **8 hex chars** (last 8 of the long id), e.g. `50102E96`. Avoid 16-char ids that start with `8`–`F` — Gradle can reject them |
| `SIGNING_PASSWORD` | GPG passphrase (omit / empty if none) |

**Never paste a private key into chat, Issues, or PRs.** Only into GitHub Secrets.

#### Easiest path (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/export-signing-secrets.ps1
```

The script auto-finds `gpg.exe` (Git for Windows or Gpg4win). If it still fails, use Git Bash instead.

The script writes files under `build/signing-export/` and opens an upload checklist:

1. Copy `SIGNING_KEY.asc` → GitHub secret `SIGNING_KEY`
2. Copy `SIGNING_KEY_ID.txt` → GitHub secret `SIGNING_KEY_ID`
3. Set `SIGNING_PASSWORD` to your passphrase
4. Delete `build/signing-export/` when finished

#### Manual commands

```powershell
gpg --list-secret-keys --keyid-format LONG
# SIGNING_KEY_ID = value after rsa4096/  (16 hex chars)

gpg --export-secret-keys --armor YOUR_KEY_ID > signing-key.asc
# Open signing-key.asc locally and paste into SIGNING_KEY only

gpg --keyserver keys.openpgp.org --send-keys YOUR_KEY_ID
```

**Common mistake:** putting the entire private key into `SIGNING_KEY_ID`. That must stay in `SIGNING_KEY` only.

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
2. Bump `androidshield.version` in `gradle.properties` to a **release** version (no `-SNAPSHOT`; Central Portal rejects snapshots)
3. Update `CHANGELOG.md`
4. Merge to `main` (CI/CD builds then publishes) or run **CI/CD** manually
5. After a release, optionally bump to `X.Y.Z-SNAPSHOT` locally for continued development (publish will stay skipped until the next release version)

## Plugin Portal (optional)

Publish `io.github.deepprojectgit.androidshield` via the Gradle Plugin Portal separately if you want the short `plugins { id(...) version }` form without extra `pluginManagement` repos.
