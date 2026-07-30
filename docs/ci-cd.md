# CI/CD Guide

## Workflows

| Workflow | File | Purpose |
|----------|------|---------|
| CI/CD | `.github/workflows/ci-cd.yml` | Build + test on PR/push; publish to Maven Central on `main` (after green build) or `workflow_dispatch` |

## Local parity

```bash
./gradlew :android-shield-annotations:build \
  :android-shield-core:build \
  :android-shield-testing:build \
  :android-shield-cli:build \
  :android-shield-plugin:build

./gradlew :android-shield-native:assembleDebug \
  :android-shield-runtime:assembleDebug \
  :sample-app:assembleDebug

# CLI offline verify (CI)
./gradlew :android-shield-cli:installDist
./android-shield-cli/build/install/android-shield-cli/bin/android-shield-cli \
  verify sample-app/build/outputs/apk/debug/sample-app-debug.apk --json
```

## Quality gates

- Detekt (`config/detekt/detekt.yml`)
- Ktlint (via `androidshield.quality`)

## Release flow

1. Keep the GitHub repository **public**
2. Conventional Commits on `main`
3. Set `androidshield.version` (SemVer; use `-SNAPSHOT` while iterating)
4. Update `CHANGELOG.md`
5. Push to `main` → **CI/CD** workflow builds, then publishes to Maven Central
6. Optional: tag `vX.Y.Z` for GitHub Releases / release notes; or run **CI/CD** via `workflow_dispatch`

## Required secrets (Maven Central)

| Secret | Purpose |
|--------|---------|
| `MAVEN_CENTRAL_USERNAME` | Central Portal user token name |
| `MAVEN_CENTRAL_PASSWORD` | Central Portal user token password |
| `SIGNING_KEY` | ASCII-armored GPG private key |
| `SIGNING_KEY_ID` | GPG key id (recommended) |
| `SIGNING_PASSWORD` | GPG passphrase |

See [publishing.md](publishing.md) for namespace, GPG, and public-repo setup.
