# Contributing

Thanks for contributing to AndroidShield.

## Rules

1. Use **Conventional Commits** (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).
2. Follow **Semantic Versioning** for releases.
3. Do not break public APIs without discussion / approval.
4. Keep modules building before expanding scope.
5. Prefer original implementations — do not paste proprietary protector code.
6. Add KDoc for every new public API.
7. Update README/CHANGELOG when a module milestone completes.

## Setup

- JDK 17
- Android SDK 35 + NDK + CMake
- Clone and run `./gradlew test`

## PR checklist

- [ ] Builds locally
- [ ] Tests added/updated
- [ ] Public API documented
- [ ] No secrets committed
- [ ] Phase scope respected (incremental delivery)

## Documentation map

Keep [docs/README.md](README.md) and the root README documentation section in sync when adding guides.
Update [CHANGELOG.md](../CHANGELOG.md) for user-visible milestones.
