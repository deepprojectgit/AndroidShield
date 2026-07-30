#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> AndroidShield smoke build"
./gradlew :android-shield-core:test \
  :android-shield-annotations:build \
  :android-shield-cli:build \
  :android-shield-plugin:build \
  :android-shield-runtime:assembleDebug \
  :sample-app:assembleDebug \
  --stacktrace

echo "==> OK"
