#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then echo "ERROR: this installer is for macOS"; exit 1; fi
if ! command -v brew >/dev/null 2>&1; then echo "ERROR: Homebrew is required: https://brew.sh"; exit 1; fi

for pkg in python node trivy openjdk gradle maven go conan cmake ninja vcpkg; do
  echo "Checking $pkg..."
  brew list "$pkg" >/dev/null 2>&1 || brew install "$pkg"
done

if ! command -v dotnet >/dev/null 2>&1; then
  brew install --cask dotnet-sdk
fi

HERE="$(CDPATH= cd -P -- "$(dirname -- "$0")/.." && pwd)"
BREW_BIN="$(brew --prefix)/bin"
ln -sf "$HERE/sbom-sca-auditor" "$BREW_BIN/sbom-sca-auditor"
echo "Installed: $BREW_BIN/sbom-sca-auditor"
echo "Run: sbom-sca-auditor /path/to/project"
