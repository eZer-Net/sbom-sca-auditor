#!/bin/sh
set -eu

if [ ! -f /etc/os-release ] || ! grep -Eqi '(^ID=(debian|ubuntu)$|^ID_LIKE=.*debian)' /etc/os-release; then
  echo "ERROR: this installer supports Debian/Ubuntu"
  exit 1
fi

if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else echo "ERROR: root privileges or sudo are required"; exit 1; fi

$SUDO apt-get update
$SUDO apt-get install -y \
  python3 python3-venv pipx nodejs npm wget curl gnupg ca-certificates git \
  default-jdk-headless gradle maven golang-go cmake ninja-build build-essential zip unzip tar

if ! command -v trivy >/dev/null 2>&1; then
  TMP_KEY="$(mktemp)"
  wget -qO "$TMP_KEY" https://aquasecurity.github.io/trivy-repo/deb/public.key
  $SUDO gpg --dearmor --yes --output /usr/share/keyrings/trivy.gpg "$TMP_KEY"
  rm -f "$TMP_KEY"
  echo 'deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main' | $SUDO tee /etc/apt/sources.list.d/trivy.list >/dev/null
  $SUDO apt-get update
  $SUDO apt-get install -y trivy
fi

if ! command -v dotnet >/dev/null 2>&1 && [ ! -x "$HOME/.dotnet/dotnet" ]; then
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  sh /tmp/dotnet-install.sh --channel 8.0 --install-dir "$HOME/.dotnet"
  rm -f /tmp/dotnet-install.sh
fi

if ! command -v conan >/dev/null 2>&1; then
  pipx install conan
fi

if ! command -v vcpkg >/dev/null 2>&1; then
  VCPKG_HOME="$HOME/.local/share/vcpkg"
  mkdir -p "$HOME/.local/bin" "$HOME/.local/share"
  if [ ! -d "$VCPKG_HOME/.git" ]; then
    git clone --depth 1 https://github.com/microsoft/vcpkg.git "$VCPKG_HOME"
  fi
  "$VCPKG_HOME/bootstrap-vcpkg.sh" -disableMetrics
  ln -sf "$VCPKG_HOME/vcpkg" "$HOME/.local/bin/vcpkg"
fi

HERE="$(CDPATH= cd -P -- "$(dirname -- "$0")/.." && pwd)"
if [ -w /usr/local/bin ]; then
  ln -sf "$HERE/sbom-sca-auditor" /usr/local/bin/sbom-sca-auditor
  DEST="/usr/local/bin/sbom-sca-auditor"
elif [ -n "$SUDO" ]; then
  $SUDO ln -sf "$HERE/sbom-sca-auditor" /usr/local/bin/sbom-sca-auditor
  DEST="/usr/local/bin/sbom-sca-auditor"
else
  mkdir -p "$HOME/.local/bin"
  ln -sf "$HERE/sbom-sca-auditor" "$HOME/.local/bin/sbom-sca-auditor"
  DEST="$HOME/.local/bin/sbom-sca-auditor"
fi

echo "Installed: $DEST"
echo 'If needed, add $HOME/.local/bin and $HOME/.dotnet to PATH.'
echo "Run: sbom-sca-auditor /path/to/project"
