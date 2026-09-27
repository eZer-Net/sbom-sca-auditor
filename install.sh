#!/bin/sh
set -eu
HERE="$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)"
case "$(uname -s)" in
  Darwin) exec "$HERE/scripts/install-macos.sh" ;;
  Linux) exec "$HERE/scripts/install-debian.sh" ;;
  *) echo "ERROR: supported installers: macOS and Debian/Ubuntu"; exit 1 ;;
esac
