#!/usr/bin/env bash
# Builds Deskwarden.app into build/.
#
# Signs with DESKWARDEN_SIGN_IDENTITY, else the first Developer ID or Apple
# Development identity in the keychain, else ad hoc. A stable identity matters:
# the login keychain ties the socket keys to the app's signature, so an ad hoc
# build asks for keychain access again after every rebuild.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-release}"
APP="$ROOT/build/Deskwarden.app"

cd "$ROOT"
swift build --configuration "$CONFIGURATION" --product Deskwarden
BIN_DIR="$(swift build --configuration "$CONFIGURATION" --show-bin-path)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/Deskwarden" "$APP/Contents/MacOS/Deskwarden"
cp "$ROOT/Resources/Info.plist" "$APP/Contents/Info.plist"

IDENTITY="${DESKWARDEN_SIGN_IDENTITY:-}"
if [[ -z "$IDENTITY" ]]; then
  IDENTITY="$(security find-identity -v -p codesigning \
    | grep -E '"(Developer ID Application|Apple Development):' \
    | head -1 | sed -E 's/.*"(.*)"/\1/' || true)"
fi
if [[ -n "$IDENTITY" ]]; then
  codesign --force --options runtime --sign "$IDENTITY" "$APP"
else
  echo "No signing identity found; signing ad hoc." >&2
  codesign --force --sign - "$APP"
fi
codesign --verify --strict "$APP"

echo "Built $APP (signed by ${IDENTITY:-ad hoc})"
