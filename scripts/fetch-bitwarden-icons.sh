#!/usr/bin/env bash
# Downloads Bitwarden's own app icon and shield logo into Branding/ for a
# local build. Branding/ is gitignored: Bitwarden's trademark guidelines don't
# allow third-party software to ship its logos, so they stay on this Mac.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENTS_REV="${CLIENTS_REV:-ea6c9e20bc262105dfff0b70002dd3cc72c29e21}"
SOURCE="https://raw.githubusercontent.com/bitwarden/clients/$CLIENTS_REV/apps"

mkdir -p "$ROOT/Branding" "$ROOT/.local"
curl -fsSL "$SOURCE/desktop/resources/icon.icns" -o "$ROOT/Branding/AppIcon.icns"

# The Safari pinned-tab icon is the shield as a vector; its "Identity" path is
# the bare logo without the rounded square behind it.
curl -fsSL "$SOURCE/web/src/images/icons/safari-pinned-tab.svg" -o "$ROOT/.local/bitwarden-shield.svg"
swift "$ROOT/scripts/make-menu-bar-icon.swift" "$ROOT/.local/bitwarden-shield.svg" Identity "$ROOT/Branding/MenuBarIcon.pdf"

echo "Saved to $ROOT/Branding; run scripts/bundle.sh to use them."
