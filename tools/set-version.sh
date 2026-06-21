#!/usr/bin/env bash
# Sync every product version string to $1 so the app, CLI and installers always
# match the git tag. Called by the release workflow with the tag (minus the "v").
# Idempotent; safe to run locally too. Works with both GNU and BSD/macOS sed.
set -euo pipefail
V="${1:?usage: set-version.sh <version>}"

sed_i() { sed -i.bak "$1" "$2" && rm -f "$2.bak"; }

# Workspace version -> every crate using `version.workspace = true` (incl. CLI).
sed_i "s/^version = \"[^\"]*\"/version = \"$V\"/" Cargo.toml
# The desktop crate carries its own version (not workspace-inherited).
sed_i "s/^version = \"[^\"]*\"/version = \"$V\"/" desktop/src-tauri/Cargo.toml
# Tauri reads the app/window version from its config.
sed_i "s/\"version\": \"[^\"]*\"/\"version\": \"$V\"/" desktop/src-tauri/tauri.conf.json

echo "version synced to $V"
