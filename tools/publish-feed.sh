#!/usr/bin/env bash
# Build, sign, and stage the daily feed clients auto-pull.
#
# Run this on the OFFLINE signer (the only machine with the private key) after
# refreshing intel (abuse.ch ingestion + the analysis worker). It:
#   1. exports the current intel store as an unsigned feed (version = now),
#   2. signs it with the offline Ed25519 key (embeds the signature),
#   3. stages dist-feed/aether.json -> upload that to your update.url.
#
# Clients verify the signature + reject rollbacks (apply_signed), so the file is
# safe to serve from any CDN, even over plain HTTP.
set -euo pipefail
cd "$(dirname "$0")/.."

KEY="${AETHER_KEY:-assets/keys/feed_private.key}"
STORE="${AETHER_STORE:-assets/models/intel.json}"
AETHER="${AETHER_BIN:-target/release/aether}"
OUT="dist-feed"

[ -f "$KEY" ]   || { echo "private key not found: $KEY (keep it offline)"; exit 1; }
[ -x "$AETHER" ] || AETHER="target/debug/aether"
[ -x "$AETHER" ] || { echo "build first: cargo build --release -p aether-cli"; exit 1; }

mkdir -p "$OUT"
# Reuse the run's version if set (so the full file's version == the store version
# == the IOC stamps, which the server's delta endpoint relies on).
VER="${FEED_VERSION:-$(date +%s)}"

echo ">> exporting feed v$VER from $STORE"
"$AETHER" intel export-feed --store "$STORE" -o "$OUT/aether.unsigned.json" --feed-version "$VER"

echo ">> signing (offline key)"
"$AETHER" feedsign "$OUT/aether.unsigned.json" "$OUT/aether.json" --key "$KEY"

echo ">> verifying our own output"
"$AETHER" feedverify "$OUT/aether.json"

echo ">> publish this file to your update.url:"
ls -lh "$OUT/aether.json"
