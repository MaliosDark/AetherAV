#!/usr/bin/env bash
# Build a TLSH fuzzy-variant database from a directory of malware samples.
#   ./tools/build-tlsh.sh <samples_dir> [threat_label] [out_db]
# Default out: assets/signatures/tlsh.db (what the engine loads).
#
# At scale, the best source of malware TLSH digests is MalwareBazaar's full
# export (it lists a `tlsh` per sample) - parse that into the same format.
set -euo pipefail
cd "$(dirname "$0")/.."
AETHER="${AETHER_BIN:-$(ls target/release/aether 2>/dev/null || ls target/debug/aether 2>/dev/null || true)}"
[ -n "$AETHER" ] || { echo "build first: cargo build --release -p aether-cli"; exit 1; }
DIR="${1:?usage: build-tlsh.sh <samples_dir> [threat] [out_db]}"
THREAT="${2:-Malware}"
OUT="${3:-assets/signatures/tlsh.db}"
mkdir -p "$(dirname "$OUT")"
tmp="$(mktemp)"
count=0
while IFS= read -r f; do
  h="$("$AETHER" tlsh "$f" 2>/dev/null | awk '{print $1}' || true)"
  if [ -n "$h" ]; then printf '%s  %s\n' "$h" "$THREAT" >> "$tmp"; count=$((count+1)); fi
done < <(find "$DIR" -type f)
sort -u "$tmp" > "$OUT"; rm -f "$tmp"
echo "wrote $(wc -l < "$OUT") TLSH entries to $OUT"
