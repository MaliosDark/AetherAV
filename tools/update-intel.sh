#!/usr/bin/env bash
# Download free, defensive threat-intel feeds (hashes & IOCs - never malware
# binaries) from abuse.ch and fold them into AetherAV's signature database.
#
#   ThreatFox   - IOCs (sha256/md5/domain/ip/url) tagged with the malware family
#   MalwareBazaar - recent malware SHA-256 hashes
#
# Output: assets/signatures/hashes.db is regenerated as  base (EICAR) + intel.
# The scanner then detects these real samples by hash on the next run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
AETHER="${AETHER_BIN:-./target/release/aether}"
[ -x "$AETHER" ] || AETHER="./target/debug/aether"
STORE="assets/models/intel.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

VER="${FEED_VERSION:-$(date +%s)}"   # epoch; one version per refresh run (delta-consistent)
KEY="${ABUSE_CH_AUTH_KEY:-}"            # free key from https://auth.abuse.ch/
FULL="${ABUSE_CH_FULL:-}"              # set =1 (with a key) to pull the FULL dumps (millions)
HDR=(); [ -n "$KEY" ] && HDR=(-H "Auth-Key: $KEY")

dl(){ curl -fsS --max-time 180 -o "$2" "$1" || { rm -f -- "$2"; return 1; }; }
# Download $1 -> if it's a zip, extract its first member -> $2.
dlx(){ local z="$TMP/dl.zip"; curl -fsS --max-time 180 "${HDR[@]}" -o "$z" "$1"; if [ -s "$z" ]; then
         if head -c2 "$z" | grep -q PK; then 7z e -y -bso0 -bsp0 -o"$TMP/x" "$z" >/dev/null 2>&1; mv "$TMP"/x/* "$2" 2>/dev/null; rm -rf "$TMP/x"; else mv "$z" "$2"; fi
       fi; }
imp(){
  if [ -s "$1" ]; then
    "$AETHER" intel import "$1" --format "$2" --store "$STORE" --feed-version "$VER" "${@:3}"
  fi
}

if [ -n "$KEY" ] && [ -n "$FULL" ]; then
  echo "▸ downloading abuse.ch FULL dumps (Auth-Key set)…"
  dlx "https://threatfox.abuse.ch/export/csv/full/" "$TMP/threatfox.csv"
  dlx "https://bazaar.abuse.ch/export/csv/full/"    "$TMP/bazaar.csv"
  dlx "https://urlhaus.abuse.ch/downloads/csv/"     "$TMP/urlhaus.csv"
  dl  "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" "$TMP/feodo.csv"
  echo "▸ importing FULL dumps into $STORE …"
  imp "$TMP/threatfox.csv" threatfox
  imp "$TMP/bazaar.csv"    malwarebazaar
  imp "$TMP/urlhaus.csv"   urlhaus
  imp "$TMP/feodo.csv"     feodo
else
  if [ -n "$KEY" ]; then
    echo "▸ querying MalwareBazaar for recent SHA-256 signatures and family labels…"
    python3 tools/refresh-malwarebazaar.py > "$TMP/bazaar.csv"
    imp "$TMP/bazaar.csv" malwarebazaar

    echo "▸ querying ThreatFox for recent indicators…"
    curl -fsS --max-time 45 "${HDR[@]}" -H 'Content-Type: application/json' \
      --data '{"query":"get_iocs","days":2}' https://threatfox-api.abuse.ch/api/v1/ \
      -o "$TMP/threatfox.json"
    imp "$TMP/threatfox.json" threatfox-json
  else
    echo "  MalwareBazaar and ThreatFox require ABUSE_CH_AUTH_KEY; skipping them" >&2
  fi
  if dl "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" "$TMP/feodo.csv"; then
    imp "$TMP/feodo.csv" feodo
  else
    echo "  (warning: Feodo Tracker could not be reached)" >&2
  fi
fi

# Optional: fetch a public YARA ruleset into assets/rules (downloaded on YOUR
# machine; not bundled). Set YARA_RULES_GIT to a repo of *.yar files, e.g.:
#   YARA_RULES_GIT=https://github.com/Yara-Rules/rules ./tools/update-intel.sh
if [ -n "${YARA_RULES_GIT:-}" ] && command -v git >/dev/null; then
  echo "▸ fetching YARA rules from $YARA_RULES_GIT …"
  git clone --depth 1 "$YARA_RULES_GIT" "$TMP/yara" 2>/dev/null \
    && find "$TMP/yara" -iname '*.yar' -o -iname '*.yara' | while read -r r; do
         cp "$r" "assets/rules/$(basename "$(dirname "$r")")_$(basename "$r")" 2>/dev/null || true
       done \
    && echo "  YARA rules copied into assets/rules (fault-tolerant loader skips any that don't compile)"
fi

echo "▸ exporting hash signatures…"
"$AETHER" intel export-hashdb --store "$STORE" -o "$TMP/intel.db"

# Keep the bundled base (EICAR test entry) and append the intel hashes, deduped.
BASE="assets/signatures/hashes.db"
{ cat "$TMP/intel.db"; grep -v '^[[:space:]]*$' "$BASE" 2>/dev/null || true; } \
  | LC_ALL=C sort -s -u -k1,1 > "$BASE.new"
mv "$BASE.new" "$BASE"

echo "✓ signature DB updated: $(grep -cvE '^\s*(#|$)' "$BASE") signatures in $BASE"
