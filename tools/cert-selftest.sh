#!/usr/bin/env bash
# AetherAV certification self-test.
#
# Produces a reproducible detection/false-positive report (the kind of evidence
# AV-Comparatives / AV-TEST / VirusTotal want) using our own `aether eval`
# harness against a clean corpus and a malware corpus. Safe: the only "malware"
# generated here is the standard EICAR test file (harmless by design).
#
#   ./tools/cert-selftest.sh [clean_dir] [malware_dir]
set -euo pipefail
cd "$(dirname "$0")/.."

AETHER="$(ls target/release/aether 2>/dev/null || ls target/debug/aether 2>/dev/null || true)"
[ -n "$AETHER" ] || { echo "build first: cargo build --release -p aether-cli"; exit 1; }

WORK="$(mktemp -d)"
CLEAN="${1:-$WORK/clean}"
MAL="${2:-$WORK/malware}"
mkdir -p "$CLEAN" "$MAL"

# Clean corpus: a sample of real system binaries (true negatives expected).
if [ "${1:-}" = "" ]; then
  n=0
  for f in /usr/bin/*; do
    [ -f "$f" ] || continue
    cp "$f" "$CLEAN/" 2>/dev/null && n=$((n+1))
    [ "$n" -ge 300 ] && break
  done
fi

# Malware corpus: the EICAR standard anti-malware test file (+ a couple of
# wrappers). Harmless string every engine is required to detect.
if [ "${2:-}" = "" ]; then
  EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  printf '%s' "$EICAR" > "$MAL/eicar.com"
  printf '%s' "$EICAR" > "$MAL/eicar.txt"
  { printf 'echo start\n'; printf '%s\n' "$EICAR"; } > "$MAL/eicar_wrapped.bat"
fi

mkdir -p dist
REPORT="dist/cert-report.txt"
{
  echo "AetherAV detection self-test"
  echo "============================"
  echo "engine:  $($AETHER --version 2>/dev/null | head -1)"
  echo "clean:   $CLEAN  ($(find "$CLEAN" -type f | wc -l) files)"
  echo "malware: $MAL  ($(find "$MAL" -type f | wc -l) files)"
  echo
  "$AETHER" eval --clean "$CLEAN" --malware "$MAL"
} | tee "$REPORT"

rm -rf "$WORK"
echo
echo "report written: $REPORT"
