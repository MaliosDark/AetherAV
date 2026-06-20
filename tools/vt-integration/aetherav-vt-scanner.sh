#!/usr/bin/env bash
# VirusTotal contributor adapter for AetherAV.
#
# Exposes the operations a VirusTotal scanner integration expects. stdout is kept
# pristine (the detection name only); all engine logging goes to stderr/null.
#
#   aetherav-vt-scanner.sh --version      print engine + signature-DB version
#   aetherav-vt-scanner.sh --update       refresh signatures (signed), exit 0 on success
#   aetherav-vt-scanner.sh <file>         scan: prints detection name; exit 1=infected, 0=clean, 2=error
set -euo pipefail
AETHER="${AETHER_BIN:-aether}"
export AETHER_LOG=off RUST_LOG=off       # keep stdout clean for VT's parser

case "${1:-}" in
  --version|-v) exec "$AETHER" vt-scan --engine-version /dev/null 2>/dev/null ;;
  --update|-u)  exec "$AETHER" update 2>/dev/null ;;
  "")           echo "usage: $0 [--version|--update] <file>" >&2; exit 2 ;;
  *)            exec "$AETHER" vt-scan "$1" 2>/dev/null ;;
esac
