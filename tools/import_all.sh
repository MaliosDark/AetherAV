#!/usr/bin/env bash
# Pull ALL the free detection content AetherAV can use, in one command.
#   ./tools/import_all.sh
# Knobs:
#   ABUSE_CH_AUTH_KEY=<key>   free key (https://auth.abuse.ch/): FULL hash dumps + MalwareBazaar TLSH
#   ABUSE_CH_FULL=1           pull the full abuse.ch hash dumps (millions)
#   WITH_YARA=1               fetch the YARA-Forge bundle (thousands of rules, opt-in)
#   SAMPLES=<dir>             build a TLSH DB from local malware samples
set -uo pipefail
cd "$(dirname "$0")/.."

echo "== 1/5 ClamAV hashes + .ndb patterns =="
python3 tools/import_clamav.py || echo "  (clamav import failed/skipped)"

echo "== 2/5 abuse.ch intel (FULL dumps need ABUSE_CH_AUTH_KEY + ABUSE_CH_FULL=1) =="
./tools/update-intel.sh || echo "  (intel update failed/skipped)"

echo "== 3/5 free IP + domain feeds (CINS, blocklist.de, ET, URLhaus domains, DigitalSide) =="
python3 tools/import_feeds.py || echo "  (feeds import failed/skipped)"

echo "== 4/5 community YARA: YARA-Forge bundle (opt-in) =="
if [ "${WITH_YARA:-0}" = "1" ]; then
  python3 tools/import_yara_forge.py core || python3 tools/import_yara.py || true
else
  echo "  (skipped; set WITH_YARA=1)"
fi

echo "== 5/5 TLSH variant database =="
if [ -n "${ABUSE_CH_AUTH_KEY:-}" ]; then
  echo "  from MalwareBazaar export (millions, no samples needed)"
  python3 tools/import_tlsh.py || true
elif [ -n "${SAMPLES:-}" ]; then
  echo "  from local samples: $SAMPLES"
  ./tools/build-tlsh.sh "$SAMPLES" Malware || true
else
  echo "  (skipped; set ABUSE_CH_AUTH_KEY for MalwareBazaar TLSH, or SAMPLES=<dir>)"
fi

echo "DONE. Rebuild/restart the engine to load the new content."
