#!/usr/bin/env bash
# Automatic signature-feed refresh, end to end:
#   1. pull fresh intel from every free source (abuse.ch ThreatFox/Bazaar/URLhaus/
#      Feodo + the IP/domain feeds), folding it into the local intel store and
#      rebuilding assets/signatures/hashes.db,
#   2. sign the feed with the offline Ed25519 key and stage dist-feed/aether.json,
#   3. the running server serves that file straight away (it reads it per request),
#      so clients pulling /feed - or pressing "Update" - get the new indicators.
#
# Designed to be driven by a systemd timer so the operator does nothing. Set
# ABUSE_CH_AUTH_KEY (free, https://auth.abuse.ch/) + ABUSE_CH_FULL=1 to pull the
# full hash dumps instead of the smaller "recent" feeds.
set -uo pipefail
cd "$(dirname "$0")/.."
log() { echo "[$(date -u +%FT%TZ)] $*"; }

# One monotonic version for the whole run, threaded through every import and the
# publish step. This keeps the per-IOC version stamps consistent so the server's
# incremental (delta) feeds are computed correctly.
export FEED_VERSION="$(date +%s)"

log "fetching fresh intel from all sources…"
./tools/update-intel.sh        || log "warn: intel fetch had warnings (some sources unreachable?)"
python3 tools/import_feeds.py   2>/dev/null || log "warn: IP/domain feeds skipped"

log "signing + publishing the feed (offline key)…"
./tools/publish-feed.sh         || { log "ERROR: publish failed"; exit 1; }

sigs=$(grep -cvE '^\s*(#|$)' assets/signatures/hashes.db 2>/dev/null || echo '?')
log "done · $(ls -lh dist-feed/aether.json 2>/dev/null | awk '{print $5}') feed · ${sigs} hash signatures live"
