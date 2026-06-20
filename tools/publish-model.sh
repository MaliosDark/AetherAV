#!/usr/bin/env bash
# Sign and stage a retrained Aegis model for distribution to all clients.
#
# Run on the OFFLINE signer. Produces dist-model/{aegis-50m.gguf, aegis.manifest.json}.
# Upload both to a static host and point clients' update.model_url at the manifest.
# Clients verify the manifest signature + the model hash + anti-rollback before
# atomically swapping the model in (see `aether model-update`).
set -euo pipefail
cd "$(dirname "$0")/.."

KEY="${AETHER_KEY:-assets/keys/feed_private.key}"
MODEL="${AETHER_MODEL:-assets/models/aegis-50m.gguf}"
AETHER="${AETHER_BIN:-target/release/aether}"
# Public URL where you will host the model file:
MODEL_URL="${AETHER_MODEL_URL:-https://feeds.example.com/aegis-50m.gguf}"
OUT="dist-model"

[ -f "$KEY" ]   || { echo "private key not found: $KEY (keep it offline)"; exit 1; }
[ -f "$MODEL" ] || { echo "model not found: $MODEL"; exit 1; }
[ -x "$AETHER" ] || AETHER="target/debug/aether"
[ -x "$AETHER" ] || { echo "build first: cargo build --release -p aether-cli"; exit 1; }

mkdir -p "$OUT"
VER="$(date +%s)"
SHA="$(sha256sum "$MODEL" | cut -d' ' -f1)"

echo ">> model v$VER sha256=$SHA"
# Sign the canonical "version|sha256" string with the offline key.
printf '%s' "${VER}|${SHA}" > "$OUT/.payload"
"$AETHER" signfile "$OUT/.payload" --key "$KEY" >/dev/null
SIG="$(cat "$OUT/.payload.sig")"
rm -f "$OUT/.payload" "$OUT/.payload.sig"

cp "$MODEL" "$OUT/aegis-50m.gguf"
cat > "$OUT/aegis.manifest.json" <<JSON
{
  "version": ${VER},
  "sha256": "${SHA}",
  "model_url": "${MODEL_URL}",
  "sig": "${SIG}"
}
JSON

echo ">> staged for upload:"
ls -lh "$OUT/aegis-50m.gguf" "$OUT/aegis.manifest.json"
echo ">> publish both; set clients' update.model_url to the manifest URL."
