#!/usr/bin/env bash
# AetherAV - retrain the Aegis-50M detection model end to end, in one flow:
#
#   1. dataset   gen_av_dataset.py  -> assets/datasets/av_train.jsonl (+ eval)
#   2. fine-tune train_av_llm.py    -> LoRA on Supra-50M + HF PowerShell
#   3. export    -> q4_k_m GGUF      -> assets/models/aegis-50m.gguf
#                  (one-shot via Unsloth, else merge -> convert -> quantize)
#   4. publish   publish-model.sh   -> dist-model/{aegis-50m.gguf, aegis.manifest.json}
#                  (Ed25519-signed + versioned; clients auto-pull via `aether model-update`)
#
# Run stages 1-3 on the box with the Unsloth env + GPU. Run stage 4 (signing) on
# the OFFLINE signer that holds assets/keys/feed_private.key. Each stage is
# individually skippable with SKIP_DATASET / SKIP_TRAIN / SKIP_PUBLISH=1.
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${AETHER_PY:-/home/nexland/.unsloth/studio/unsloth_studio/bin/python}"
LLAMA="${LLAMA_CPP:-/home/nexland/.unsloth/llama.cpp}"
MODEL="assets/models/aegis-50m.gguf"

SKIP_DATASET="${SKIP_DATASET:-0}"
SKIP_TRAIN="${SKIP_TRAIN:-0}"
SKIP_PUBLISH="${SKIP_PUBLISH:-0}"

log() { printf '\n=== %s ===\n' "$*"; }

# --- 1) dataset -----------------------------------------------------------
if [ "$SKIP_DATASET" = "0" ]; then
  log "1/4 generate dataset"
  [ -x "$PY" ] || { echo "Unsloth python not found at $PY (set AETHER_PY)"; exit 1; }
  "$PY" tools/gen_av_dataset.py
else
  log "1/4 dataset (skipped)"
fi

# --- 2/3) train + export GGUF --------------------------------------------
if [ "$SKIP_TRAIN" = "0" ]; then
  [ -x "$PY" ] || { echo "Unsloth python not found at $PY (set AETHER_PY)"; exit 1; }
  prev_sha=""; [ -f "$MODEL" ] && prev_sha="$(sha256sum "$MODEL" | cut -d' ' -f1)"

  log "2/4 fine-tune Aegis-50M (this is the long step)"
  "$PY" tools/train_av_llm.py

  new_sha=""; [ -f "$MODEL" ] && new_sha="$(sha256sum "$MODEL" | cut -d' ' -f1)"
  if [ -z "$new_sha" ] || [ "$new_sha" = "$prev_sha" ]; then
    # The in-script Unsloth GGUF helper can be flaky; fall back to the manual
    # merge -> convert -> quantize path.
    log "3/4 GGUF fallback (merge LoRA -> convert -> quantize q4_k_m)"
    "$PY" tools/export_gguf.py
    "$PY" tools/convert_gguf.py
    QUANT="$(ls "$LLAMA"/build*/bin/llama-quantize 2>/dev/null | head -1 || true)"
    [ -n "$QUANT" ] || { echo "llama-quantize not found under $LLAMA/build*/bin"; exit 1; }
    "$QUANT" /tmp/aether-f16.gguf "$MODEL" Q4_K_M
  else
    log "3/4 GGUF produced by the training step"
  fi
else
  log "2-3/4 train + export (skipped)"
fi

[ -f "$MODEL" ] || { echo "no model at $MODEL - training/export did not produce one"; exit 1; }
echo ">> model ready: $MODEL ($(du -h "$MODEL" | cut -f1))"

# --- 4) sign + stage for distribution ------------------------------------
if [ "$SKIP_PUBLISH" = "0" ]; then
  log "4/4 sign + stage for clients (publish-model.sh)"
  tools/publish-model.sh
  echo ">> staged: dist-model/{aegis-50m.gguf, aegis.manifest.json}"
else
  log "4/4 publish (skipped) - run tools/publish-model.sh on the OFFLINE signer"
fi

log "DONE"
echo "Upload dist-model/* to your model host and point clients' update.model_url at the manifest."
echo "Clients verify signature + hash + anti-rollback, then atomically swap via: aether model-update"
