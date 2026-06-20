#!/usr/bin/env bash
# AetherAV detection benchmark -> a methodology-compliant, publishable report.
#
# Produces dist/benchmark-report.md with the confusion matrix + metrics AND the
# context that makes numbers credible (dataset name/date/source/counts), per
# AMTSO testing principles.
#
#   ./tools/benchmark.sh --malware <dir> --clean <dir> [--name "MOTIF 2024-xx"]
#
# Free open malware corpora you can scan (REAL malware -> isolated, offline VM;
# do NOT redistribute inside AetherAV):
#   MOTIF   https://github.com/boozallen/MOTIF    (cleanest license; git-lfs)
#   SOREL-20M s3://sorel-20m/ (open AWS, ~9.9M disarmed PE)
#   BODMAS  https://whyisyoung.github.io/BODMAS/  (malware + benign, use-agreement)
# Benign corpus: there is no free redistributable goodware set - build your own
# from system binaries + bulk `winget`/`choco`/`apt` installs.
set -euo pipefail
cd "$(dirname "$0")/.."

AETHER="$(ls target/release/aether 2>/dev/null || ls target/debug/aether 2>/dev/null || true)"
[ -n "$AETHER" ] || { echo "build first: cargo build --release -p aether-cli"; exit 1; }

MAL=""; CLEAN=""; NAME=""
while [ $# -gt 0 ]; do case "$1" in
  --malware) MAL="$2"; shift 2;;
  --clean)   CLEAN="$2"; shift 2;;
  --name)    NAME="$2"; shift 2;;
  *) echo "unknown arg: $1"; exit 2;;
esac; done

WORK="$(mktemp -d)"

# Default benign corpus: a sample of real system binaries.
if [ -z "$CLEAN" ]; then
  CLEAN="$WORK/clean"; mkdir -p "$CLEAN"; n=0
  for f in /usr/bin/*; do
    [ -f "$f" ] || continue
    cp "$f" "$CLEAN/" 2>/dev/null && n=$((n+1)); [ "$n" -ge 500 ] && break
  done
fi
# Default malware corpus: EICAR only (a SMOKE TEST, not a real benchmark).
if [ -z "$MAL" ]; then
  MAL="$WORK/malware"; mkdir -p "$MAL"
  printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$MAL/eicar.com"
  [ -z "$NAME" ] && NAME="EICAR smoke test (NOT a benchmark - pass --malware a real corpus)"
fi
[ -z "$NAME" ] && NAME="custom corpus"

NC=$(find "$CLEAN" -type f | wc -l)
NM=$(find "$MAL" -type f | wc -l)
DATE="$(date -u +%Y-%m-%d)"
EVAL="$("$AETHER" eval --clean "$CLEAN" --malware "$MAL" 2>/dev/null)"

mkdir -p dist
REPORT="dist/benchmark-report.md"
cat > "$REPORT" <<MD
# AetherAV detection benchmark

| Field | Value |
|-------|-------|
| Engine | $("$AETHER" --version 2>/dev/null | head -1) |
| Date (UTC) | $DATE |
| Malware set | $NAME ($NM files) |
| Benign set | $CLEAN ($NC files) |
| Signatures | $("$AETHER" vt-scan --engine-version /dev/null 2>/dev/null) |

## Results
\`\`\`
$EVAL
\`\`\`

## Methodology (AMTSO-aligned)
- Samples are real files scanned by the shipping engine (not precomputed features).
- The full confusion matrix is reported (TP / FP / FN / TN), not just a headline rate.
- The malware set name, size and date are stated above so the result is reproducible.
- Benign (false-positive) testing uses real, in-the-wild goodware.
- Reproduce: \`./tools/benchmark.sh --malware <dir> --clean <dir> --name "<set>"\`.

## Honest caveats
- A detection rate is meaningless without the sample set: state set + date always.
- Use a large, recent, well-labelled malware corpus (e.g. MOTIF / SOREL-20M /
  BODMAS) for a representative figure; EICAR alone only proves the pipeline works.
- We do NOT derive comparisons against other engines from VirusTotal (its terms
  forbid using it for AV testing/benchmarking).
MD

rm -rf "$WORK"
echo "report written: $REPORT"
echo "-----"
cat "$REPORT"
