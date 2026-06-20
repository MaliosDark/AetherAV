# Benchmarking AetherAV (honest, reproducible numbers)

No paid lab is required to publish credible detection numbers - only a real
sample set, a real benign set, and full disclosure. This is how we do it.

## Run it
```bash
cargo build --release -p aether-cli
./tools/benchmark.sh --malware <malware_dir> --clean <benign_dir> --name "MOTIF 2024"
# -> dist/benchmark-report.md  (confusion matrix + metrics + methodology)
```
With no arguments it runs an EICAR smoke test against a sample of system binaries
- enough to prove the pipeline works, **not** a real detection figure.

## Free open malware corpora (give real numbers)
| Corpus | Free | Raw samples | Notes |
|--------|------|-------------|-------|
| **MOTIF** | yes | yes (3,095 disarmed PE + family labels) | cleanest license; the best first benchmark. git-lfs |
| **SOREL-20M** | yes | yes (~9.9M disarmed PE) | open AWS `s3://sorel-20m/`; large scale |
| **BODMAS** | yes | yes (57k mal + 77k benign), via use-agreement | includes a benign set |
| **EMBER 2018/2024** | yes | no (features only) | for ML parity, not for scanning |

Benign / false-positive corpus: there is **no** free redistributable goodware
set (it is copyrighted). Build your own from system binaries plus bulk app
installs (`winget` / `choco` / `apt`) - these are exactly the files that legit
AVs false-positive on, so they make an excellent FP regression set. Use the
**NIST NSRL** hash set for known-good whitelisting (hashes only, not files).

## Rules for credible numbers (AMTSO principles)
1. Always state the sample **set name, size, source and date**.
2. Report the **full confusion matrix** (TP/FP/FN/TN), not just a headline rate.
3. Test **false positives** on real, in-the-wild goodware.
4. For ML-style results, report **TPR at a fixed low FPR** (0.1% and 1%) and AUC.
5. Publish the scripts so anyone can reproduce it (`tools/benchmark.sh`).

## Safety + legal
- Open malware corpora are **real malware** (often disarmed but still dangerous).
  Handle only in an **isolated, offline VM**; know your local laws.
- **Never redistribute** samples inside AetherAV - MOTIF/BODMAS/abuse.ch terms
  forbid it. Keep them as a private test corpus.
- **VirusTotal:** its terms forbid using it for AV testing/benchmarking and
  publishing comparisons attributed to other engines. Use it only as a private
  sanity check of our own verdicts - never as a published comparison.

See also `docs/CERTIFICATION.md` (free badges + the paid-lab roadmap).
