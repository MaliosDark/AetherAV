# Independent certification - roadmap

Independent lab results are the credibility currency of an antivirus. This is how
AetherAV gets there, and what we can show today.

## Run our self-test (reproducible evidence)
```bash
cargo build --release -p aether-cli
./tools/cert-selftest.sh            # -> dist/cert-report.txt
```
It evaluates the engine against a clean corpus (a sample of real system
binaries) and a malware corpus (the EICAR standard test file) using `aether
eval`, and reports detection rate, false-positive rate, precision and accuracy.

Current internal numbers (small set; not a substitute for a lab): 100% detection
on the EICAR/internal malware set, ~0% false positives on real binaries. Use a
larger labelled malware corpus for a meaningful detection figure before any
submission.

## The labs (in the order worth pursuing)
1. **VirusTotal (free, fastest credibility).** Apply to add AetherAV as a
   contributor scanner. Lowest barrier; gets the engine in front of millions of
   lookups and produces public detection data.
2. **AV-Comparatives.** Real-World Protection + Malware Protection tests.
   Requires a stable installer, real-time protection on the tested OS (Windows),
   and a support contact. Start with their "Approved" certification track.
3. **AV-TEST.** Protection / Performance / Usability scoring on Windows. Needs a
   Windows real-time product and an update channel (both wired - see below).
4. **MITRE ATT&CK Evaluations.** Behavioral/EDR-focused; pursue once an EDR
   console exists. Our verdicts already carry ATT&CK technique IDs.

## Prerequisites we already have
- Signed, reproducible installers for all three OSes (`docs/RELEASE.md`).
- Auto-updating, Ed25519-signed signatures + model.
- Real-time protection (Linux kernel fanotify today; Windows user-mode watcher
  now, kernel minifilter scaffolded).
- An evaluation harness (`aether eval`) and this self-test.

## Prerequisites still needed before submitting
- **Windows real-time at kernel level** (sign + ship the minifilter) for the
  Windows-based lab tests.
- **OS code-signing certificates** (Authenticode + Apple Developer ID) so the
  installers are trusted - labs test the real, signed product.
- A **larger labelled malware corpus** for a statistically meaningful detection
  rate (the labs supply their own; this is for our pre-submission tuning).
- A vendor **support/contact** and a stable release cadence.

The honest message for users until then: we publish our own measured numbers and
keep the engine fully auditable - trust by verification, with lab certification
on the roadmap.
