# VirusTotal contributor integration

This package lets AetherAV run as a scanner engine inside VirusTotal (so an
"AetherAV" verdict appears alongside the other engines on every uploaded file).

## The adapter
`aetherav-vt-scanner.sh` implements the operations a VT scanner integration uses:

| Call | Behavior | Output |
|------|----------|--------|
| `--version` | report engine + signature-DB version | `AetherAV <ver> (signatures: N)` |
| `--update`  | pull the signed signature feed | exit 0 on success |
| `<file>`    | scan one file | detection name on **stdout**; exit **1**=infected, **0**=clean, **2**=error |

stdout carries only the detection name (all logs go to stderr), and a hit fires
only on a *Malicious* disposition - VirusTotal penalizes false positives, so the
adapter is intentionally conservative.

## How VirusTotal scans (the contract we satisfy)
VT runs each engine over uploaded files and records: detected (yes/no), the
detection name, the engine version and the definitions version. `vt-scan`
provides exactly those (see `--json` for a machine-readable form).

## Eligibility (the honest part)
VirusTotal onboards **established** AV vendors - typically AMTSO membership
and/or an independent-lab certification (AV-Comparatives / AV-TEST). This package
is ready so that, once AetherAV has that standing (see `docs/CERTIFICATION.md`),
applying is a matter of handing VT this adapter + the engine build. We do NOT
ship the reverse (querying VT's API from the client) by default - that would send
data to a third party and break our local-first, no-telemetry promise.

## Local test
```bash
cargo build --release -p aether-cli
export AETHER_BIN=target/release/aether
printf 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
tools/vt-integration/aetherav-vt-scanner.sh /tmp/eicar.com   # -> Test.EICAR  (exit 1)
tools/vt-integration/aetherav-vt-scanner.sh --version
```
