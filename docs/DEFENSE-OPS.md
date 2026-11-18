# AetherAV defensive monitoring

## Linux executables, fileless activity and local AI

```sh
aether monitor --host server-01 --scan-executables --fileless --jsonl
aether monitor --host server-01 --scan-executables --fileless \
  --baseline known-good.json --aegis --propose-signatures --jsonl
```

The Linux process poller tracks PID start time and the executable's device and
inode. Use `--scan-running` alongside `--scan-executables` to inspect the
initial process snapshot. The monitor drains up to 32 inspections per poll
from a 4,096-entry queue, discards stale identities and logs overflow. It can
miss very short-lived or inaccessible processes. Executables are read via `/proc/PID/exe`. Fileless triage checks
executable anonymous regions, writable/executable mappings, memory-backed
images and mappings whose backing file was deleted. Content reads are bounded
and depend on OS permissions. Mapping findings can also arise from legitimate
JITs and software upgrades.

The host baseline learns from operator-supplied known-good traces. Aegis
receives redacted counts and detector IDs, and its output remains a triage
signal. A model prediction cannot block a process or change the baseline. For
pre-execution file blocking on supported Linux mounts, use the existing
privileged `aether protect` fanotify path with reviewed scope. A process poller
detects activity after it starts.

## Learn from confirmed incidents

The opt-in monitor can propose an exact hash when independent malicious
engines agree and an existing hash signature did not supply the result.
Review the quarantined evidence first, then run:

```sh
aether learn-attack quarantined-file --family Reviewed.Family
aether learn-attack quarantined-file --family Reviewed.Family \
  --apply --output approved-reviewed-family.db
```

The second command writes a new approval record after re-running eligibility
checks. The operator can merge reviewed records into their managed signature
collection. Live activity and unconfirmed incidents do not train the benign
baseline or publish signatures.

## Large SHA-256 catalogs

```sh
aether pack-signatures reviewed-sorted.sha256 --output reviewed.sha256.pack
```

Use unique, ascending SHA-256 entries from reviewed inputs with verifiable
provenance and a license that permits your intended use. Keep the original
source and family metadata in the named database if useful for investigation.
The packed index retains the digest and performs exact matching. It is
read-only during scans and the CLI creates the packed file atomically.

```toml
[engines]
packed_hash_db = "reviewed.sha256.pack"
```

`aether info` reports named and packed signatures separately. A 23-million
record index requires about 736.5 MB on disk. The packed reader uses a prefix
table and on-disk search rather than loading every hash into a heap map.
It reads the prefix table through a buffer at startup. On Unix, concurrent
lookups read with independent file offsets.

## SSH, Sigma and multi-server correlation

Export journal records locally or through an authenticated collector using
unique host names and synchronized clocks. Include overlapping collection
windows when batching, since SSH correlation uses five minutes of history.
Pass trusted exports to the correlation command:

```sh
aether ssh-events server-01.ndjson server-02.ndjson server-03.ndjson \
  --sigma assets/sigma/linux-sshd-root-login.json \
  --sigma assets/sigma/linux-sshd-invalid-user.json
```

The command parses `journalctl -o json` exports, deduplicates journal cursors
and emits JSONL findings for password spraying, distributed host targeting
from one IP, and login success after related failures. It accepts IPv4 and
IPv6. Correlation is batch-scoped and limited to 250,000 SSH events, one
million lines and 512 MiB per invocation. Forward findings to an existing
Wazuh or Elastic deployment and use transport authentication, retention and
dashboards provided by that deployment. The JSONL events share
`schema=aether.security_event.v1`, `event_time_us`, `host`, `rule_id` and
`severity`.

The compiled matcher supports a subset of Sigma in JSON syntax for
`product: linux` and `service: sshd`. It accepts one named selection with
AND across fields and OR within a value list. Fields are `Message`,
`TargetUser`, `SourceIp`, `Hostname` and `Outcome` (`success` or `failure`).
Operators are equality, `contains`, `startswith` and `endswith`. Unsupported
conditions or modifiers produce an error. See the
[Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html).

## SSH, firewall, administrative access and software audit

Collect effective settings in a secure location. On a Linux host with
OpenSSH and UFW, example inputs are the outputs of `sshd -T`, `ufw status
verbose`, and `id -nG jadmin`. Substitute the host's actual administrative
login if it uses another name. Optional inputs are `cargo audit --json` for
the specific antivirus checkout and `apt list --upgradable` on APT-based
hosts.

```sh
aether host-audit --sshd sshd-effective.txt --ufw ufw.txt \
  --admin-groups jadmin-groups.txt --cargo-audit antivirus-audit.json \
  --pending-packages packages.txt
```

The command emits recommendations in JSONL and returns code 1 for findings.
It reviews root login, password and keyboard-interactive settings,
authentication attempts, broad SSH rules, sensitive group membership and
supplied advisory or update records. Treat package updates as pending
maintenance and confirm applicable security advisories for the distribution.
Apply SSH and firewall changes only through the authorized host management
workflow after checking a separate recovery path.

## Ransomware

```sh
aether ransomguard documents --vault /protected-backups/run-01
aether ransomguard documents --vault /protected-backups/run-02 --restore
```

Use one empty vault per snapshot. The first mode detects a canary or mass-write
signal and reports it. The second mode permits one restore of changed or
missing direct regular files up to 25 MiB that were captured by the snapshot.
It skips symlink targets. Run each example on a separate clean test directory
or reuse one command for the chosen mode. Restore coverage is limited to the
snapshot, and an active encryptor can continue writing after rollback.
Keep separate access-restricted backups and verify recovery. See the
[CISA StopRansomware guide](https://www.cisa.gov/stopransomware/ransomware-guide).

## Reproduce metadata validation and model experiments

[EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) distributes file
features and labels without the original executables. Download the desired
archives from its [official dataset](https://huggingface.co/datasets/joyce8/EMBER2024)
and use the Git LFS SHA-256 shown for each archive as the expected digest.
The catalog tool requires Python 3.11 or newer and SQLite 3.30 or newer.

```sh
python tools/validate_ember_catalog.py --out review.sha256 \
  "$EXPECTED_TRAIN_DIGEST=$TRAIN_ZIP" "$EXPECTED_TEST_DIGEST=$TEST_ZIP"
aether pack-signatures review.sha256 --output review.pack
```

Each candidate has the dataset's malicious label, at least ten reported
detections and no conflicting benign label in the supplied archives. This
is source validation and deduplication for review. Detection counts from
one dataset cannot substitute for independent corroboration. Keep these
candidates outside the blocking configuration while evaluating them, and
keep evaluation hashes out of catalog data used for detector benchmarks.

The November 2026 run processed eight archives covering ELF, .NET, PDF and
APK. From 1,344,000 rows and 671,942 distinct hashes it staged 275,978
candidates. The review list SHA-256 was
`0af18750065da338a96da3a33ddd92b8fb4ef9bc676ee27fa2decfe6434c5a4a`.
The repository's bundled signature counts and default configuration stay
separate from these operator-generated catalogs.

For a temporal evaluation of the static PE classifier, use the .NET
archives and install NumPy and scikit-learn in an isolated Python
environment.

```sh
python tools/train_ember_pe.py \
  --train "$EXPECTED_TRAIN_DIGEST=$TRAIN_ZIP" \
  --test "$EXPECTED_TEST_DIGEST=$TEST_ZIP" \
  --baseline assets/models/pe.json --out pe-candidate.json
```

The experiment trained on 219,997 unique rows, calibrated on 39,999 and
tested on 59,953 from later weeks. At the calibrated threshold, it
flagged 1,822 of 30,000 malicious rows and 23 of 29,953 benign rows.
ROC AUC was 0.924. The test used metadata features corresponding to
AetherAV's PE extractor and omitted imports due to parser differences.
These figures describe that experiment and do not establish byte-level
parser parity or production scan efficacy. The shipped PE model was not
replaced.

To reproduce response-only fine-tuning of the local Aegis model, prepare
the JSONL files using [the dataset generator](../tools/TRAINING.md), then
install CPU PyTorch, Transformers 4.57, Accelerate and GGUF in an isolated
Python environment.

```sh
python tools/train_aegis_triage.py --base assets/models/aegis-50m.gguf \
  --train av_train.jsonl --eval av_eval.jsonl --out aegis-candidate
```

The command updates two transformer layers and the final norm. It reports
the score of each candidate label before and after training and writes
the changed layers as a separate safetensors file for review, with the
base checkpoint's SHA-256. The pilot used synthetic
behavioral observations and does not measure free-form verdict generation,
performance on real traces or the behavior of an exported quantized model.
On 120 held-out synthetic observations, the baseline got 42 labels correct
and the candidate got 69 correct. False positives rose from 21 to 39 out
of 49 benign observations, so the candidate was not promoted.
