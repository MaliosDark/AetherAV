# AetherAV fuzzing

Coverage-guided fuzzing of the security-critical parsers - the #1 attack surface
of any scanner (a crash on attacker-controlled input is a vulnerability).

Two layers:

1. **Always-on robustness tests** (run under stable `cargo test`): each of
   `aether-parsers`, `aether-unpack` and `aether-core` has a
   `*_never_panic_on_hostile_input` test that throws thousands of random /
   magic-prefixed buffers at every parser and the full scan pipeline. These run
   in CI today and catch regressions without a nightly toolchain.

2. **Deep coverage-guided fuzzing** (this crate, nightly + libFuzzer):

   ```bash
   cargo install cargo-fuzz
   cargo +nightly fuzz run parse_pe        # PE parser + entropy
   cargo +nightly fuzz run parse_object    # ELF + Mach-O
   cargo +nightly fuzz run parse_docs      # PDF / Office / script scanners
   cargo +nightly fuzz run unpack          # ZIP/GZIP/TAR/7z extraction
   cargo +nightly fuzz run intel_feeds     # ThreatFox/MalwareBazaar/URLhaus/Feodo parsers

   # reproduce a crash:
   cargo +nightly fuzz run parse_pe fuzz/artifacts/parse_pe/crash-<hash>
   ```

Targets live in `fuzz_targets/` and must never panic for any input. This crate
is its own workspace and is excluded from the engine workspace, so normal
`cargo build` / CI never require nightly.
