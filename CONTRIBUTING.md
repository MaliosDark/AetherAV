# Contributing to AetherAV

Thanks for helping build a trustworthy, open antivirus. AetherAV is Apache-2.0
licensed; by contributing you agree your work is licensed under the same terms.

## Getting started
```bash
cargo build --workspace
cargo test  --workspace
cargo fmt --all && cargo clippy --workspace -- -D warnings
```

## Ground rules
- **Tests + clippy must pass.** CI runs `cargo test`, `cargo fmt --check` and
  `cargo clippy -- -D warnings` on Linux, macOS and Windows.
- **No ASCII-art noise.** Do not use em-dashes, en-dashes, box-drawing
  characters, or arrow glyphs in code, output or docs.
- **We own our detection content.** New detection rules go in `assets/rules/`
  (our YARA). Third-party rule repos are opt-in only, never default.
- **Security-sensitive areas** (signing, the update channel, real-time blockers)
  need a test and a clear rationale in the PR.

## How to contribute
1. Open an issue describing the bug or proposal first.
2. Fork, branch, and keep PRs focused.
3. Add or update tests; update docs/README if behavior changes.
4. Describe what you changed and why; reference the issue.

## Reporting vulnerabilities
Do **not** open a public issue for security bugs. Follow [SECURITY.md](SECURITY.md).

## Code of conduct
Participation is governed by our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
