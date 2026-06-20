# OpenSSF Best Practices badge - readiness checklist

The [OpenSSF Best Practices badge](https://www.bestpractices.dev) is the most
recognized, **free**, self-certified seal for open-source projects. This maps the
"Passing" criteria to AetherAV's evidence so the form can be filled quickly.

> To get the live badge: register the repo at https://www.bestpractices.dev, copy
> the answers below, and paste the issued badge URL into the README (placeholder
> already in place).

## Basics
| Criterion | Status | Evidence |
|---|---|---|
| Project website / description | met | `README.md` |
| Describes how to contribute | met | `CONTRIBUTING.md` |
| Contribution requirements (style, tests) | met | `CONTRIBUTING.md` |
| Free/open license (OSI) | met | `LICENSE` (Apache-2.0) |
| License in standard location | met | `/LICENSE` |
| Documentation (basics + interface) | met | `README.md`, `docs/` |
| Code of conduct | met | `CODE_OF_CONDUCT.md` |
| English for docs | met | all docs in English |

## Change control
| Criterion | Status | Evidence |
|---|---|---|
| Public version-controlled source | met | Git repository |
| Unique version numbering | met | calendar versions (e.g. 2026.1.0) |
| Release notes / changelog | met | `CHANGELOG.md` |

## Reporting
| Criterion | Status | Evidence |
|---|---|---|
| Bug-reporting process | met | GitHub Issues + `CONTRIBUTING.md` |
| Vulnerability report process | met | `SECURITY.md` (private disclosure) |
| Vulnerability reports honored | met | documented response policy |

## Quality
| Criterion | Status | Evidence |
|---|---|---|
| Working build system | met | Cargo workspace |
| Automated test suite | met | `cargo test` (200+ tests) in CI |
| Tests added for new functionality (policy) | met | `CONTRIBUTING.md` requires tests |
| Warning flags / linters | met | `cargo clippy -- -D warnings`, `cargo fmt --check` in CI |
| CI on multiple platforms | met | `.github/workflows/ci.yml` (Linux/macOS/Windows) |

## Security
| Criterion | Status | Evidence |
|---|---|---|
| Secure development knowledge | met | threat model in `SECURITY.md` |
| Uses good cryptography (no custom crypto) | met | Ed25519 (ed25519-dalek), SHA-2/3, ChaCha20-Poly1305 |
| Crypto keys / signatures for releases | met | signed feeds, model, releases; `docs/VERIFY.md` |
| Delivered over HTTPS / verified | met | signature verification regardless of transport |
| Hardening / no leaked credentials | met | offline signing key; `.gitignore` blocks keys/certs |
| Static analysis | met | clippy in CI; OpenSSF Scorecard workflow |
| Reproducible build | met | `tools/reproducible-build.sh` |

## Analysis / supply chain
| Criterion | Status | Evidence |
|---|---|---|
| OpenSSF Scorecard | met | `.github/workflows/scorecard.yml` |
| Dependency review | recommended | enable Dependabot / `cargo audit` in CI |

## Remaining to reach Silver/Gold
- Add `cargo audit` (or Dependabot) to CI for dependency CVEs.
- Two or more contributors / a documented bus-factor.
- Test coverage measurement (e.g. Codecov) and a stated coverage target.
- Signed releases published (the release CI already signs once certs/keys exist).
