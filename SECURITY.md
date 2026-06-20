# Security Policy

AetherAV is open source. Its security does **not** depend on the code being
secret - only on **keys** being secret (Kerckhoffs's principle). Reading the
source does not let an attacker forge updates, tamper with releases undetected,
or evade every detection layer.

## How we stay hard to bypass even though we're open

- **Cryptographic update integrity.** Threat-intel feeds and releases are signed
  with **Ed25519**; the private key is kept offline and never touches any server.
  A compromised mirror/CDN or a man-in-the-middle **cannot** push a malicious
  update - clients reject anything not signed by the offline key.
- **Behavioral / runtime detection.** Static rules can be read and evaded, but
  malware cannot hide *what it does*: mass file encryption (ransomware shield),
  code injection / fileless execution (memory scan), hidden processes
  (cross-view Process Sentinel), C2 ports/IPs (network monitor). These are not
  bypassable by reading our source.
- **Defense in depth.** Evading one engine is not enough - a sample must beat
  hashes, YARA, ClamAV-style patterns, heuristics, the on-device model, the
  sandbox, behavioral, memory, on-access and reputation layers.
- **Frequent content updates.** Signatures/IOCs move constantly, so a static
  evasion studied today is stale tomorrow. Some detection is server-side.
- **Tamper detection.** `aether selfcheck` (integrity manifest) and process
  self-protection (`PR_SET_DUMPABLE=0`) detect/raise the cost of tampering.

## Reporting a vulnerability

**Please do not open a public issue for security bugs.** Email
`security@aetherav.example` (replace with the project's address) with:
- a description and impact,
- steps/PoC to reproduce,
- affected version/commit.

We aim to acknowledge within 72 hours and to ship a fix (and a signed feed/
release) before public disclosure. We support **coordinated disclosure** and
will credit reporters who want it.

In scope: the engine, CLI, desktop app, the feed/submission protocol and the
signing/verification logic. Out of scope: attacks requiring an already-root
local attacker (no userland AV survives that - defense there is detection, not
prevention), and third-party feeds (abuse.ch, CIRCL).

## Verifying a download

Every release ships a signed `SHA256SUMS`. See [docs/VERIFY.md](docs/VERIFY.md).

## Key rotation

If the offline signing key is ever exposed, we generate a new keypair, ship a
client update embedding the new `TRUSTED_FEED_PUBKEY`, and re-sign current feeds
and releases. Old signatures stop being trusted.
