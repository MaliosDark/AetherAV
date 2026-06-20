# Verifying an AetherAV download

Every release ships three files: the `aether` binary, `SHA256SUMS`, and
`SHA256SUMS.sig` (an Ed25519 signature made with our **offline** key). This lets
you prove a download is genuine and untampered - even if the mirror/CDN you got
it from is compromised.

## Quick verify

```bash
# 1) the binary matches the published hash
sha256sum -c SHA256SUMS        # must print: aether: OK

# 2) the hash list itself is signed by the official offline key
aether verifyfile SHA256SUMS   # must print: ✓ TRUSTED
```

`verifyfile` checks `SHA256SUMS.sig` against the public key **compiled into the
client** (`TRUSTED_FEED_PUBKEY`). If it prints `✗ REJECTED`, do not run the
binary - the file (or its signature) was altered.

## Why this is safe even though we're open source

The verification key is *public* (it's in the source). What an attacker would
need is the **private** key, which never leaves an offline machine. Reading the
code doesn't help them forge a signature.

## Build it yourself (reproducible build)

You don't have to trust our binaries at all - rebuild from source and compare:

```bash
./tools/reproducible-build.sh
# compare the printed sha256 to the value in SHA256SUMS (same toolchain).
```

## Publisher (maintainers only)

On the air-gapped signer that holds `assets/keys/feed_private.key`:

```bash
./tools/sign-release.sh        # builds, hashes, signs -> dist/SHA256SUMS(.sig)
```
