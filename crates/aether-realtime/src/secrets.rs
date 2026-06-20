//! Secret / wallet-key scanner.
//!
//! Infostealers that scrape memory or files harvest private keys, seed phrases
//! and cloud credentials. This recognizes those secrets in a byte buffer, so the
//! memory scanner can flag a (non-wallet) process whose memory is full of
//! harvested keys - a strong sign it is exfiltrating wallets.
//!
//! Pure and cross-platform. Deliberately conservative to avoid false positives
//! (e.g. a bare 64-hex string is ignored - it is usually a hash, not a key).

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretKind {
    PrivateKeyPem, // -----BEGIN ... PRIVATE KEY-----
    EthPrivateKey, // 0x + 64 hex
    SeedPhrase,    // 12/24 word mnemonic
    AwsKey,        // AKIA...
    StripeKey,     // sk_live_...
}

impl SecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::PrivateKeyPem => "PEM private key",
            SecretKind::EthPrivateKey => "Ethereum private key",
            SecretKind::SeedPhrase => "wallet seed phrase",
            SecretKind::AwsKey => "AWS access key",
            SecretKind::StripeKey => "Stripe secret key",
        }
    }
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// 0x followed by exactly 64 hex digits (a 256-bit EVM private key).
fn has_eth_private_key(t: &[u8]) -> bool {
    let mut i = 0;
    while i + 66 <= t.len() {
        if t[i] == b'0' && (t[i + 1] == b'x' || t[i + 1] == b'X') {
            let hex = &t[i + 2..i + 66];
            let after_ok = i + 66 >= t.len() || !is_hex(t[i + 66]);
            let before_ok = i == 0 || !is_hex(t[i - 1]);
            if before_ok && after_ok && hex.iter().all(|&b| is_hex(b)) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// AKIA + 16 uppercase alphanumerics (an AWS access-key id).
fn has_aws_key(t: &[u8]) -> bool {
    let mut i = 0;
    while i + 20 <= t.len() {
        if &t[i..i + 4] == b"AKIA" {
            let rest = &t[i + 4..i + 20];
            if rest
                .iter()
                .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// A run of >=12 consecutive lowercase words of 3-8 letters (BIP39-style mnemonic).
fn has_seed_phrase(text: &str) -> bool {
    let mut run = 0usize;
    for w in text.split_whitespace() {
        if (3..=8).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase()) {
            run += 1;
            if run >= 12 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Scan a byte buffer for embedded secrets; returns the distinct kinds found.
pub fn scan_secrets(data: &[u8]) -> Vec<SecretKind> {
    let mut hits = BTreeSet::new();
    // ASCII/UTF-8 view (memory may be binary; lossy keeps the printable runs).
    let text = String::from_utf8_lossy(data);
    let bytes = text.as_bytes();

    if text.contains("PRIVATE KEY-----") {
        hits.insert(SecretKind::PrivateKeyPem);
    }
    if text.contains("sk_live_") {
        hits.insert(SecretKind::StripeKey);
    }
    if has_eth_private_key(bytes) {
        hits.insert(SecretKind::EthPrivateKey);
    }
    if has_aws_key(bytes) {
        hits.insert(SecretKind::AwsKey);
    }
    if has_seed_phrase(&text) {
        hits.insert(SecretKind::SeedPhrase);
    }
    hits.into_iter().collect()
}

/// Convenience for the memory scanner's content callback: secret names found.
pub fn secret_labels(data: &[u8]) -> Vec<String> {
    scan_secrets(data)
        .into_iter()
        .map(|k| format!("Secret.{}", k.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pem_and_cloud_keys() {
        assert!(scan_secrets(b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
            .contains(&SecretKind::PrivateKeyPem));
        assert!(scan_secrets(b"key=AKIAIOSFODNN7EXAMPLE;").contains(&SecretKind::AwsKey));
        assert!(scan_secrets(b"stripe sk_live_abc123").contains(&SecretKind::StripeKey));
    }

    #[test]
    fn detects_eth_private_key_but_not_bare_hash() {
        let k = b"priv=0x4c0883a69102937d6231471b5dbb6204fe512961708279f2e3a1f1e2d8a5b6c7 end";
        assert!(scan_secrets(k).contains(&SecretKind::EthPrivateKey));
        // A bare 64-hex (no 0x) is a hash, not a key -> must NOT flag.
        let h = b"sha256 4c0883a69102937d6231471b5dbb6204fe512961708279f2e3a1f1e2d8a5b6c7";
        assert!(!scan_secrets(h).contains(&SecretKind::EthPrivateKey));
    }

    #[test]
    fn detects_seed_phrase() {
        let seed =
            "abandon ability able about above absent absorb abstract absurd abuse access accident";
        assert!(scan_secrets(seed.as_bytes()).contains(&SecretKind::SeedPhrase));
    }

    #[test]
    fn benign_text_is_clean() {
        let t = b"The quick brown fox jumps over the lazy dog. Meeting at 3pm regarding the quarterly report.";
        assert!(scan_secrets(t).is_empty());
    }
}
