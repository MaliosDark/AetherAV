//! Crypto clipboard-hijacker ("clipper") protection.
//!
//! Clippers sit in the background watching the clipboard; the instant you copy a
//! crypto address they silently replace it with the attacker's address, so your
//! funds go to them. The tell is unmistakable: a copied wallet address is
//! replaced by a *different* address of the *same* coin within a split second,
//! with no human in between. This module recognizes crypto addresses and flags
//! that swap (and can restore the original).
//!
//! Address classification and the swap detector are pure and cross-platform;
//! reading/writing the live clipboard is done by the CLI via the OS tools
//! (wl-paste/xclip, pbpaste/pbcopy, PowerShell Get-/Set-Clipboard).

use std::time::{Duration, Instant};

/// Crypto address families we recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinKind {
    Bitcoin,
    Ethereum,
    Litecoin,
    Tron,
    Monero,
    Solana,
}

impl CoinKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CoinKind::Bitcoin => "Bitcoin",
            CoinKind::Ethereum => "Ethereum",
            CoinKind::Litecoin => "Litecoin",
            CoinKind::Tron => "Tron",
            CoinKind::Monero => "Monero",
            CoinKind::Solana => "Solana",
        }
    }
}

const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn is_base58(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| B58.contains(c))
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Recognize a string as a single crypto wallet address. Conservative on
/// purpose - it must look like an address with no surrounding text.
pub fn classify_address(s: &str) -> Option<CoinKind> {
    let t = s.trim();
    if t.contains(char::is_whitespace) {
        return None;
    }
    // Ethereum / EVM: 0x + 40 hex.
    if t.len() == 42 && t.starts_with("0x") && is_hex(&t[2..]) {
        return Some(CoinKind::Ethereum);
    }
    // Bitcoin bech32 (bc1...) and legacy (1.../3...).
    if t.starts_with("bc1")
        && (14..=74).contains(&t.len())
        && t[3..].chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Some(CoinKind::Bitcoin);
    }
    if (t.starts_with('1') || t.starts_with('3')) && (26..=35).contains(&t.len()) && is_base58(t) {
        return Some(CoinKind::Bitcoin);
    }
    // Litecoin.
    if t.starts_with("ltc1") && (26..=48).contains(&t.len()) {
        return Some(CoinKind::Litecoin);
    }
    if (t.starts_with('L') || t.starts_with('M')) && (26..=35).contains(&t.len()) && is_base58(t) {
        return Some(CoinKind::Litecoin);
    }
    // Tron: T + base58, length 34.
    if t.starts_with('T') && t.len() == 34 && is_base58(t) {
        return Some(CoinKind::Tron);
    }
    // Monero: 4/8 + base58, length 95.
    if (t.starts_with('4') || t.starts_with('8')) && t.len() == 95 && is_base58(t) {
        return Some(CoinKind::Monero);
    }
    // Solana: base58, length 43-44 (checked last to avoid overlaps).
    if (43..=44).contains(&t.len()) && is_base58(t) {
        return Some(CoinKind::Solana);
    }
    None
}

/// A detected clipboard swap.
#[derive(Debug, Clone)]
pub struct ClipAlert {
    pub from: String,
    pub to: String,
    pub kind: CoinKind,
    pub note: String,
}

/// Watches a stream of clipboard contents for a clipper swap.
pub struct ClipGuard {
    window: Duration,
    last: Option<(String, CoinKind, Instant)>,
}

impl Default for ClipGuard {
    fn default() -> Self {
        ClipGuard::new()
    }
}

impl ClipGuard {
    /// A swap within this window (default 2s) of the same coin = suspected clipper.
    pub fn new() -> ClipGuard {
        ClipGuard {
            window: Duration::from_secs(2),
            last: None,
        }
    }

    pub fn with_window(window: Duration) -> ClipGuard {
        ClipGuard { window, last: None }
    }

    /// Feed the current clipboard text. Returns an alert when a wallet address
    /// is swapped for a different one of the same coin within the window.
    pub fn observe(&mut self, content: &str) -> Option<ClipAlert> {
        self.observe_at(content, Instant::now())
    }

    /// Testable variant with an explicit timestamp.
    pub fn observe_at(&mut self, content: &str, now: Instant) -> Option<ClipAlert> {
        // Not an address; ignore (don't reset a pending copy).
        let kind = classify_address(content)?;
        let cur = content.trim().to_string();
        let mut alert = None;
        if let Some((prev, pk, t)) = &self.last {
            if *pk == kind && *prev != cur && now.duration_since(*t) <= self.window {
                alert = Some(ClipAlert {
                    from: prev.clone(),
                    to: cur.clone(),
                    kind,
                    note: format!(
                        "{} address replaced within {}s - possible clipboard hijacker",
                        kind.as_str(),
                        self.window.as_secs()
                    ),
                });
            }
        }
        self.last = Some((cur, kind, now));
        alert
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_addresses() {
        assert_eq!(
            classify_address("0x52908400098527886E0F7030069857D2E4169EE7"),
            Some(CoinKind::Ethereum)
        );
        assert_eq!(
            classify_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            Some(CoinKind::Bitcoin)
        );
        assert_eq!(
            classify_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            Some(CoinKind::Bitcoin)
        );
        assert_eq!(
            classify_address("TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE"),
            Some(CoinKind::Tron)
        );
    }

    #[test]
    fn ignores_non_addresses() {
        assert_eq!(classify_address("hello world"), None);
        assert_eq!(classify_address("https://example.com/page"), None);
        assert_eq!(classify_address("0xnothex"), None);
        assert_eq!(classify_address(""), None);
    }

    #[test]
    fn detects_same_coin_swap_in_window() {
        let mut g = ClipGuard::new();
        let t = Instant::now();
        // User copies their address.
        assert!(g
            .observe_at("0x52908400098527886E0F7030069857D2E4169EE7", t)
            .is_none());
        // Clipper swaps it for a different ETH address moments later.
        let alert = g
            .observe_at(
                "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
                t + Duration::from_millis(80),
            )
            .expect("swap should be flagged");
        assert_eq!(alert.kind, CoinKind::Ethereum);
        assert!(alert.from.starts_with("0x529"));
        assert!(alert.to.starts_with("0xde0"));
    }

    #[test]
    fn no_alert_for_same_value_or_slow_change() {
        let mut g = ClipGuard::new();
        let t = Instant::now();
        let a = "0x52908400098527886E0F7030069857D2E4169EE7";
        let b = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe";
        g.observe_at(a, t);
        // Same content again: not a swap.
        assert!(g.observe_at(a, t + Duration::from_millis(50)).is_none());
        // A deliberate change long after: outside the window, not flagged.
        assert!(g.observe_at(b, t + Duration::from_secs(30)).is_none());
    }
}
