//! Infostealer / wallet-stealer shield.
//!
//! Modern commodity malware (RedLine, Lumma, Raccoon, ...) does not encrypt -
//! it *steals*: it sweeps the disk for crypto-wallet files, browser credential
//! stores, SSH keys, cloud secrets and password vaults, then exfiltrates them.
//!
//! This shield defends two ways:
//!   1. **Honeytokens (decoys):** plant believable fake wallet / credential
//!      files. No legitimate program ever reads them, so a *read* is a near
//!      certain stealer - and we get the offending PID to block at the source.
//!   2. **Enumeration detection:** a process that opens many real credential /
//!      wallet targets in a short window is flagged even without a decoy hit.
//!
//! Classification and decoy logic are pure and cross-platform; live blocking
//! (PID capture + kill/deny) uses fanotify on Linux (see [`crate::onaccess`]).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// What an infostealer is after.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetKind {
    CryptoWallet,
    BrowserCreds,
    SshKey,
    CloudCreds,
    EnvSecret,
    PasswordVault,
    Keychain,
}

impl TargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetKind::CryptoWallet => "crypto wallet",
            TargetKind::BrowserCreds => "browser credentials",
            TargetKind::SshKey => "SSH key",
            TargetKind::CloudCreds => "cloud credentials",
            TargetKind::EnvSecret => "env secret",
            TargetKind::PasswordVault => "password vault",
            TargetKind::Keychain => "keychain",
        }
    }
}

/// Classify a path as a credential/wallet target an infostealer hunts for.
/// Cross-platform: matches on filename + path substrings, case-insensitive.
pub fn classify(path: &Path) -> Option<TargetKind> {
    let full = path.to_string_lossy().to_lowercase().replace('\\', "/");
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Crypto wallets.
    if name == "wallet.dat"
        || name.ends_with(".wallet")
        || name.contains("electrum")
        || full.contains("/exodus/")
        || full.contains("metamask")
        || full.contains("/ethereum/keystore")
        || full.contains("/.bitcoin/")
        || full.contains("ledger live")
        || full.contains("/trezor")
        || (name.starts_with("seed") && name.ends_with(".txt"))
    {
        return Some(TargetKind::CryptoWallet);
    }
    // Browser credential stores (Chrome/Edge/Brave + Firefox).
    if name == "login data"
        || name == "key4.db"
        || name == "logins.json"
        || name == "signons.sqlite"
        || name == "cookies.sqlite"
        || full.contains("/login data")
    {
        return Some(TargetKind::BrowserCreds);
    }
    // SSH private keys.
    if full.contains("/.ssh/") && (name.starts_with("id_") && !name.ends_with(".pub")) {
        return Some(TargetKind::SshKey);
    }
    // Cloud credentials.
    if full.contains("/.aws/credentials")
        || full.contains("/.azure/")
        || full.contains("/.kube/config")
        || full.contains("gcloud/credentials")
    {
        return Some(TargetKind::CloudCreds);
    }
    // .env secrets.
    if name == ".env" || name.starts_with(".env.") {
        return Some(TargetKind::EnvSecret);
    }
    // Password vaults.
    if name.ends_with(".kdbx") || name.ends_with(".kdb") || full.contains("bitwarden") {
        return Some(TargetKind::PasswordVault);
    }
    // macOS keychain.
    if name.ends_with(".keychain") || name.ends_with(".keychain-db") || full.contains("/keychains/")
    {
        return Some(TargetKind::Keychain);
    }
    None
}

/// Believable decoy honeytokens (name -> content). Content is harmless/fake;
/// the *read* is the signal, so the bytes only need to look plausible.
const DECOYS: &[(&str, &[u8])] = &[
    ("wallet.dat", b"\x00\x01core-wallet\x00fake-aetherav-decoy-do-not-use\x00"),
    ("seed phrase.txt", b"abandon ability able about above absent absorb abstract absurd abuse access accident\n"),
    ("metamask_vault.json", b"{\"data\":\"AETHERAV-DECOY\",\"iv\":\"00\",\"salt\":\"00\"}\n"),
    ("Login Data", b"SQLite format 3\x00AETHERAV-DECOY-browser-credentials\n"),
    (".env", b"AETHERAV_DECOY=1\nAWS_SECRET_ACCESS_KEY=DECOY0000000000000000000000000000000000\n"),
    ("id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----\nAETHERAV-DECOY-not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n"),
];

/// A set of planted decoy files.
pub struct Decoys {
    pub dir: PathBuf,
    pub files: Vec<PathBuf>,
}

impl Decoys {
    /// Plant decoy honeytokens into `dir` (created if needed).
    pub fn plant(dir: impl AsRef<Path>) -> Result<Decoys, String> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let mut files = Vec::new();
        for (name, body) in DECOYS {
            let p = dir.join(name);
            fs::write(&p, body).map_err(|e| e.to_string())?;
            files.push(p);
        }
        Ok(Decoys { dir, files })
    }

    /// Re-derive the decoy paths for an already-armed dir (no writes).
    pub fn existing(dir: impl AsRef<Path>) -> Decoys {
        let dir = dir.as_ref().to_path_buf();
        let files = DECOYS.iter().map(|(n, _)| dir.join(n)).collect();
        Decoys { dir, files }
    }

    pub fn is_decoy(&self, path: &Path) -> bool {
        // Compare by file name within our decoy dir (handles symlinked /proc fd paths loosely).
        self.files.iter().any(|d| d == path)
            || path.file_name().is_some_and(|n| {
                DECOYS.iter().any(|(dn, _)| *dn == n.to_string_lossy())
                    && path.parent() == Some(self.dir.as_path())
            })
    }
}

/// A confirmed or suspected stealer activity.
#[derive(Debug, Clone)]
pub struct Detection {
    pub pid: i32,
    pub reason: String,
    pub kind: Option<TargetKind>,
    /// True when triggered by a decoy read (near-certain).
    pub decoy: bool,
    /// "high" for decoy hits, "medium" for enumeration heuristic.
    pub severity: &'static str,
}

/// Detects stealer behavior from a stream of (pid, path) file-access events.
pub struct StealerDetector {
    window: Duration,
    enum_threshold: usize,
    seen: HashMap<i32, (Instant, HashSet<String>)>,
}

impl Default for StealerDetector {
    fn default() -> Self {
        StealerDetector::new()
    }
}

impl StealerDetector {
    /// Default: a process touching >=4 distinct credential/wallet targets within
    /// 8 seconds is flagged.
    pub fn new() -> StealerDetector {
        StealerDetector {
            window: Duration::from_secs(8),
            enum_threshold: 4,
            seen: HashMap::new(),
        }
    }

    pub fn with_params(window: Duration, enum_threshold: usize) -> StealerDetector {
        StealerDetector {
            window,
            enum_threshold,
            seen: HashMap::new(),
        }
    }

    /// Observe a file open. `is_decoy` should be true if the path is a planted
    /// honeytoken. Returns a [`Detection`] when this access confirms a stealer.
    pub fn observe(&mut self, pid: i32, path: &Path, is_decoy: bool) -> Option<Detection> {
        self.observe_at(pid, path, is_decoy, Instant::now())
    }

    /// Testable variant with an explicit timestamp.
    pub fn observe_at(
        &mut self,
        pid: i32,
        path: &Path,
        is_decoy: bool,
        now: Instant,
    ) -> Option<Detection> {
        if is_decoy {
            return Some(Detection {
                pid,
                reason: format!("read a credential/wallet DECOY ({})", path.display()),
                kind: classify(path),
                decoy: true,
                severity: "high",
            });
        }
        let kind = classify(path)?;
        let entry = self
            .seen
            .entry(pid)
            .or_insert_with(|| (now, HashSet::new()));
        // Reset the window if it elapsed.
        if now.duration_since(entry.0) > self.window {
            *entry = (now, HashSet::new());
        }
        entry.1.insert(format!("{kind:?}:{}", path.display()));
        if entry.1.len() >= self.enum_threshold {
            let n = entry.1.len();
            self.seen.remove(&pid);
            return Some(Detection {
                pid,
                reason: format!(
                    "enumerated {n} credential/wallet locations in <{}s",
                    self.window.as_secs()
                ),
                kind: Some(kind),
                decoy: false,
                severity: "medium",
            });
        }
        None
    }
}

/// Best-effort kill of the offending (stealer) process. Linux only for now.
#[cfg(target_os = "linux")]
pub fn kill_pid(pid: i32) -> bool {
    unsafe { libc::kill(pid, libc::SIGKILL) == 0 }
}
#[cfg(not(target_os = "linux"))]
pub fn kill_pid(_pid: i32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_targets() {
        let cases = [
            ("/home/u/.bitcoin/wallet.dat", TargetKind::CryptoWallet),
            ("/home/u/Exodus/exodus.wallet", TargetKind::CryptoWallet),
            (
                "/home/u/.config/google-chrome/Default/Login Data",
                TargetKind::BrowserCreds,
            ),
            (
                "/home/u/.mozilla/firefox/x/key4.db",
                TargetKind::BrowserCreds,
            ),
            ("/home/u/.ssh/id_ed25519", TargetKind::SshKey),
            ("/home/u/.aws/credentials", TargetKind::CloudCreds),
            ("/srv/app/.env", TargetKind::EnvSecret),
            ("/home/u/Vault.kdbx", TargetKind::PasswordVault),
            (
                "/Users/u/Library/Keychains/login.keychain-db",
                TargetKind::Keychain,
            ),
        ];
        for (p, want) in cases {
            assert_eq!(classify(Path::new(p)), Some(want), "{p}");
        }
    }

    #[test]
    fn classify_ignores_benign_and_pubkeys() {
        assert_eq!(classify(Path::new("/home/u/notes.txt")), None);
        assert_eq!(classify(Path::new("/home/u/.ssh/id_rsa.pub")), None); // public key, not secret
        assert_eq!(classify(Path::new("/usr/bin/ls")), None);
    }

    #[test]
    fn decoy_read_is_instant_high() {
        let mut d = StealerDetector::new();
        let hit = d
            .observe(1234, Path::new("/decoys/wallet.dat"), true)
            .unwrap();
        assert!(hit.decoy);
        assert_eq!(hit.severity, "high");
        assert_eq!(hit.pid, 1234);
    }

    #[test]
    fn enumeration_triggers_at_threshold() {
        let mut d = StealerDetector::new();
        let t = Instant::now();
        let paths = [
            "/h/.bitcoin/wallet.dat",
            "/h/.ssh/id_rsa",
            "/h/.aws/credentials",
            "/h/app/.env",
        ];
        let mut fired = None;
        for p in paths {
            fired = d.observe_at(4444, Path::new(p), false, t);
        }
        let hit = fired.expect("should flag enumeration at 4 distinct targets");
        assert!(!hit.decoy);
        assert_eq!(hit.pid, 4444);
    }

    #[test]
    fn below_threshold_or_spread_across_pids_is_quiet() {
        let mut d = StealerDetector::new();
        let t = Instant::now();
        assert!(d
            .observe_at(1, Path::new("/h/.ssh/id_rsa"), false, t)
            .is_none());
        assert!(d
            .observe_at(1, Path::new("/h/app/.env"), false, t)
            .is_none());
        // Different pids each touching one target: never reaches threshold.
        for (i, p) in ["/h/.bitcoin/wallet.dat", "/h/.aws/credentials"]
            .iter()
            .enumerate()
        {
            assert!(d
                .observe_at(100 + i as i32, Path::new(p), false, t)
                .is_none());
        }
    }

    #[test]
    fn decoy_plant_and_detect() {
        let dir = std::env::temp_dir().join("aether_decoy_test_xyz");
        let _ = fs::remove_dir_all(&dir);
        let decoys = Decoys::plant(&dir).unwrap();
        assert!(!decoys.files.is_empty());
        assert!(decoys.files.iter().all(|p| p.exists()));
        assert!(decoys.is_decoy(&dir.join("wallet.dat")));
        assert!(!decoys.is_decoy(Path::new("/etc/hosts")));
        let _ = fs::remove_dir_all(&dir);
    }
}
