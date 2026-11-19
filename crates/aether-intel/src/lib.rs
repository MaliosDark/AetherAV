//! `aether-intel` - threat-intelligence feeds, signed delta updates, hot-reload.
//!
//! Local-first: everything works offline. A [`Feed`] is a versioned batch of
//! IOCs, authenticated with an HMAC so tampered/spoofed updates are rejected.
//! An [`IntelStore`] merges feeds incrementally (delta updates) and can be
//! re-applied at runtime without a restart, then exported to the hash-DB format
//! the signature engine already consumes. MISP/VirusTotal exports import via
//! [`Feed::from_misp_json`].

pub mod hmac;

use aether_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::Path;

/// Kind of indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Sha256,
    Md5,
    Domain,
    Ipv4,
    Url,
}

/// A single indicator of compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    #[serde(default)]
    pub threat: String,
    /// Latest store version at which the indicator or its label changed.
    /// Not part of `canonical()`, so it never affects the signature.
    #[serde(default)]
    pub ver: u64,
}

impl Ioc {
    /// Stable de-dup key (kind + normalized value).
    fn key(&self) -> String {
        format!("{:?}:{}", self.kind, self.value.to_lowercase())
    }
}

/// A versioned, authenticated batch of IOCs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feed {
    pub version: u64,
    #[serde(default)]
    pub created: u64,
    pub iocs: Vec<Ioc>,
    /// Hex HMAC-SHA256 over the canonical form (set by [`Feed::sign`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Hex Ed25519 signature over the canonical form (set by
    /// [`Feed::sign_ed25519`]). Asymmetric: the private key never leaves the
    /// offline signer, so a compromised server/CDN cannot forge an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// The trusted Ed25519 **public** key (hex) that signs official AetherAV feeds.
/// Compiled into every client as a trust anchor - the matching private key is
/// kept offline. Verification against this key is what makes the update channel
/// tamper-proof even if the distribution server is fully compromised.
pub const TRUSTED_FEED_PUBKEY: &str =
    "b86706c6d0e93ac12f65acb58215bc322ca5fd6f42408a18ce4add591ce2e431";

/// Detached Ed25519 signature (hex) over arbitrary bytes - used to sign release
/// artifacts (e.g. a `SHA256SUMS` file) so users can verify a download wasn't
/// tampered with. Same offline private key, never on any server.
pub fn sign_detached(secret: &[u8; 32], data: &[u8]) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    hex::encode(SigningKey::from_bytes(secret).sign(data).to_bytes())
}

/// Derive the hex Ed25519 public key for a 32-byte secret seed. Used by clients
/// to advertise their per-device identity (the private seed never leaves them).
pub fn public_hex(secret: &[u8; 32]) -> String {
    use ed25519_dalek::SigningKey;
    hex::encode(SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

/// Verify a detached Ed25519 signature over `data` against a hex public key.
pub fn verify_detached(pubkey_hex: &str, data: &[u8], sig_hex: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let (Ok(pk), Ok(sig)) = (hex::decode(pubkey_hex), hex::decode(sig_hex)) else {
        return false;
    };
    let (Ok(pk), Ok(sig)) = (
        <[u8; 32]>::try_from(pk.as_slice()),
        <[u8; 64]>::try_from(sig.as_slice()),
    ) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify(data, &Signature::from_bytes(&sig)).is_ok()
}

impl Feed {
    pub fn new(version: u64, iocs: Vec<Ioc>) -> Feed {
        Feed {
            version,
            created: 0,
            iocs,
            mac: None,
            sig: None,
        }
    }

    /// Deterministic byte form used for the MAC (independent of map/array order
    /// and excluding the `mac` field itself).
    fn canonical(&self) -> Vec<u8> {
        let mut lines: Vec<String> = self
            .iocs
            .iter()
            .map(|i| format!("{:?}|{}|{}", i.kind, i.value.to_lowercase(), i.threat))
            .collect();
        lines.sort();
        format!("v{}\n{}", self.version, lines.join("\n")).into_bytes()
    }

    /// The legacy line-based signature format relies on unambiguous fields
    /// and unique normalized keys. Check the same invariants on all verifiers.
    fn valid_signed_fields(&self) -> bool {
        let mut keys = HashSet::with_capacity(self.iocs.len());
        self.iocs.iter().all(|ioc| {
            !ioc.value.is_empty()
                && !ioc.value.contains('|')
                && !ioc.value.chars().any(char::is_control)
                && !ioc.threat.chars().any(char::is_control)
                && keys.insert(ioc.key())
        })
    }

    /// Authenticate the feed with a shared key.
    pub fn sign(&mut self, key: &[u8]) {
        self.mac = Some(hex::encode(hmac::hmac_sha256(key, &self.canonical())));
    }

    /// Verify the feed's MAC. Returns `false` if unsigned or tampered.
    pub fn verify(&self, key: &[u8]) -> bool {
        if !self.valid_signed_fields() {
            return false;
        }
        match &self.mac {
            Some(mac_hex) => {
                let expected = hmac::hmac_sha256(key, &self.canonical());
                match hex::decode(mac_hex) {
                    Ok(got) => hmac::constant_time_eq(&got, &expected),
                    Err(_) => false,
                }
            }
            None => false,
        }
    }

    /// Sign the feed with an Ed25519 secret seed (32 bytes). Used only by the
    /// offline signer; the secret never ships with the client or the server.
    pub fn sign_ed25519(&mut self, secret: &[u8; 32]) {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(secret);
        let sig = sk.sign(&self.canonical());
        self.sig = Some(hex::encode(sig.to_bytes()));
    }

    /// Verify the Ed25519 signature against a public key. `false` if unsigned,
    /// malformed, or tampered.
    pub fn verify_ed25519(&self, pubkey_hex: &str) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if !self.valid_signed_fields() {
            return false;
        }
        let Some(sig_hex) = &self.sig else {
            return false;
        };
        let (Ok(pk_bytes), Ok(sig_bytes)) = (hex::decode(pubkey_hex), hex::decode(sig_hex)) else {
            return false;
        };
        let (Ok(pk_arr), Ok(sig_arr)) = (
            <[u8; 32]>::try_from(pk_bytes.as_slice()),
            <[u8; 64]>::try_from(sig_bytes.as_slice()),
        ) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
            return false;
        };
        vk.verify(&self.canonical(), &Signature::from_bytes(&sig_arr))
            .is_ok()
    }

    /// Verify against the compiled-in trusted feed key. This is the check that
    /// makes a forged/tampered update from a compromised server fail.
    pub fn verify_trusted(&self) -> bool {
        self.verify_ed25519(TRUSTED_FEED_PUBKEY)
    }

    pub fn from_json(text: &str) -> Result<Feed> {
        serde_json::from_str(text).map_err(|e| Error::Config(format!("feed parse: {e}")))
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Feed> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json(&text)
    }

    /// Import a MISP/VirusTotal-style export: a JSON array of `{type, value}`
    /// attribute objects. Unknown attribute types are skipped.
    pub fn from_misp_json(text: &str, version: u64, threat: &str) -> Result<Feed> {
        #[derive(Deserialize)]
        struct Attr {
            #[serde(rename = "type")]
            kind: String,
            value: String,
        }
        let attrs: Vec<Attr> =
            serde_json::from_str(text).map_err(|e| Error::Config(format!("misp parse: {e}")))?;
        let iocs = attrs
            .into_iter()
            .filter_map(|a| {
                let kind = match a.kind.as_str() {
                    "sha256" => IocKind::Sha256,
                    "md5" => IocKind::Md5,
                    "domain" | "hostname" => IocKind::Domain,
                    "ip-dst" | "ip-src" | "ip" => IocKind::Ipv4,
                    "url" => IocKind::Url,
                    _ => return None,
                };
                Some(Ioc {
                    ver: 0,
                    kind,
                    value: a.value,
                    threat: threat.to_string(),
                })
            })
            .collect();
        Ok(Feed::new(version, iocs))
    }

    /// Import the abuse.ch **ThreatFox** CSV export (recent or full). Comment
    /// lines (`#`) are ignored; each data row is quoted CSV with columns:
    /// `first_seen, ioc_id, ioc_value, ioc_type, threat_type, fk_malware,
    ///  malware_alias, malware_printable, …`.
    pub fn from_threatfox_csv(text: &str, version: u64) -> Result<Feed> {
        let mut iocs = Vec::new();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let f = split_csv(l);
            if f.len() < 4 {
                continue;
            }
            let raw_value = f[2].trim();
            let kind = match f[3].trim() {
                "sha256_hash" => IocKind::Sha256,
                "md5_hash" => IocKind::Md5,
                "domain" => IocKind::Domain,
                "ip:port" => IocKind::Ipv4,
                "url" => IocKind::Url,
                _ => continue,
            };
            // ip:port -> keep the IP; everything else verbatim.
            let value = if kind == IocKind::Ipv4 {
                raw_value.split(':').next().unwrap_or(raw_value).to_string()
            } else {
                raw_value.to_string()
            };
            let threat = f
                .get(7)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or("ThreatFox.IOC")
                .to_string();
            iocs.push(Ioc {
                ver: 0,
                kind,
                value,
                threat,
            });
        }
        Ok(Feed::new(version, iocs))
    }

    /// Import high-confidence SHA-256 indicators from the ThreatFox API.
    /// Network indicators require expiry and are intentionally kept out of
    /// this append-only refresh path.
    pub fn from_threatfox_json(text: &str, version: u64) -> Result<Feed> {
        #[derive(Deserialize)]
        struct Response {
            query_status: String,
            data: Option<Vec<Record>>,
        }

        #[derive(Deserialize)]
        struct Record {
            ioc: String,
            ioc_type: String,
            confidence_level: u8,
            malware_printable: Option<String>,
        }

        let response: Response = serde_json::from_str(text)
            .map_err(|e| Error::Config(format!("ThreatFox response: {e}")))?;
        if response.query_status != "ok" {
            return Err(Error::Config("ThreatFox query did not succeed".into()));
        }
        let records = response
            .data
            .ok_or_else(|| Error::Config("ThreatFox response missing records".into()))?;
        let mut best = BTreeMap::new();
        for record in records {
            if record.ioc_type != "sha256_hash" || !(75..=100).contains(&record.confidence_level) {
                continue;
            }
            let digest = record.ioc.trim().to_ascii_lowercase();
            if !valid_file_sha256(&digest) {
                continue;
            }
            let label = signature_label(record.malware_printable.as_deref(), "ThreatFox.Sample");
            let candidate = (!generic_hash_label(&label), record.confidence_level, label);
            let previous = best.entry(digest).or_insert_with(|| candidate.clone());
            if candidate > *previous {
                *previous = candidate;
            }
        }
        let iocs = best
            .into_iter()
            .map(|(value, (_, _, threat))| Ioc {
                ver: 0,
                kind: IocKind::Sha256,
                value,
                threat,
            })
            .collect();
        Ok(Feed::new(version, iocs))
    }

    /// Import the abuse.ch **URLhaus** CSV (malware-distribution URLs).
    /// Columns: `id, dateadded, url, url_status, last_online, threat, …`.
    pub fn from_urlhaus_csv(text: &str, version: u64) -> Result<Feed> {
        let mut iocs = Vec::new();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let f = split_csv(l);
            if f.len() < 6 || f[2].trim() == "url" {
                continue;
            }
            let threat = match f[5].trim() {
                "" => "URLhaus.Malware",
                t => t,
            };
            iocs.push(Ioc {
                ver: 0,
                kind: IocKind::Url,
                value: f[2].trim().to_string(),
                threat: threat.to_string(),
            });
        }
        Ok(Feed::new(version, iocs))
    }

    /// Import the abuse.ch **Feodo Tracker** IP blocklist CSV (botnet C2 IPs).
    /// Columns: `first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware`.
    pub fn from_feodo_csv(text: &str, version: u64) -> Result<Feed> {
        let mut iocs = Vec::new();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let f = split_csv(l);
            if f.len() < 6 || f[1].trim() == "dst_ip" {
                continue;
            }
            let threat = match f[5].trim() {
                "" => "Feodo.C2",
                t => t,
            };
            iocs.push(Ioc {
                ver: 0,
                kind: IocKind::Ipv4,
                value: f[1].trim().to_string(),
                threat: threat.to_string(),
            });
        }
        Ok(Feed::new(version, iocs))
    }

    /// Import the abuse.ch **MalwareBazaar** CSV export (recent or full dump).
    /// Columns: `first_seen, sha256_hash, md5_hash, sha1_hash, reporter,
    /// file_name, file_type, mime, signature, clamav, …`. The `signature`
    /// column carries the malware family (falls back to a generic label).
    pub fn from_malwarebazaar_csv(text: &str, version: u64) -> Result<Feed> {
        let mut entries = BTreeMap::new();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let f = split_csv(l);
            if f.len() < 2 {
                continue;
            }
            let sha = f[1].trim().to_lowercase();
            if !valid_file_sha256(&sha) {
                continue;
            }
            let threat = signature_label(f.get(8).map(String::as_str), "MalwareBazaar.Sample");
            let previous = entries.entry(sha).or_insert_with(|| threat.clone());
            if generic_hash_label(previous) && !generic_hash_label(&threat) {
                *previous = threat;
            }
        }
        let iocs = entries
            .into_iter()
            .map(|(value, threat)| Ioc {
                ver: 0,
                kind: IocKind::Sha256,
                value,
                threat,
            })
            .collect();
        Ok(Feed::new(version, iocs))
    }

    /// Import a plain SHA-256 hash list (one hash per line, `#` comments
    /// allowed, optional surrounding quotes) - e.g. the abuse.ch MalwareBazaar
    /// `export/txt/sha256/` feed.
    pub fn from_sha256_list(text: &str, version: u64, threat: &str) -> Result<Feed> {
        let mut seen = HashSet::new();
        let iocs = text
            .lines()
            .map(|l| l.trim().trim_matches('"').trim())
            .filter(|h| valid_file_sha256(h))
            .map(str::to_ascii_lowercase)
            .filter(|h| seen.insert(h.clone()))
            .map(|h| Ioc {
                ver: 0,
                kind: IocKind::Sha256,
                value: h,
                threat: threat.to_string(),
            })
            .collect();
        Ok(Feed::new(version, iocs))
    }

    /// Parse a plain text list of malicious IPv4 addresses or CIDRs (one per
    /// line; `#`/`;` comments and trailing fields ignored). Works with many free
    /// feeds: CINS Army, blocklist.de, ET Open compromised-ips, Spamhaus DROP.
    pub fn from_ipv4_list(text: &str, version: u64, threat: &str) -> Result<Feed> {
        let iocs = text
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
            .filter_map(|l| {
                let tok = l.split([' ', '\t', ',', ';']).next().unwrap_or("").trim();
                Self::looks_ipv4(tok).then(|| Ioc {
                    ver: 0,
                    kind: IocKind::Ipv4,
                    value: tok.to_string(),
                    threat: threat.to_string(),
                })
            })
            .collect();
        Ok(Feed::new(version, iocs))
    }

    /// Parse a plain text list of malicious domains (one per line).
    pub fn from_domain_list(text: &str, version: u64, threat: &str) -> Result<Feed> {
        let iocs = text
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| {
                let d = l
                    .split([' ', '\t', ','])
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('.');
                let ok = d.contains('.')
                    && !d.contains('/')
                    && !d.contains(' ')
                    && !Self::looks_ipv4(d)
                    && d.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
                ok.then(|| Ioc {
                    ver: 0,
                    kind: IocKind::Domain,
                    value: d.to_lowercase(),
                    threat: threat.to_string(),
                })
            })
            .collect();
        Ok(Feed::new(version, iocs))
    }

    /// True for an IPv4 dotted-quad, optionally with a `/nn` CIDR suffix.
    fn looks_ipv4(s: &str) -> bool {
        let ip = s.split('/').next().unwrap_or(s);
        let octets: Vec<&str> = ip.split('.').collect();
        octets.len() == 4
            && octets
                .iter()
                .all(|o| !o.is_empty() && o.parse::<u8>().is_ok())
    }
}

/// Split one CSV record into fields, honoring double-quoted values (which may
/// contain commas). Minimal RFC-4180-ish parser sufficient for abuse.ch feeds.
fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next(); // escaped quote ""
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// The live, merged set of indicators. Hot-reloadable: `apply` a new feed at
/// any time to update without restarting the engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelStore {
    pub version: u64,
    iocs: HashMap<String, Ioc>,
}

impl IntelStore {
    pub fn new() -> IntelStore {
        IntelStore::default()
    }

    pub fn load_or_new(path: impl AsRef<Path>) -> Result<IntelStore> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(IntelStore::default());
        }
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|e| Error::Config(format!("store parse: {e}")))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let io_error = |source| Error::Io {
            path: path.to_path_buf(),
            source,
        };
        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(io_error)?;
        let mut writer = std::io::BufWriter::new(tmp.as_file_mut());
        serde_json::to_writer(&mut writer, self)
            .map_err(|e| Error::Config(format!("store write: {e}")))?;
        writer.flush().map_err(io_error)?;
        drop(writer);
        if let Ok(meta) = std::fs::metadata(path) {
            tmp.as_file()
                .set_permissions(meta.permissions())
                .map_err(io_error)?;
        }
        tmp.as_file().sync_all().map_err(io_error)?;
        tmp.persist(path).map_err(|e| io_error(e.error))?;
        Ok(())
    }

    /// Merge a feed (delta update) into the store. If `key` is provided, the
    /// feed must verify against it or the update is rejected. Returns the number
    /// of indicators added/updated.
    pub fn apply(&mut self, feed: &Feed, key: Option<&[u8]>) -> Result<usize> {
        if let Some(k) = key {
            if !feed.verify(k) {
                return Err(Error::Config(
                    "feed signature verification failed - update rejected".into(),
                ));
            }
        }
        let mut changed = 0;
        for ioc in &feed.iocs {
            let k = ioc.key();
            let version = match self.iocs.get(&k) {
                Some(existing) if existing.threat == ioc.threat => {
                    // Duplicate entries count as applied without changing the delta stamp.
                    changed += 1;
                    continue;
                }
                Some(existing) if existing.ver > feed.version => continue,
                Some(existing)
                    if ioc.kind == IocKind::Sha256
                        && generic_hash_label(&ioc.threat)
                        && !generic_hash_label(&existing.threat) =>
                {
                    continue;
                }
                _ => feed.version,
            };
            let mut ioc = ioc.clone();
            ioc.ver = version;
            self.iocs.insert(k, ioc);
            changed += 1;
        }
        self.version = self.version.max(feed.version);
        tracing::info!(
            version = feed.version,
            added = changed,
            "intel update applied"
        );
        Ok(changed)
    }

    /// Apply a feed received over the network: it MUST carry a valid Ed25519
    /// signature from the trusted key, AND its version must be newer than what
    /// we already have (anti-rollback). This is the safe path for auto-update.
    pub fn apply_signed(&mut self, feed: &Feed) -> Result<usize> {
        self.apply_verified(feed, TRUSTED_FEED_PUBKEY)
    }

    fn apply_verified(&mut self, feed: &Feed, pubkey: &str) -> Result<usize> {
        if !feed.verify_ed25519(pubkey) {
            return Err(Error::Config(
                "untrusted feed signature - update rejected".into(),
            ));
        }
        if feed.version <= self.version {
            return Ok(0); // already up to date (or a rollback attempt)
        }
        self.apply(feed, None)
    }

    pub fn len(&self) -> usize {
        self.iocs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.iocs.is_empty()
    }

    /// Export the whole store as a (still unsigned) [`Feed`] at `version`, ready
    /// to be signed and published for clients to auto-pull.
    pub fn to_feed(&self, version: u64) -> Feed {
        Feed::new(version, self.iocs.values().cloned().collect())
    }

    /// Export only the indicators newer than `since` (a client's current version)
    /// as a delta feed stamped `version`. `since == 0` returns the full snapshot.
    /// The result is unsigned - the caller signs it before sending to clients.
    pub fn to_feed_since(&self, since: u64, version: u64) -> Feed {
        let iocs: Vec<Ioc> = if since == 0 {
            self.iocs.values().cloned().collect()
        } else {
            self.iocs
                .values()
                .filter(|i| i.ver > since)
                .cloned()
                .collect()
        };
        Feed::new(version, iocs)
    }

    /// Iterate over every stored indicator (e.g. to feed the firewall / web
    /// protection with malicious IPs and domains).
    pub fn iocs(&self) -> impl Iterator<Item = &Ioc> {
        self.iocs.values()
    }

    /// Look up a SHA-256 hex digest; returns the threat name on a hit.
    pub fn lookup_sha256(&self, sha256_hex: &str) -> Option<&str> {
        self.iocs
            .get(&format!("Sha256:{}", sha256_hex.to_lowercase()))
            .map(|i| i.threat.as_str())
    }

    fn lookup(&self, kind: IocKind, value: &str) -> Option<&str> {
        self.iocs
            .get(&format!("{:?}:{}", kind, value.to_lowercase()))
            .map(|i| i.threat.as_str())
    }

    /// Look up a URL (exact match).
    pub fn lookup_url(&self, url: &str) -> Option<&str> {
        self.lookup(IocKind::Url, url)
    }
    /// Look up a domain / host.
    pub fn lookup_domain(&self, domain: &str) -> Option<&str> {
        self.lookup(IocKind::Domain, domain)
    }
    /// Look up an IPv4 address.
    pub fn lookup_ip(&self, ip: &str) -> Option<&str> {
        self.lookup(IocKind::Ipv4, ip)
    }

    /// Count IOCs of a given kind.
    pub fn count_kind(&self, kind: IocKind) -> usize {
        self.iocs.values().filter(|i| i.kind == kind).count()
    }

    /// Export the SHA-256 indicators in the `aether-signatures` hash-DB format
    /// (`<sha256-hex> <threat>` per line), enabling hot signature reload.
    pub fn export_hashdb(&self) -> String {
        let mut lines: Vec<String> = self
            .iocs
            .values()
            .filter(|i| i.kind == IocKind::Sha256 && valid_file_sha256(&i.value))
            .map(|i| {
                let name = signature_label(Some(&i.threat), "Intel.Unknown");
                format!("{} {}", i.value.to_ascii_lowercase(), name)
            })
            .collect();
        lines.sort();
        lines.join("\n")
    }
}

fn valid_file_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|b| b.is_ascii_hexdigit())
        && !value.bytes().all(|b| b == b'0')
        && !value.eq_ignore_ascii_case(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
}

fn generic_hash_label(label: &str) -> bool {
    matches!(
        label.trim().to_ascii_lowercase().as_str(),
        "" | "-"
            | "unknown"
            | "n/a"
            | "malwarebazaar.sample"
            | "threatfox.sample"
            | "threatfox.ioc"
            | "intel.unknown"
            | "unknown.signature"
    )
}

fn signature_label(raw: Option<&str>, fallback: &str) -> String {
    let Some(raw) = raw
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("n/a"))
    else {
        return fallback.to_string();
    };
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).take(128).collect();
    if cleaned.trim().is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threatfox_json_requires_valid_high_confidence_file_indicators() {
        let hash = "a".repeat(64);
        let text = serde_json::json!({
            "query_status": "ok",
            "data": [
                {"ioc":hash, "ioc_type":"sha256_hash", "confidence_level":90, "malware_printable":"Family"},
                {"ioc":hash, "ioc_type":"sha256_hash", "confidence_level":90},
                {"ioc":"b".repeat(64), "ioc_type":"sha256_hash", "confidence_level":40},
                {"ioc":"8.8.8.8:443", "ioc_type":"ip:port", "confidence_level":99},
                {"ioc":"0".repeat(64), "ioc_type":"sha256_hash", "confidence_level":100}
            ]
        });
        let feed = Feed::from_threatfox_json(&text.to_string(), 1).unwrap();
        assert_eq!(feed.iocs.len(), 1);
        assert_eq!(feed.iocs[0].threat, "Family");
        assert!(Feed::from_threatfox_json(r#"{"query_status":"error"}"#, 1).is_err());
    }

    #[test]
    fn parses_ip_and_domain_lists() {
        let ips = "# CINS Army list\n1.2.3.4\n45.9.148.0/24 ; some note\nnot-an-ip\n10.0.0.256\n";
        let f = Feed::from_ipv4_list(ips, 1, "badip").unwrap();
        let vals: Vec<&str> = f.iocs.iter().map(|i| i.value.as_str()).collect();
        assert!(vals.contains(&"1.2.3.4"));
        assert!(vals.contains(&"45.9.148.0/24"));
        assert!(!vals.iter().any(|v| v.contains("256"))); // 256 is not a valid octet
        assert!(f.iocs.iter().all(|i| i.kind == IocKind::Ipv4));

        let doms = "evil-domain.com\nphish.example.org\n1.2.3.4\nhttp://x/y\n";
        let d = Feed::from_domain_list(doms, 1, "baddom").unwrap();
        let dv: Vec<&str> = d.iocs.iter().map(|i| i.value.as_str()).collect();
        assert!(dv.contains(&"evil-domain.com"));
        assert!(dv.contains(&"phish.example.org"));
        assert!(!dv.contains(&"1.2.3.4")); // IPs excluded from domain list
        assert!(d.iocs.iter().all(|i| i.kind == IocKind::Domain));
    }

    fn sample_feed(version: u64) -> Feed {
        Feed::new(
            version,
            vec![
                Ioc {
                    ver: 0,
                    kind: IocKind::Sha256,
                    value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                        .into(),
                    threat: "Test.EICAR".into(),
                },
                Ioc {
                    ver: 0,
                    kind: IocKind::Domain,
                    value: "evil.example".into(),
                    threat: "C2.Generic".into(),
                },
            ],
        )
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = b"super-secret-feed-key";
        let mut feed = sample_feed(1);
        feed.sign(key);
        assert!(feed.verify(key));
        assert!(!feed.verify(b"wrong-key"));
    }

    #[test]
    fn ed25519_trust_anchor_blocks_forgery() {
        // The offline private seed matching the compiled-in TRUSTED_FEED_PUBKEY.
        let secret: [u8; 32] = <[u8; 32]>::try_from(
            hex::decode("c340607787b2a92e926beb498c08fb07f974d06fb180cee3264b320d7dcaf276")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let mut feed = sample_feed(1);
        feed.sign_ed25519(&secret);
        // A correctly signed feed passes the client's trust check.
        assert!(feed.verify_trusted());

        // Tampering with the payload after signing -> rejected.
        let mut tampered = feed.clone();
        tampered.iocs[0].value = "attacker-injected.example".into();
        assert!(!tampered.verify_trusted(), "tampered feed must be rejected");

        // An attacker who controls the server but lacks the private key cannot
        // produce a signature that verifies against the trusted public key.
        let attacker_seed = [7u8; 32];
        let mut forged = sample_feed(2);
        forged.sign_ed25519(&attacker_seed);
        assert!(!forged.verify_trusted(), "forged-key feed must be rejected");

        // An unsigned feed is not trusted.
        assert!(!sample_feed(3).verify_trusted());
    }

    #[test]
    fn apply_signed_enforces_trust_and_anti_rollback() {
        let secret: [u8; 32] = <[u8; 32]>::try_from(
            hex::decode("c340607787b2a92e926beb498c08fb07f974d06fb180cee3264b320d7dcaf276")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let mut store = IntelStore::default();

        // Unsigned feed -> rejected.
        assert!(store.apply_signed(&sample_feed(5)).is_err());

        // Properly signed v5 -> applied.
        let mut f5 = sample_feed(5);
        f5.sign_ed25519(&secret);
        assert!(store.apply_signed(&f5).unwrap() > 0);
        assert_eq!(store.version, 5);

        // Rollback to v3 (validly signed) -> no-op, version stays 5.
        let mut f3 = sample_feed(3);
        f3.sign_ed25519(&secret);
        assert_eq!(store.apply_signed(&f3).unwrap(), 0);
        assert_eq!(store.version, 5);

        // Newer v6 -> applied.
        let mut f6 = sample_feed(6);
        f6.sign_ed25519(&secret);
        assert!(store.apply_signed(&f6).unwrap() > 0);
        assert_eq!(store.version, 6);
    }

    #[test]
    fn detached_release_signature() {
        let secret: [u8; 32] = <[u8; 32]>::try_from(
            hex::decode("c340607787b2a92e926beb498c08fb07f974d06fb180cee3264b320d7dcaf276")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let data = b"SHA256SUMS: deadbeef  aether\n";
        let sig = sign_detached(&secret, data);
        assert!(verify_detached(TRUSTED_FEED_PUBKEY, data, &sig));
        assert!(!verify_detached(TRUSTED_FEED_PUBKEY, b"tampered", &sig));
    }

    #[test]
    fn tampering_invalidates_mac() {
        let key = b"k";
        let mut feed = sample_feed(1);
        feed.sign(key);
        // Mutate an IOC after signing.
        feed.iocs[0].threat = "Totally.Benign".into();
        assert!(!feed.verify(key), "tampered feed must fail verification");
    }

    #[test]
    fn delta_updates_merge_and_bump_version() {
        let mut store = IntelStore::new();
        store.apply(&sample_feed(1), None).unwrap();
        assert_eq!(store.version, 1);
        assert_eq!(
            store.lookup_sha256("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"),
            Some("Test.EICAR")
        );

        // A v2 delta adds one new hash.
        let delta = Feed::new(
            2,
            vec![Ioc {
                ver: 0,
                kind: IocKind::Sha256,
                value: "ab".repeat(32),
                threat: "Mal.New".into(),
            }],
        );
        store.apply(&delta, None).unwrap();
        assert_eq!(store.version, 2);
        assert_eq!(store.count_kind(IocKind::Sha256), 2);
    }

    #[test]
    fn signed_update_rejected_with_bad_key() {
        let mut store = IntelStore::new();
        let mut feed = sample_feed(1);
        feed.sign(b"correct");
        assert!(store.apply(&feed, Some(b"attacker")).is_err());
        assert!(store.apply(&feed, Some(b"correct")).is_ok());
    }

    #[test]
    fn exports_hashdb_format() {
        let mut store = IntelStore::new();
        store.apply(&sample_feed(1), None).unwrap();
        let db = store.export_hashdb();
        assert!(db.contains(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f Test.EICAR"
        ));
        // Only sha256 IOCs are exported (the domain is excluded).
        assert_eq!(db.lines().count(), 1);
    }

    #[test]
    fn imports_threatfox_csv() {
        let csv = "# comment\n\
\"2026-06-18 10:00:00\",\"123\",\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"sha256_hash\",\"payload\",\"win.cobalt_strike\",\"\",\"CobaltStrike\",\"2026-06-18\",\"75\",\"ref\",\"tag1,tag2\",\"0\",\"reporter\"\n\
\"2026-06-18 10:01:00\",\"124\",\"45.9.1.2:443\",\"ip:port\",\"c2\",\"win.x\",\"\",\"Emotet\",\"\",\"100\",\"\",\"\",\"0\",\"r\"\n\
\"2026-06-18 10:02:00\",\"125\",\"bad.example\",\"domain\",\"c2\",\"win.y\",\"\",\"Qakbot\",\"\",\"90\",\"\",\"\",\"0\",\"r\"";
        let feed = Feed::from_threatfox_csv(csv, 7).unwrap();
        assert_eq!(feed.iocs.len(), 3);
        assert_eq!(feed.version, 7);
        // ip:port is reduced to the bare IP.
        assert!(feed
            .iocs
            .iter()
            .any(|i| i.kind == IocKind::Ipv4 && i.value == "45.9.1.2"));
        assert!(feed
            .iocs
            .iter()
            .any(|i| i.kind == IocKind::Sha256 && i.threat == "CobaltStrike"));
    }

    #[test]
    fn imports_urlhaus_and_feodo() {
        let uh = "# id,dateadded,url,url_status,last_online,threat,tags,link,reporter\n\
\"1\",\"2026-06-18\",\"http://bad.host/x.bin\",\"online\",\"\",\"malware_download\",\"elf\",\"l\",\"r\"";
        let f = Feed::from_urlhaus_csv(uh, 1).unwrap();
        assert_eq!(f.iocs.len(), 1);
        assert_eq!(f.iocs[0].kind, IocKind::Url);
        assert_eq!(f.iocs[0].value, "http://bad.host/x.bin");

        let fe = "\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n\
\"2026-06-18\",\"45.9.1.2\",\"443\",\"online\",\"\",\"Emotet\"";
        let g = Feed::from_feodo_csv(fe, 1).unwrap();
        assert_eq!(g.iocs.len(), 1); // header row skipped
        assert_eq!(g.iocs[0].kind, IocKind::Ipv4);
        assert_eq!(g.iocs[0].threat, "Emotet");
    }

    #[test]
    fn imports_sha256_list() {
        let txt = "# MalwareBazaar\n\
\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n\
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n\
not-a-hash\n";
        let feed = Feed::from_sha256_list(txt, 1, "MalwareBazaar.Sample").unwrap();
        assert_eq!(feed.iocs.len(), 1);
        assert!(feed
            .iocs
            .iter()
            .all(|i| i.kind == IocKind::Sha256 && i.value.len() == 64));
    }

    #[test]
    fn imports_misp_export() {
        let json = r#"[
            {"type":"sha256","value":"DEADBEEF","category":"Payload"},
            {"type":"domain","value":"bad.example"},
            {"type":"comment","value":"ignore me"}
        ]"#;
        let feed = Feed::from_misp_json(json, 5, "APT.Demo").unwrap();
        assert_eq!(feed.iocs.len(), 2); // comment skipped
        assert_eq!(feed.version, 5);
        assert!(feed.iocs.iter().all(|i| i.threat == "APT.Demo"));
    }

    #[test]
    fn ed25519_rejects_modified_and_ambiguous_feeds() {
        let seed = [42; 32];
        let key = public_hex(&seed);
        let mut feed = sample_feed(1);
        feed.sign_ed25519(&seed);
        assert!(feed.verify_ed25519(&key));
        feed.iocs[0].threat.push_str(" changed");
        assert!(!feed.verify_ed25519(&key));

        feed.iocs[0].threat = "invalid\nlabel".into();
        feed.sign_ed25519(&seed);
        assert!(!feed.verify_ed25519(&key));

        let mut feed = sample_feed(1);
        feed.iocs.push(feed.iocs[0].clone());
        feed.sign_ed25519(&seed);
        assert!(!feed.verify_ed25519(&key));
    }

    #[test]
    fn signed_deltas_preserve_rollback_protection_and_publish_label_changes() {
        let seed = [42; 32];
        let key = public_hex(&seed);
        let mut store = IntelStore::new();
        let mut feed = sample_feed(5);
        assert!(store.apply_verified(&feed, &key).is_err());
        feed.sign_ed25519(&seed);
        assert_eq!(store.apply_verified(&feed, &key).unwrap(), 2);
        assert_eq!(store.apply_verified(&feed, &key).unwrap(), 0);

        let mut feed = sample_feed(6);
        feed.iocs[0].threat = "Updated family".into();
        feed.sign_ed25519(&seed);
        assert_eq!(store.apply_verified(&feed, &key).unwrap(), 2);
        assert_eq!(store.version, 6);
        assert_eq!(store.to_feed_since(5, 6).iocs.len(), 1);
    }
    #[test]
    fn generic_hash_update_keeps_known_family() {
        let digest = "b".repeat(64);
        let mut store = IntelStore::new();
        let known = Feed::from_sha256_list(&digest, 1, "Known.Family").unwrap();
        let generic = Feed::from_sha256_list(&digest, 2, "MalwareBazaar.Sample").unwrap();
        store.apply(&known, None).unwrap();
        store.apply(&generic, None).unwrap();
        assert_eq!(store.lookup_sha256(&digest), Some("Known.Family"));
        assert!(store.to_feed_since(1, 2).iocs.is_empty());
    }
}
