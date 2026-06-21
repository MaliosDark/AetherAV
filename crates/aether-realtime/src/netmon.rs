//! Real-time network monitor: enumerate the host's TCP connections/listeners
//! and flag any that use ports strongly associated with malware (RATs, C2
//! frameworks, classic backdoors).
//!
//! Connections are read from `/proc/net/tcp` + `/proc/net/tcp6` on Linux (no
//! root needed). The malicious-port table is a curated, factual reference of
//! well-known RAT/C2/backdoor default ports - a high-signal heuristic, since
//! seeing one of these in use on a host is rarely legitimate.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Severity of a port association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSeverity {
    High,
    Medium,
}

impl PortSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            PortSeverity::High => "high",
            PortSeverity::Medium => "medium",
        }
    }
}

/// Curated table of ports linked to malware families / offensive tooling.
/// (Factual reference of well-known default ports - not exhaustive; encrypted
/// C2 increasingly hides on 80/443, so this is one signal among many.)
pub const MALICIOUS_PORTS: &[(u16, &str, PortSeverity)] = &[
    (1170, "Streaming Audio Trojan", PortSeverity::Medium),
    (1337, "leet / generic backdoor", PortSeverity::Medium),
    (1604, "DarkComet RAT", PortSeverity::High),
    (2222, "common backdoor/SSH-alt", PortSeverity::Medium),
    (3127, "MyDoom worm", PortSeverity::High),
    (3128, "abused proxy (malware)", PortSeverity::Medium),
    (4444, "Metasploit/Meterpreter default", PortSeverity::High),
    (4445, "Metasploit alt", PortSeverity::High),
    (4782, "Quasar RAT", PortSeverity::High),
    (5000, "common RAT/C2 default", PortSeverity::Medium),
    (5552, "backdoor", PortSeverity::Medium),
    (6666, "IRC botnet C2", PortSeverity::High),
    (6667, "IRC botnet C2", PortSeverity::High),
    (6697, "IRC (TLS) botnet C2", PortSeverity::Medium),
    (6969, "backdoor / worm", PortSeverity::Medium),
    (7777, "Tini / generic backdoor", PortSeverity::Medium),
    (8080, "abused proxy / C2", PortSeverity::Medium),
    (9001, "Tor / C2", PortSeverity::Medium),
    (9999, "backdoor", PortSeverity::Medium),
    (12345, "NetBus", PortSeverity::High),
    (12346, "NetBus", PortSeverity::High),
    (16959, "SubSeven", PortSeverity::High),
    (20034, "NetBus 2 Pro", PortSeverity::High),
    (27374, "SubSeven", PortSeverity::High),
    (31337, "Back Orifice", PortSeverity::High),
    (31338, "Back Orifice / DeepThroat", PortSeverity::High),
    (40421, "Masters Paradise", PortSeverity::Medium),
    (
        50050,
        "Cobalt Strike (default team server)",
        PortSeverity::High,
    ),
    (53531, "dnscat2 default", PortSeverity::High),
    (54320, "Back Orifice 2000", PortSeverity::High),
    (54321, "Back Orifice 2000", PortSeverity::High),
    (57230, "Covenant C2 default", PortSeverity::High),
    (65000, "Devil RAT", PortSeverity::Medium),
];

/// Look up a port in the malicious table.
pub fn lookup_port(port: u16) -> Option<(&'static str, PortSeverity)> {
    MALICIOUS_PORTS
        .iter()
        .find(|(p, _, _)| *p == port)
        .map(|(_, name, sev)| (*name, *sev))
}

/// A single TCP connection / listener.
#[derive(Debug, Clone)]
pub struct Connection {
    pub proto: &'static str, // "tcp" | "tcp6"
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: &'static str,
}

impl Connection {
    /// The suspicious port for this connection, if any (remote first, then a
    /// local listener on a known-bad port).
    pub fn flagged(&self) -> Option<(u16, &'static str, PortSeverity)> {
        if let Some((n, s)) = lookup_port(self.remote_port) {
            return Some((self.remote_port, n, s));
        }
        if self.state == "LISTEN" {
            if let Some((n, s)) = lookup_port(self.local_port) {
                return Some((self.local_port, n, s));
            }
        }
        None
    }
}

fn tcp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "06" => "TIME_WAIT",
        "08" => "CLOSE_WAIT",
        "0A" => "LISTEN",
        _ => "OTHER",
    }
}

/// Parse a `/proc/net/tcp` "addr:port" hex field into (ip, port).
fn parse_endpoint(field: &str, v6: bool) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if v6 {
        if addr_hex.len() != 32 {
            return None;
        }
        let mut segs = [0u16; 8];
        // /proc stores IPv6 as four little-endian 32-bit words.
        for w in 0..4 {
            let word = &addr_hex[w * 8..w * 8 + 8];
            let le = u32::from_str_radix(word, 16).ok()?.to_be(); // correct word order
            segs[w * 2] = (le >> 16) as u16;
            segs[w * 2 + 1] = (le & 0xffff) as u16;
        }
        Ipv6Addr::new(
            segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
        )
        .to_string()
    } else {
        if addr_hex.len() != 8 {
            return None;
        }
        let v = u32::from_str_radix(addr_hex, 16).ok()?;
        // Stored little-endian: reverse the bytes for dotted-quad.
        Ipv4Addr::from(v.swap_bytes()).to_string()
    };
    Some((ip, port))
}

/// Split a `ip:port` endpoint (Windows netstat; handles `[v6]:port`).
fn split_colon_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    let idx = s.rfind(':')?;
    let (addr, port) = (&s[..idx], &s[idx + 1..]);
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    Some((addr.to_string(), port.parse().ok()?))
}

/// Split a `ip.port` endpoint (BSD/macOS netstat: `192.168.1.5.443`, `*.*`).
fn split_dot_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    let idx = s.rfind('.')?;
    let (addr, port) = (&s[..idx], &s[idx + 1..]);
    let port = if port == "*" { 0 } else { port.parse().ok()? };
    Some((addr.replace('*', "0.0.0.0"), port))
}

fn norm_state(s: &str) -> &'static str {
    match s.trim().to_ascii_uppercase().as_str() {
        "LISTENING" | "LISTEN" => "LISTEN",
        "ESTABLISHED" => "ESTABLISHED",
        "TIME_WAIT" => "TIME_WAIT",
        "CLOSE_WAIT" => "CLOSE_WAIT",
        "SYN_SENT" => "SYN_SENT",
        _ => "OTHER",
    }
}

/// Parse Windows `netstat -ano -p tcp` output.
pub fn parse_netstat_windows(text: &str) -> Vec<Connection> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || !f[0].eq_ignore_ascii_case("tcp") {
            continue;
        }
        if let (Some((la, lp)), Some((ra, rp))) = (split_colon_port(f[1]), split_colon_port(f[2])) {
            out.push(Connection {
                proto: "tcp",
                local_addr: la,
                local_port: lp,
                remote_addr: ra,
                remote_port: rp,
                state: norm_state(f[3]),
            });
        }
    }
    out
}

/// Parse BSD/macOS `netstat -an -p tcp` output.
pub fn parse_netstat_bsd(text: &str) -> Vec<Connection> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || !f[0].starts_with("tcp") {
            continue;
        }
        if let (Some((la, lp)), Some((ra, rp))) = (split_dot_port(f[3]), split_dot_port(f[4])) {
            out.push(Connection {
                proto: "tcp",
                local_addr: la,
                local_port: lp,
                remote_addr: ra,
                remote_port: rp,
                state: norm_state(f[5]),
            });
        }
    }
    out
}

/// Enumerate the host's TCP connections.
/// Linux reads `/proc/net`; Windows/macOS shell out to `netstat`.
pub fn connections() -> Vec<Connection> {
    #[cfg(target_os = "windows")]
    {
        return aether_common::quiet_command("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()
            .ok()
            .map(|o| parse_netstat_windows(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
    }
    #[cfg(target_os = "macos")]
    {
        return std::process::Command::new("netstat")
            .args(["-an", "-p", "tcp"])
            .output()
            .ok()
            .map(|o| parse_netstat_bsd(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
    }

    let mut out = Vec::new();
    #[cfg(target_os = "linux")]
    {
        for (path, proto, v6) in [
            ("/proc/net/tcp", "tcp", false),
            ("/proc/net/tcp6", "tcp6", true),
        ] {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for line in text.lines().skip(1) {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 4 {
                    continue;
                }
                let (Some((la, lp)), Some((ra, rp))) =
                    (parse_endpoint(f[1], v6), parse_endpoint(f[2], v6))
                else {
                    continue;
                };
                out.push(Connection {
                    proto,
                    local_addr: la,
                    local_port: lp,
                    remote_addr: ra,
                    remote_port: rp,
                    state: tcp_state(f[3]),
                });
            }
        }
    }
    out
}

/// Reverse-resolve an IP to a hostname (PTR / getnameinfo). Best-effort; the
/// OS resolver may block briefly, so callers should bound how many they run.
pub fn reverse_dns(ip: &str) -> Option<String> {
    let addr: std::net::IpAddr = ip.parse().ok()?;
    dns_lookup::lookup_addr(&addr)
        .ok()
        .filter(|h| h != ip && !h.is_empty())
}

/// Reverse-resolve up to `max` IPs concurrently, returning the ones that
/// answer within `deadline`. Concurrency + a global deadline keep this fast
/// and non-blocking even when some PTR lookups hang on the OS resolver.
pub fn resolve_hosts(
    ips: &[String],
    max: usize,
    deadline: std::time::Duration,
) -> std::collections::HashMap<String, String> {
    use std::sync::mpsc::channel;
    let (tx, rx) = channel();
    let n = ips.len().min(max);
    for ip in ips.iter().take(n).cloned() {
        let tx = tx.clone();
        // Detached worker; if it overruns the deadline we simply ignore it.
        std::thread::spawn(move || {
            let host = reverse_dns(&ip);
            let _ = tx.send((ip, host));
        });
    }
    drop(tx);

    let mut map = std::collections::HashMap::new();
    let end = std::time::Instant::now() + deadline;
    for _ in 0..n {
        let remaining = end.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok((ip, Some(host))) => {
                map.insert(ip, host);
            }
            Ok((_, None)) => {}
            Err(_) => break,
        }
    }
    map
}

/// Domain match-candidates for a hostname: the full name plus each parent
/// domain down to the registrable label, e.g. `a.b.evil.com` ->
/// `["a.b.evil.com", "b.evil.com", "evil.com"]`. Lets an IOC for `evil.com`
/// match a subdomain a connection resolved to.
pub fn domain_candidates(host: &str) -> Vec<String> {
    let host = host.trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let mut out = Vec::new();
    // Generate suffixes with >= 2 labels (skip bare TLDs).
    for i in 0..labels.len().saturating_sub(1) {
        out.push(labels[i..].join("."));
    }
    out
}

/// All connections whose port matches the malicious table.
pub fn flagged_connections() -> Vec<(Connection, u16, &'static str, PortSeverity)> {
    connections()
        .into_iter()
        .filter_map(|c| c.flagged().map(|(p, n, s)| (c, p, n, s)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_bad_ports_flagged() {
        assert!(lookup_port(4444).is_some()); // meterpreter
        assert!(lookup_port(31337).is_some()); // back orifice
        assert!(lookup_port(50050).is_some()); // cobalt strike
        assert!(lookup_port(443).is_none()); // legit https
    }

    #[test]
    fn parses_ipv4_endpoint() {
        // 0100007F:1538 -> 127.0.0.1:5432
        let (ip, port) = parse_endpoint("0100007F:1538", false).unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 0x1538);
    }

    #[test]
    fn parses_windows_netstat() {
        let text = "\
Active Connections
  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.5:50111      52.1.2.3:443           ESTABLISHED     1234
  TCP    0.0.0.0:4444           0.0.0.0:0              LISTENING       4
";
        let c = parse_netstat_windows(text);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].remote_port, 443);
        assert_eq!(c[1].local_port, 4444);
        assert_eq!(c[1].state, "LISTEN");
        assert_eq!(c[1].flagged().map(|f| f.0), Some(4444)); // meterpreter listener
    }

    #[test]
    fn parses_macos_netstat() {
        let text = "\
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.5.50111      45.9.1.2.31337         ESTABLISHED
tcp4       0      0  *.22                   *.*                    LISTEN
";
        let c = parse_netstat_bsd(text);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].remote_addr, "45.9.1.2");
        assert_eq!(c[0].remote_port, 31337);
        assert_eq!(c[0].flagged().map(|f| f.0), Some(31337)); // back orifice
    }

    #[test]
    fn domain_candidates_walk_parents() {
        assert_eq!(
            domain_candidates("a.b.evil.com"),
            vec!["a.b.evil.com", "b.evil.com", "evil.com"]
        );
        assert_eq!(domain_candidates("evil.example"), vec!["evil.example"]);
        assert!(domain_candidates("localhost").is_empty());
    }

    #[test]
    fn connection_flags_malicious_remote() {
        let c = Connection {
            proto: "tcp",
            local_addr: "10.0.0.5".into(),
            local_port: 50101,
            remote_addr: "45.9.1.2".into(),
            remote_port: 4444,
            state: "ESTABLISHED",
        };
        assert_eq!(c.flagged().map(|f| f.0), Some(4444));
    }
}
