//! AetherAV firewall + web protection.
//!
//! Rather than ship a per-OS kernel module, AetherAV drives each operating
//! system's OWN native firewall from our threat intelligence:
//!
//!   * Linux   -> nftables          (`nft -f`)
//!   * Windows -> Windows Firewall  (`netsh advfirewall`)
//!   * macOS   -> packet filter     (`pfctl`)
//!
//! The rule *rendering* is pure, deterministic and unit-tested on any platform;
//! only `install()` shells out to the native tool (which needs admin/root).
//!
//! Web/phishing protection uses a portable hosts-file blocklist (module [`web`])
//! so malicious domains resolve to a dead address - locally, with no cloud.

use std::fmt::Write as _;

pub mod web;

/// Allow or block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

/// Transport protocol a port rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Any,
}

/// Target operating system for rule rendering / installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
    Macos,
}

impl Platform {
    /// The platform this binary is running on (best effort).
    pub fn current() -> Platform {
        if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::Macos
        } else {
            Platform::Linux
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Windows => "windows",
            Platform::Macos => "macos",
        }
    }

    pub fn parse(s: &str) -> Option<Platform> {
        match s.to_lowercase().as_str() {
            "linux" | "nftables" | "nft" => Some(Platform::Linux),
            "windows" | "win" | "netsh" => Some(Platform::Windows),
            "macos" | "mac" | "osx" | "pf" => Some(Platform::Macos),
            _ => None,
        }
    }
}

fn is_ipv6(addr: &str) -> bool {
    addr.contains(':')
}

/// A threat-driven firewall policy: a block-list over a permissive default.
///
/// We never flip the default policy to "deny everything" (that would break the
/// machine); we only DROP traffic to/from indicators our intelligence flags.
#[derive(Debug, Default, Clone)]
pub struct RuleSet {
    /// Malicious destination IPs (v4 or v6) to block outbound.
    pub bad_ips: Vec<String>,
    /// Malicious ports (RAT/C2/backdoor) to block, with a short label.
    pub bad_ports: Vec<(u16, String)>,
    /// Optional human note rendered as a header comment.
    pub note: String,
}

impl RuleSet {
    pub fn new() -> RuleSet {
        RuleSet::default()
    }

    pub fn block_ip(&mut self, ip: impl Into<String>) -> &mut Self {
        let ip = ip.into();
        if !ip.is_empty() && !self.bad_ips.contains(&ip) {
            self.bad_ips.push(ip);
        }
        self
    }

    pub fn block_port(&mut self, port: u16, label: impl Into<String>) -> &mut Self {
        if !self.bad_ports.iter().any(|(p, _)| *p == port) {
            self.bad_ports.push((port, label.into()));
        }
        self
    }

    pub fn is_empty(&self) -> bool {
        self.bad_ips.is_empty() && self.bad_ports.is_empty()
    }

    fn ip4(&self) -> Vec<&str> {
        self.bad_ips
            .iter()
            .map(String::as_str)
            .filter(|a| !is_ipv6(a))
            .collect()
    }
    fn ip6(&self) -> Vec<&str> {
        self.bad_ips
            .iter()
            .map(String::as_str)
            .filter(|a| is_ipv6(a))
            .collect()
    }
    fn ports(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self.bad_ports.iter().map(|(p, _)| *p).collect();
        v.sort_unstable();
        v
    }

    /// Render the ruleset in the chosen platform's native firewall syntax.
    pub fn render(&self, p: Platform) -> String {
        match p {
            Platform::Linux => self.render_nftables(),
            Platform::Windows => self.render_netsh(),
            Platform::Macos => self.render_pf(),
        }
    }

    /// Linux nftables script (`nft -f -`).
    pub fn render_nftables(&self) -> String {
        let mut s = String::new();
        s.push_str("#!/usr/sbin/nft -f\n");
        s.push_str("# AetherAV threat firewall - generated, do not edit by hand.\n");
        if !self.note.is_empty() {
            let _ = writeln!(s, "# {}", self.note);
        }
        // Recreate the table cleanly each load.
        s.push_str("add table inet aetherav\n");
        s.push_str("delete table inet aetherav\n");
        s.push_str("table inet aetherav {\n");

        let (ip4, ip6, ports) = (self.ip4(), self.ip6(), self.ports());
        if !ip4.is_empty() {
            let _ = writeln!(
                s,
                "    set bad_ip4 {{ type ipv4_addr; flags interval; elements = {{ {} }} }}",
                ip4.join(", ")
            );
        }
        if !ip6.is_empty() {
            let _ = writeln!(
                s,
                "    set bad_ip6 {{ type ipv6_addr; flags interval; elements = {{ {} }} }}",
                ip6.join(", ")
            );
        }
        if !ports.is_empty() {
            let plist = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                s,
                "    set bad_ports {{ type inet_service; elements = {{ {plist} }} }}"
            );
        }

        s.push_str("    chain output {\n");
        s.push_str("        type filter hook output priority 0; policy accept;\n");
        if !ip4.is_empty() {
            s.push_str("        ip daddr @bad_ip4 drop\n");
        }
        if !ip6.is_empty() {
            s.push_str("        ip6 daddr @bad_ip6 drop\n");
        }
        if !ports.is_empty() {
            s.push_str("        tcp dport @bad_ports drop\n");
            s.push_str("        udp dport @bad_ports drop\n");
        }
        s.push_str("    }\n");

        if !ports.is_empty() {
            s.push_str("    chain input {\n");
            s.push_str("        type filter hook input priority 0; policy accept;\n");
            s.push_str("        tcp sport @bad_ports drop\n");
            s.push_str("    }\n");
        }
        s.push_str("}\n");
        s
    }

    /// Windows Firewall script (`netsh advfirewall`, run as Administrator).
    pub fn render_netsh(&self) -> String {
        let mut s = String::new();
        s.push_str(":: AetherAV threat firewall - run this as Administrator.\n");
        if !self.note.is_empty() {
            let _ = writeln!(s, ":: {}", self.note);
        }
        // Clean previous AetherAV rules first (ignore "not found").
        s.push_str("netsh advfirewall firewall delete rule name=\"AetherAV-block-ip\" >nul 2>&1\n");
        s.push_str(
            "netsh advfirewall firewall delete rule name=\"AetherAV-block-port\" >nul 2>&1\n",
        );

        if !self.bad_ips.is_empty() {
            let _ = writeln!(
                s,
                "netsh advfirewall firewall add rule name=\"AetherAV-block-ip\" dir=out action=block remoteip={}",
                self.bad_ips.join(",")
            );
        }
        let ports = self.ports();
        if !ports.is_empty() {
            let plist = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let _ = writeln!(
                s,
                "netsh advfirewall firewall add rule name=\"AetherAV-block-port\" dir=out action=block protocol=TCP remoteport={plist}"
            );
        }
        s
    }

    /// macOS pf anchor (`pfctl -a aetherav -f - ; pfctl -e`).
    pub fn render_pf(&self) -> String {
        let mut s = String::new();
        s.push_str("# AetherAV threat firewall (pf).\n");
        s.push_str("# load:  pfctl -a aetherav -f <this-file>  &&  pfctl -e\n");
        if !self.note.is_empty() {
            let _ = writeln!(s, "# {}", self.note);
        }
        if !self.bad_ips.is_empty() {
            let _ = writeln!(
                s,
                "table <aetherav_bad> persist {{ {} }}",
                self.bad_ips.join(", ")
            );
            s.push_str("block drop out quick to <aetherav_bad>\n");
        }
        let ports = self.ports();
        if !ports.is_empty() {
            let plist = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                s,
                "block drop out quick proto {{ tcp udp }} to any port {{ {plist} }}"
            );
            let _ = writeln!(
                s,
                "block drop in quick proto tcp from any port {{ {plist} }}"
            );
        }
        s
    }

    /// Install the ruleset into the host's native firewall. Needs admin/root.
    ///
    /// Returns a short human summary on success, or an error (commonly a
    /// permission error when not run elevated).
    pub fn install(&self, p: Platform) -> std::io::Result<String> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let script = self.render(p);
        match p {
            Platform::Linux => {
                let mut c = Command::new("nft")
                    .arg("-f")
                    .arg("-")
                    .stdin(Stdio::piped())
                    .spawn()?;
                c.stdin.take().unwrap().write_all(script.as_bytes())?;
                let st = c.wait()?;
                if st.success() {
                    Ok(format!(
                        "nftables: {} IPs, {} ports blocked",
                        self.bad_ips.len(),
                        self.bad_ports.len()
                    ))
                } else {
                    Err(std::io::Error::other(
                        "nft exited non-zero (need root / CAP_NET_ADMIN?)",
                    ))
                }
            }
            Platform::Macos => {
                let mut c = Command::new("pfctl")
                    .args(["-a", "aetherav", "-f", "-"])
                    .stdin(Stdio::piped())
                    .spawn()?;
                c.stdin.take().unwrap().write_all(script.as_bytes())?;
                let st = c.wait()?;
                let _ = Command::new("pfctl").arg("-e").status();
                if st.success() {
                    Ok(format!(
                        "pf: {} IPs, {} ports blocked",
                        self.bad_ips.len(),
                        self.bad_ports.len()
                    ))
                } else {
                    Err(std::io::Error::other("pfctl failed (need sudo?)"))
                }
            }
            Platform::Windows => {
                // Each non-empty, non-comment line is a netsh command.
                let mut applied = 0;
                for line in script.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with("::") {
                        continue;
                    }
                    let st = Command::new("cmd").args(["/C", line]).status()?;
                    if st.success() {
                        applied += 1;
                    }
                }
                if applied > 0 {
                    Ok(format!("netsh: {applied} rule(s) applied"))
                } else {
                    Err(std::io::Error::other(
                        "netsh applied nothing (run as Administrator?)",
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RuleSet {
        let mut r = RuleSet::new();
        r.block_ip("1.2.3.4").block_ip("2001:db8::1");
        r.block_port(4444, "Metasploit")
            .block_port(31337, "Back Orifice");
        r
    }

    #[test]
    fn nftables_blocks_ip_and_ports() {
        let s = sample().render_nftables();
        assert!(s.contains("table inet aetherav"));
        assert!(s.contains("set bad_ip4"));
        assert!(s.contains("1.2.3.4"));
        assert!(s.contains("set bad_ip6"));
        assert!(s.contains("2001:db8::1"));
        assert!(s.contains("ip daddr @bad_ip4 drop"));
        assert!(s.contains("4444"));
        assert!(s.contains("31337"));
    }

    #[test]
    fn netsh_blocks_ip_and_ports() {
        let s = sample().render_netsh();
        assert!(s.contains("netsh advfirewall"));
        assert!(s.contains("remoteip=1.2.3.4,2001:db8::1"));
        assert!(s.contains("remoteport=4444,31337"));
        assert!(s.contains("action=block"));
    }

    #[test]
    fn pf_blocks_ip_and_ports() {
        let s = sample().render_pf();
        assert!(s.contains("table <aetherav_bad>"));
        assert!(s.contains("block drop out quick to <aetherav_bad>"));
        assert!(s.contains("port { 4444, 31337 }"));
    }

    #[test]
    fn empty_ruleset_renders_no_drop_rules() {
        let r = RuleSet::new();
        assert!(!r.render_nftables().contains("drop"));
        assert!(!r.render_pf().contains("block drop"));
        // netsh: only the delete (cleanup) lines, no add rules.
        assert!(!r.render_netsh().contains("add rule"));
    }

    #[test]
    fn dedup_ip_and_port() {
        let mut r = RuleSet::new();
        r.block_ip("9.9.9.9").block_ip("9.9.9.9");
        r.block_port(4444, "a").block_port(4444, "b");
        assert_eq!(r.bad_ips.len(), 1);
        assert_eq!(r.bad_ports.len(), 1);
    }

    #[test]
    fn platform_roundtrip() {
        for p in [Platform::Linux, Platform::Windows, Platform::Macos] {
            assert_eq!(Platform::parse(p.as_str()), Some(p));
        }
    }
}
