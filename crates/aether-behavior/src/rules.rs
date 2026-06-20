//! Behavioral detection rules.
//!
//! Each rule correlates events (and, where lineage matters, the graph) into a
//! [`Verdict`] tagged with MITRE ATT&CK techniques. Rules are intentionally
//! behavior-based - they fire on *what code does*, not what it looks like - so
//! they catch polymorphic, fileless and living-off-the-land activity that
//! static signatures miss.

use crate::event::{basename, Action, Event};
use crate::graph::BehaviorGraph;
use aether_common::{EngineKind, ThreatLevel, Verdict};
use std::collections::{HashMap, HashSet};

/// Process command lines / images derived from spawn events.
pub struct Context {
    pub cmdlines: HashMap<u32, String>,
}

impl Context {
    pub fn build(events: &[Event]) -> Context {
        let mut cmdlines = HashMap::new();
        for ev in events {
            if let Action::ProcessSpawn {
                child_pid, cmdline, ..
            } = &ev.action
            {
                cmdlines.insert(*child_pid, cmdline.to_lowercase());
            }
        }
        Context { cmdlines }
    }
}

const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "powershell",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
];

const OFFICE_APPS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
];

fn is_script_host(image: &str) -> bool {
    SCRIPT_HOSTS.contains(&image)
}

/// Run every rule and collect the verdicts that fired.
pub fn evaluate(events: &[Event], graph: &BehaviorGraph) -> Vec<Verdict> {
    let ctx = Context::build(events);
    let mut verdicts = Vec::new();
    verdicts.extend(office_macro_chain(graph, &ctx));
    verdicts.extend(encoded_powershell(graph, &ctx));
    verdicts.extend(process_injection(events, graph));
    verdicts.extend(ransomware(events, graph));
    verdicts.extend(c2_beacon(events, graph));
    verdicts.extend(persistence(events));
    verdicts
}

fn verdict(
    level: ThreatLevel,
    signature: &str,
    score: f32,
    mitre: &[&str],
    detail: String,
) -> Verdict {
    Verdict {
        engine: EngineKind::Behavioral,
        level,
        signature: signature.to_string(),
        score,
        mitre: mitre.iter().map(|s| s.to_string()).collect(),
        detail: Some(detail),
    }
}

/// T1566 / T1059 - an Office application in the lineage of a script host.
fn office_macro_chain(graph: &BehaviorGraph, ctx: &Context) -> Option<Verdict> {
    let mut chains = Vec::new();
    for &pid in ctx.cmdlines.keys() {
        let image = graph.image_of(pid);
        if is_script_host(image) && graph.has_ancestor_in(pid, OFFICE_APPS) {
            // Drop synthetic/unknown (empty) ancestor images from the display.
            let lineage: Vec<String> = graph
                .ancestor_images(pid)
                .into_iter()
                .filter(|a| !a.is_empty())
                .collect();
            chains.push(format!("{} <= {}", image, lineage.join(" <= ")));
        }
    }
    if chains.is_empty() {
        return None;
    }
    Some(verdict(
        ThreatLevel::Malicious,
        "behavior.office_spawns_script",
        0.95,
        &["T1566.001", "T1059"],
        format!(
            "Office application spawned a script interpreter: {}",
            chains.join("; ")
        ),
    ))
}

/// T1059.001 / T1027 - PowerShell launched with encoded / hidden / download flags.
fn encoded_powershell(graph: &BehaviorGraph, ctx: &Context) -> Option<Verdict> {
    const FLAGS: &[&str] = &[
        "-enc",
        "-encodedcommand",
        "-e ",
        "-w hidden",
        "-windowstyle hidden",
        "frombase64string",
        "downloadstring",
        "iex",
        "invoke-expression",
    ];
    let mut hits = Vec::new();
    for (&pid, cmd) in &ctx.cmdlines {
        let image = graph.image_of(pid);
        if (image == "powershell.exe" || image == "pwsh.exe" || image == "powershell")
            && FLAGS.iter().any(|f| cmd.contains(f))
        {
            hits.push(pid);
        }
    }
    if hits.is_empty() {
        return None;
    }
    Some(verdict(
        ThreatLevel::Malicious,
        "behavior.encoded_powershell",
        0.9,
        &["T1059.001", "T1027"],
        format!("obfuscated/encoded PowerShell invocation (pids {hits:?})"),
    ))
}

/// T1055 - allocate W+X memory in another process, then start a thread there.
fn process_injection(events: &[Event], graph: &BehaviorGraph) -> Option<Verdict> {
    // (actor, target) pairs that allocated executable+writable memory remotely.
    let mut allocs: HashSet<(u32, u32)> = HashSet::new();
    for ev in events {
        if let Action::MemAlloc {
            target_pid,
            protection,
        } = &ev.action
        {
            let p = protection.to_uppercase();
            let wx = (p.contains('W') && p.contains('X')) || p.contains("EXECUTE_READWRITE");
            if wx && *target_pid != ev.pid {
                allocs.insert((ev.pid, *target_pid));
            }
        }
    }
    for ev in events {
        if let Action::RemoteThread { target_pid } = &ev.action {
            if allocs.contains(&(ev.pid, *target_pid)) {
                return Some(verdict(
                    ThreatLevel::Malicious,
                    "behavior.process_injection",
                    0.97,
                    &["T1055"],
                    format!(
                        "process {} ({}) allocated W+X memory and started a remote thread in process {}",
                        ev.pid,
                        graph.image_of(ev.pid),
                        target_pid
                    ),
                ));
            }
        }
    }
    None
}

/// T1486 (+ T1490) - mass high-entropy file modification, optionally with
/// shadow-copy deletion (the canonical ransomware fingerprint).
fn ransomware(events: &[Event], graph: &BehaviorGraph) -> Option<Verdict> {
    const MASS_THRESHOLD: usize = 12;

    // Distinct high-entropy writes / renames per actor.
    let mut encrypted: HashMap<u32, HashSet<String>> = HashMap::new();
    for ev in events {
        match &ev.action {
            Action::FileWrite { path, entropy } if *entropy > 7.0 => {
                encrypted.entry(ev.pid).or_default().insert(path.clone());
            }
            Action::FileRename { to, .. } => {
                encrypted.entry(ev.pid).or_default().insert(to.clone());
            }
            _ => {}
        }
    }
    let mass = encrypted
        .iter()
        .find(|(_, paths)| paths.len() >= MASS_THRESHOLD)
        .map(|(pid, paths)| (*pid, paths.len()));

    // Shadow-copy / backup destruction (Inhibit System Recovery).
    const RECOVERY_TOOLS: &[&str] = &["vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe"];
    let shadow_delete = events.iter().any(|ev| {
        if let Action::ProcessSpawn { image, cmdline, .. } = &ev.action {
            let img = basename(image);
            let cmd = cmdline.to_lowercase();
            RECOVERY_TOOLS.contains(&img.as_str())
                && (cmd.contains("delete") && (cmd.contains("shadow") || cmd.contains("catalog"))
                    || cmd.contains("recoveryenabled no"))
        } else {
            false
        }
    });

    if mass.is_none() && !shadow_delete {
        return None;
    }

    let mut mitre = vec!["T1486"];
    let mut detail = String::new();
    if let Some((pid, count)) = mass {
        detail.push_str(&format!(
            "process {} ({}) wrote/renamed {} files with encryption-grade entropy",
            pid,
            graph.image_of(pid),
            count
        ));
    }
    if shadow_delete {
        mitre.push("T1490");
        if !detail.is_empty() {
            detail.push_str("; ");
        }
        detail.push_str("deleted volume shadow copies / backups (Inhibit System Recovery)");
    }

    // A mass-encryption burst alone is conclusive; shadow-delete on its own is
    // strongly suspicious. Both together is the highest-confidence verdict.
    let level = if mass.is_some() {
        ThreatLevel::Malicious
    } else {
        ThreatLevel::Suspicious
    };
    let score = if mass.is_some() && shadow_delete {
        0.98
    } else {
        0.8
    };

    Some(verdict(level, "behavior.ransomware", score, &mitre, detail))
}

/// T1071 / T1105 - a script host or injected process beaconing to a public host.
fn c2_beacon(events: &[Event], graph: &BehaviorGraph) -> Option<Verdict> {
    let mut hits = Vec::new();
    for ev in events {
        if let Action::NetConnect { remote, port } = &ev.action {
            let image = graph.image_of(ev.pid);
            if (is_script_host(image) || graph.has_ancestor_in(ev.pid, OFFICE_APPS))
                && is_public_remote(remote)
            {
                hits.push(format!("{} -> {}:{}", image, remote, port));
            }
        }
    }
    if hits.is_empty() {
        return None;
    }
    Some(verdict(
        ThreatLevel::Suspicious,
        "behavior.c2_beacon",
        0.7,
        &["T1071", "T1105"],
        format!(
            "script/interpreter contacted external host(s): {}",
            hits.join(", ")
        ),
    ))
}

/// T1547.001 / T1053.005 - autostart registry keys or scheduled-task creation.
fn persistence(events: &[Event]) -> Option<Verdict> {
    let mut detail = Vec::new();
    let mut mitre: Vec<&str> = Vec::new();
    for ev in events {
        match &ev.action {
            Action::RegistrySet { key, .. } => {
                let k = key.to_lowercase();
                if k.contains("currentversion\\run") || k.contains("currentversion\\runonce") {
                    detail.push(format!("autostart registry key set: {key}"));
                    if !mitre.contains(&"T1547.001") {
                        mitre.push("T1547.001");
                    }
                }
            }
            Action::ProcessSpawn { image, cmdline, .. } => {
                let img = basename(image);
                let cmd = cmdline.to_lowercase();
                if img == "schtasks.exe" && cmd.contains("/create") {
                    detail.push("scheduled task created (schtasks /create)".to_string());
                    if !mitre.contains(&"T1053.005") {
                        mitre.push("T1053.005");
                    }
                }
            }
            _ => {}
        }
    }
    if detail.is_empty() {
        return None;
    }
    Some(verdict(
        ThreatLevel::Suspicious,
        "behavior.persistence",
        0.6,
        &mitre,
        detail.join("; "),
    ))
}

/// Crude public-address check: private/loopback ranges are treated as internal;
/// anything else (including bare hostnames) is treated as a potential C2.
fn is_public_remote(remote: &str) -> bool {
    if remote.starts_with("127.")
        || remote.starts_with("10.")
        || remote.starts_with("192.168.")
        || remote == "localhost"
        || remote.starts_with("::1")
        || remote.starts_with("169.254.")
    {
        return false;
    }
    // 172.16.0.0 - 172.31.255.255
    if let Some(rest) = remote.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(octet) = second.parse::<u8>() {
                if (16..=31).contains(&octet) {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::BehaviorGraph;

    fn run(json: &str) -> Vec<Verdict> {
        let events = Event::from_json(json).unwrap();
        let graph = BehaviorGraph::build(&events);
        evaluate(&events, &graph)
    }

    #[test]
    fn detects_office_macro_chain() {
        let v = run(r#"[
            {"pid":1,"action":"process_spawn","child_pid":10,"image":"explorer.exe"},
            {"pid":10,"action":"process_spawn","child_pid":20,"image":"winword.exe"},
            {"pid":20,"action":"process_spawn","child_pid":30,"image":"powershell.exe","cmdline":"-w hidden -enc AAAA"}
        ]"#);
        assert!(v
            .iter()
            .any(|v| v.signature == "behavior.office_spawns_script"));
        assert!(v
            .iter()
            .any(|v| v.signature == "behavior.encoded_powershell"));
    }

    #[test]
    fn detects_process_injection() {
        let v = run(r#"[
            {"pid":500,"action":"mem_alloc","target_pid":900,"protection":"RWX"},
            {"pid":500,"action":"remote_thread","target_pid":900}
        ]"#);
        let inj = v
            .iter()
            .find(|v| v.signature == "behavior.process_injection")
            .unwrap();
        assert_eq!(inj.level, ThreatLevel::Malicious);
        assert!(inj.mitre.contains(&"T1055".to_string()));
    }

    #[test]
    fn injection_needs_both_alloc_and_thread() {
        let v = run(r#"[{"pid":500,"action":"mem_alloc","target_pid":900,"protection":"RWX"}]"#);
        assert!(!v
            .iter()
            .any(|v| v.signature == "behavior.process_injection"));
    }

    #[test]
    fn detects_ransomware_with_shadow_delete() {
        // 13 high-entropy writes + vssadmin delete shadows.
        let mut events = String::from("[");
        for i in 0..13 {
            events.push_str(&format!(
                r#"{{"pid":42,"action":"file_write","path":"C:\\docs\\f{i}.locked","entropy":7.9}},"#
            ));
        }
        events.push_str(
            r#"{"pid":42,"action":"process_spawn","child_pid":77,"image":"vssadmin.exe","cmdline":"delete shadows /all /quiet"}]"#,
        );
        let v = run(&events);
        let r = v
            .iter()
            .find(|v| v.signature == "behavior.ransomware")
            .unwrap();
        assert_eq!(r.level, ThreatLevel::Malicious);
        assert!(r.mitre.contains(&"T1486".to_string()));
        assert!(r.mitre.contains(&"T1490".to_string()));
    }

    #[test]
    fn clean_trace_yields_nothing() {
        let v = run(r#"[
            {"pid":10,"action":"process_spawn","child_pid":20,"image":"notepad.exe"},
            {"pid":20,"action":"file_write","path":"C:\\docs\\note.txt","entropy":3.1}
        ]"#);
        assert!(v.is_empty());
    }

    #[test]
    fn public_vs_private_remote() {
        assert!(is_public_remote("45.9.1.2"));
        assert!(!is_public_remote("192.168.1.5"));
        assert!(!is_public_remote("10.0.0.3"));
        assert!(!is_public_remote("172.16.5.5"));
        assert!(is_public_remote("172.32.0.1"));
    }
}
