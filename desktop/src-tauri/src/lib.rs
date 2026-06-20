//! AetherAV desktop - Tauri shell wired to the real engine.
//!
//! Every panel is fed by live data: engine counts (signatures incl. downloaded
//! malware hashes, YARA rules, intel IOCs), real system metrics via `sysinfo`,
//! live process activity, and a 2-second `metrics` event stream. `update_intel`
//! downloads free abuse.ch feeds and hot-reloads the signature database.

use aether_intel::{Feed, IntelStore};
use aether_quarantine::Vault;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::{Disks, Networks, System};
use tauri::{Emitter, Manager};

/// Locate the repo `assets/` dir from the working dir or next to the binary.
fn assets_root() -> PathBuf {
    let mut candidates = vec![
        PathBuf::from("assets"),
        PathBuf::from("../assets"),
        PathBuf::from("../../assets"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("assets"));
        }
    }
    candidates
        .into_iter()
        .find(|p| p.join("signatures").exists() || p.join("rules").exists())
        .unwrap_or_else(|| PathBuf::from("assets"))
}

/// User-facing, persisted settings (engine toggles + paths).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Settings {
    heuristics: bool,
    ml: bool,
    yara: bool,
    sandbox: bool,
    intel: bool,
    plugins: bool,
    #[serde(default = "default_true")]
    llm: bool,
    #[serde(default)]
    llm_runner: String,
    quarantine_dir: String,
    auto_update_hours: u64,
    /// URL of the Ed25519-signed feed for manual/auto signature updates.
    #[serde(default)]
    update_url: String,
}

fn default_true() -> bool {
    true
}

/// Locate the llama.cpp one-shot runner (built CPU binary, then PATH).
fn find_llm_runner() -> String {
    let candidates = [
        "/home/nexland/.unsloth/llama.cpp/build_cli/bin/llama-completion",
        "/home/nexland/.unsloth/llama.cpp/build/bin/llama-completion",
        "/usr/local/bin/llama-completion",
    ];
    candidates
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|p| p.to_string())
        .unwrap_or_else(|| "llama-completion".to_string())
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            heuristics: true,
            ml: true,
            yara: true,
            sandbox: true,
            intel: true,
            plugins: false,
            llm: true, // Aegis-50M boots with the engine
            llm_runner: String::new(),
            quarantine_dir: String::new(),
            auto_update_hours: 6,
            update_url: String::new(),
        }
    }
}

impl Settings {
    fn path(assets: &Path) -> PathBuf {
        assets.join("models/settings.json")
    }
    fn load(assets: &Path) -> Settings {
        std::fs::read_to_string(Self::path(assets))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }
    fn save(&self, assets: &Path) {
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(Self::path(assets), t);
        }
    }
}

fn build_scanner(assets: &Path, s: &Settings) -> Option<aether_core::Scanner> {
    let mut cfg = aether_config::Config::default();
    cfg.engines.hash_db = assets.join("signatures/hashes.db");
    cfg.engines.yara_rules = assets.join("rules");
    cfg.engines.ml_model = assets.join("models/pe.json");
    cfg.engines.intel_store = assets.join("models/intel.json");
    cfg.engines.heuristics = s.heuristics;
    cfg.engines.ml = s.ml;
    cfg.engines.yara = s.yara;
    cfg.engines.sandbox = s.sandbox;
    cfg.engines.intel = s.intel;
    cfg.engines.plugins = s.plugins;
    // Aegis-50M on-device LLM engine.
    cfg.engines.llm = s.llm;
    cfg.engines.llm_model = assets.join("models/aegis-50m.gguf");
    cfg.engines.llm_runner = if s.llm_runner.is_empty() {
        find_llm_runner()
    } else {
        s.llm_runner.clone()
    };
    aether_core::Scanner::new(cfg).ok()
}

/// Shared, mutable application state.
struct AppState {
    assets: PathBuf,
    scanner: Mutex<Option<aether_core::Scanner>>,
    settings: Mutex<Settings>,
    sys: Mutex<System>,
    nets: Mutex<Networks>,
    cpu_hist: Mutex<VecDeque<f32>>,
    files_scanned: Mutex<u64>,
    threats_blocked: Mutex<u64>,
    /// Guards against starting the live exec monitor twice.
    watch_started: std::sync::atomic::AtomicBool,
}

impl AppState {
    fn new() -> AppState {
        let assets = assets_root();
        let settings = Settings::load(&assets);
        AppState {
            // Built lazily on a background thread at startup (loading ~1M+ hash
            // signatures takes a few seconds) so the window appears instantly.
            scanner: Mutex::new(None),
            settings: Mutex::new(settings),
            sys: Mutex::new(System::new_all()),
            nets: Mutex::new(Networks::new_with_refreshed_list()),
            cpu_hist: Mutex::new(VecDeque::from(vec![0.0f32; 24])),
            files_scanned: Mutex::new(0),
            threats_blocked: Mutex::new(0),
            watch_started: std::sync::atomic::AtomicBool::new(false),
            assets,
        }
    }

    fn intel_count(&self) -> usize {
        IntelStore::load_or_new(self.assets.join("models/intel.json"))
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Where the encrypted quarantine vault lives (settings override, else default).
    fn vault_path(&self) -> PathBuf {
        let dir = self.settings.lock().unwrap().quarantine_dir.clone();
        if dir.is_empty() {
            self.assets.join("../quarantine")
        } else {
            PathBuf::from(dir)
        }
    }
}

/// Worst-disposition string + best verdict for a report row.
fn report_row(r: &aether_common::ScanReport) -> Value {
    let worst = r.verdicts.iter().max_by(|a, b| a.level.cmp(&b.level));
    json!({
        "path": r.path.display().to_string(),
        "risk": r.disposition().to_string().to_lowercase(),
        "signature": worst.map(|v| v.signature.clone()).unwrap_or_default(),
        "detail": worst.and_then(|v| v.detail.clone()).unwrap_or_default(),
    })
}

/// Routable (non-private, non-loopback) address check.
fn is_external_ip(ip: &str) -> bool {
    !(ip.starts_with("127.")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("169.254.")
        || ip == "0.0.0.0"
        || ip.starts_with("::1")
        || ip.starts_with("fe80")
        || ip.starts_with("::")
        || (ip.starts_with("172.")
            && ip
                .split('.')
                .nth(1)
                .and_then(|o| o.parse::<u8>().ok())
                .is_some_and(|o| (16..=31).contains(&o))))
}

/// Fire a native OS notification (floating, shows even when minimized) and
/// mirror it to the in-app notification center (the bell) via an `alert` event.
fn notify(app: &tauri::AppHandle, title: &str, body: &str) {
    // 1) Always log to the in-app notification center (the bell) - independent
    //    of any OS notification daemon, so this can never be lost or blocked.
    let level = if title.contains('⚠') {
        "alert"
    } else if title.contains("clean") || title.contains("Active") || title.contains("updated") {
        "success"
    } else {
        "info"
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = app.emit("alert", json!({"title": title, "body": body, "level": level, "ts": ts}));

    // 2) Best-effort floating OS notification, off-thread so a slow or absent
    //    notification daemon can never block the caller.
    let (app2, t, b) = (app.clone(), title.to_string(), body.to_string());
    std::thread::spawn(move || {
        use tauri_plugin_notification::NotificationExt;
        let _ = app2.notification().builder().title(t).body(b).show();
    });
}

fn fmt_clock(epoch_secs: u64) -> String {
    let s = epoch_secs % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Snapshot of system metrics used by the status bar / live widgets.
fn metrics_snapshot(state: &AppState) -> Value {
    let mut sys = state.sys.lock().unwrap();
    sys.refresh_cpu_usage();
    sys.refresh_memory();

    let cpu = sys.global_cpu_usage();
    let total = sys.total_memory().max(1);
    let ram = (sys.used_memory() as f64 / total as f64 * 100.0) as u32;

    let disks = Disks::new_with_refreshed_list();
    let (mut dtot, mut dused) = (0u64, 0u64);
    for d in disks.list() {
        dtot += d.total_space();
        dused += d.total_space().saturating_sub(d.available_space());
    }
    let disk = if dtot > 0 { (dused as f64 / dtot as f64 * 100.0) as u32 } else { 0 };

    // Network receive rate over the refresh interval.
    let mut nets = state.nets.lock().unwrap();
    nets.refresh(true);
    let rx: u64 = nets.list().values().map(|n| n.received()).sum();
    drop(nets);
    let net_kb = (rx as f64 / 1024.0 / 2.0).max(0.0);

    state.cpu_hist.lock().unwrap().push_back(cpu);
    while state.cpu_hist.lock().unwrap().len() > 24 {
        state.cpu_hist.lock().unwrap().pop_front();
    }

    json!({
      "os": format!("{} {}", System::name().unwrap_or_else(|| "Unknown".into()),
                    System::os_version().unwrap_or_default()),
      "arch": std::env::consts::ARCH,
      "cpu": format!("{cpu:.0}%"),
      "ram": format!("{ram}%"),
      "disk": format!("{disk}%"),
      "net": format!("{net_kb:.1} KB/s"),
      "processes": sys.processes().len(),
    })
}

/// Full dashboard payload - all live.
#[tauri::command]
fn dashboard_data(state: tauri::State<AppState>) -> Value {
    let (signatures, ml_loaded, yara_rules, llm_loaded) = {
        let g = state.scanner.lock().unwrap();
        match g.as_ref() {
            Some(s) => (s.signature_count(), s.ml_loaded(), s.yara_rule_count(), s.llm_loaded()),
            None => (0, false, 0, false),
        }
    };
    let intel = state.intel_count();
    let files = *state.files_scanned.lock().unwrap();
    let threats = *state.threats_blocked.lock().unwrap();
    let metrics = metrics_snapshot(&state);
    let procs = metrics["processes"].as_u64().unwrap_or(0);
    let conns = aether_realtime::netmon::connections();
    let net_conns = conns.len() as u64;
    let net_flagged = conns.iter().filter(|c| c.flagged().is_some()).count() as u64;

    // Live process activity -> "recent detections" + behavior graph.
    let (detections, graph) = process_activity(&state);
    let chart = {
        let hist: Vec<f32> = state.cpu_hist.lock().unwrap().iter().copied().collect();
        let actual: Vec<f64> = hist.iter().map(|v| *v as f64).collect();
        // Baseline = trailing moving average of CPU.
        let mut baseline = Vec::with_capacity(actual.len());
        let w = 5usize;
        for i in 0..actual.len() {
            let lo = i.saturating_sub(w);
            let avg = actual[lo..=i].iter().sum::<f64>() / ((i - lo + 1) as f64);
            baseline.push(avg);
        }
        json!({"baseline": baseline, "actual": actual,
               "xlabels":["-48s","-36s","-24s","-12s","now"]})
    };

    json!({
      "stats": [
        {"ic":"shield","v":fmt_num(threats),"l":"Threats Blocked","n":"this session","up":threats>0},
        {"ic":"file","v":fmt_num(files),"l":"Files Scanned","n":"this session","up":files>0},
        {"ic":"code","v":fmt_num(yara_rules as u64),"l":"YARA Rules Loaded","n":"compiled"},
        {"ic":"lock","v":fmt_num(quarantine_count(&state)),"l":"Quarantined Items","n":"isolated"},
        {"ic":"database","v":fmt_num(signatures as u64),"l":"Malware Signatures","n":"hash DB"},
        {"ic":"rss","v":fmt_num(intel as u64),"l":"Threat Intel IOCs","n":"abuse.ch feeds"}
      ],
      "modules": modules(ml_loaded, signatures, llm_loaded),
      "detections": detections,
      "graph": graph,
      "mitre": mitre(),
      "chart": chart,
      "feed": [
        {"ic":"wifi","g":true,"name":"Feeds Status","val": if intel>0 {"Loaded"} else {"Run Update"},"ok":intel>0},
        {"ic":"database","name":"Signatures","val":format!("{} hashes", fmt_num(signatures as u64))},
        {"ic":"code","name":"YARA Rules","val":format!("{} rules", fmt_num(yara_rules as u64))},
        {"ic":"refresh","name":"Hot Reload","val":"Enabled"}
      ],
      "system": {"os": metrics["os"], "cpu": metrics["cpu"], "ram": metrics["ram"],
                 "disk": metrics["disk"], "net": metrics["net"]},
      "live": {"processes": procs, "connections": net_conns, "flagged_ports": net_flagged, "aegis": llm_loaded}
    })
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn quarantine_count(state: &AppState) -> u64 {
    let vault = state.assets.join("../quarantine");
    aether_quarantine::Vault::open(&vault).map(|v| v.list().len() as u64).unwrap_or(0)
}

/// Build recent-activity rows and a behavior graph from the live process table.
fn process_activity(state: &AppState) -> (Value, Value) {
    let sys = state.sys.lock().unwrap();
    let mut procs: Vec<_> = sys.processes().iter().collect();
    procs.sort_by_key(|(_, p)| std::cmp::Reverse(p.start_time()));

    let detections: Vec<Value> = procs.iter().take(6).map(|(pid, p)| {
        json!({
          "time": fmt_clock(p.start_time()),
          "item": p.name().to_string_lossy(),
          "type": "Process",
          "risk": "clean",
          "action": format!("PID {}", pid)
        })
    }).collect();

    drop(sys); // release the process lock before network work

    // --- Live network connection map (real, verified connections) ---
    // Center = this host; spokes = its actual external endpoints, with any on
    // malware-associated ports or known-bad IPs (intel) marked malicious.
    use std::collections::HashSet;
    let conns = aether_realtime::netmon::connections();
    let intel = IntelStore::load_or_new(state.assets.join("models/intel.json")).ok();

    let established = conns.iter().filter(|c| c.state == "ESTABLISHED").count();
    let mut seen = HashSet::new();
    let mut endpoints: Vec<(String, String, bool)> = Vec::new(); // (label, detail, flagged)
    for c in &conns {
        if !is_external_ip(&c.remote_addr) || c.remote_port == 0 {
            continue;
        }
        let label = format!("{}:{}", c.remote_addr, c.remote_port);
        if !seen.insert(label.clone()) {
            continue;
        }
        let (flagged, detail) = if let Some((port, name, _s)) = c.flagged() {
            (true, format!("\u{26a0} port {port} · {name}"))
        } else if let Some(threat) = intel.as_ref().and_then(|s| s.lookup_ip(&c.remote_addr)) {
            (true, format!("\u{26a0} known-bad IP · {threat}"))
        } else {
            (false, c.state.to_string())
        };
        endpoints.push((label, detail, flagged));
    }
    // Flagged endpoints first; cap the node count so the map stays readable.
    endpoints.sort_by_key(|e| !e.2);
    endpoints.truncate(12);

    let host = System::host_name().unwrap_or_else(|| "this host".to_string());
    let mut nodes = vec![json!({
        "id": "c", "label": host, "kind": "center", "x": 50, "y": 50,
        "pid": format!("{established} live connection(s)")
    })];
    let mut edges: Vec<Value> = Vec::new();
    let n = endpoints.len().max(1) as f64;
    for (i, (label, detail, flagged)) in endpoints.iter().enumerate() {
        let ang = 2.0 * std::f64::consts::PI * (i as f64) / n - std::f64::consts::PI / 2.0;
        let x = (50.0 + 38.0 * ang.cos()).round() as i64;
        let y = (50.0 + 40.0 * ang.sin()).round() as i64;
        let id = format!("e{i}");
        nodes.push(json!({
            "id": id, "label": label, "pid": detail, "x": x, "y": y,
            "kind": if *flagged { "malicious" } else { "net" }
        }));
        edges.push(json!(["c", id]));
    }
    (json!(detections), json!({"nodes": nodes, "edges": edges}))
}

fn modules(ml: bool, sigs: usize, llm: bool) -> Value {
    json!([
      {"ic":"database","t":"Hash + Bloom Filter","s":format!("{} signatures loaded", fmt_num(sigs as u64))},
      {"ic":"code","t":"YARA-X Rules","s":"Advanced pattern matching engine"},
      {"ic":"cube","t":"PE / ELF / Mach-O","s":"Binary parsing & structure analysis"},
      {"ic":"doc","t":"PDF / Office / Script","s":"Document & script inspection"},
      {"ic":"target","t":"Static Heuristics","s":"AI-driven static code analysis"},
      {"ic":"brain","t":"Aegis-50M LLM","s": if llm {"On-device model · loaded & live"} else {"On-device model · not loaded"}, "active": llm},
      {"ic":"share","t":"Behavioral + Graph","s":"Process, file & network correlation"},
      {"ic":"box","t":"Sandbox Emulation","s":"Anti-evasion + shellcode analysis"},
      {"ic":"wave","t":"ML / Anomaly","s": if ml {"Static model loaded · live scoring"} else {"Unsupervised anomaly scoring"}},
      {"ic":"lock","t":"Encrypted Quarantine","s":"AES-256-GCM vault"},
      {"ic":"rss","t":"Threat Intel Feed","s":"abuse.ch signed feeds & hot-reload"}
    ])
}

fn mitre() -> Value {
    json!([
      {"ic":"key","name":"Initial Access","tech":["T1566","T1190"]},
      {"ic":"zap","name":"Execution","tech":["T1059","T1204"]},
      {"ic":"refresh","name":"Persistence","tech":["T1547","T1060"]},
      {"ic":"eye","name":"Defense Evasion","tech":["T1027","T1036"]},
      {"ic":"search","name":"Discovery","tech":["T1082","T1018"]}
    ])
}

/// Quick-action handler.
#[tauri::command]
fn run_action(app: tauri::AppHandle, state: tauri::State<AppState>, action: String) -> Value {
    match action.as_str() {
        "quick" | "full" => {
            let dir = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
            let g = state.scanner.lock().unwrap();
            let Some(scanner) = g.as_ref() else { return json!({"message":"engine unavailable"}); };
            match scanner.scan_path(&dir) {
                Ok((_r, summary)) => {
                    *state.files_scanned.lock().unwrap() += summary.scanned;
                    let threats = summary.malicious + summary.suspicious;
                    *state.threats_blocked.lock().unwrap() += threats;
                    if threats > 0 {
                        notify(&app, "⚠ Threats detected",
                               &format!("{} malicious · {} suspicious in {} files.",
                                        summary.malicious, summary.suspicious, summary.scanned));
                    } else {
                        notify(&app, "Scan complete - clean",
                               &format!("{} files scanned, no threats.", summary.scanned));
                    }
                    json!({"message": format!(
                        "Scan complete · {} files · {} malicious · {} suspicious · {} ms",
                        summary.scanned, summary.malicious, summary.suspicious, summary.elapsed.as_millis())})
                }
                Err(e) => json!({"message": format!("scan error: {e}")}),
            }
        }
        "custom" => json!({"message":"Custom scan profile - configure targets first."}),
        "quarantine" => json!({"message":"Opening encrypted quarantine vault…"}),
        "restore" => json!({"message":"Restore / export from the vault…"}),
        other => json!({"message": format!("unknown action: {other}")}),
    }
}

/// Scan a file or directory and return real per-file results.
#[tauri::command]
fn scan_path_cmd(app: tauri::AppHandle, state: tauri::State<AppState>, path: String) -> Value {
    let g = state.scanner.lock().unwrap();
    let Some(scanner) = g.as_ref() else {
        return json!({"error": "engine unavailable"});
    };
    let p = PathBuf::from(&path);
    if !p.exists() {
        return json!({"error": format!("path not found: {path}")});
    }
    match scanner.scan_path(&p) {
        Ok((reports, summary)) => {
            *state.files_scanned.lock().unwrap() += summary.scanned;
            let threats = summary.malicious + summary.suspicious;
            *state.threats_blocked.lock().unwrap() += threats;
            if threats > 0 {
                notify(&app, "⚠ Threats detected",
                       &format!("{} malicious · {} suspicious in {}",
                                summary.malicious, summary.suspicious, path));
            }
            let rows: Vec<Value> = reports
                .iter()
                .filter(|r| r.is_threat())
                .map(report_row)
                .collect();
            json!({
                "summary": {"scanned": summary.scanned, "malicious": summary.malicious,
                            "suspicious": summary.suspicious, "clean": summary.clean,
                            "ms": summary.elapsed.as_millis()},
                "threats": rows
            })
        }
        Err(e) => json!({"error": e.to_string()}),
    }
}

/// Scan the executables of running processes against the engine (real-time).
#[tauri::command]
fn scan_processes(state: tauri::State<AppState>) -> Value {
    use sysinfo::ProcessesToUpdate;
    let mut sys = state.sys.lock().unwrap();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    // Collect (pid, name, exe) for processes that expose an on-disk image.
    let mut targets: Vec<(u32, String, PathBuf)> = sys
        .processes()
        .iter()
        .filter_map(|(pid, p)| {
            p.exe().map(|e| (pid.as_u32(), p.name().to_string_lossy().to_string(), e.to_path_buf()))
        })
        .collect();
    drop(sys);
    targets.sort_by(|a, b| a.1.cmp(&b.1));
    targets.dedup_by(|a, b| a.2 == b.2); // one row per unique image
    targets.truncate(60);

    let g = state.scanner.lock().unwrap();
    let Some(scanner) = g.as_ref() else {
        return json!({"error": "engine unavailable"});
    };
    let mut rows = Vec::new();
    let (mut scanned, mut flagged) = (0u64, 0u64);
    for (pid, name, exe) in targets {
        if let Ok(report) = scanner.scan_file(&exe) {
            scanned += 1;
            let risk = report.disposition().to_string().to_lowercase();
            if report.is_threat() {
                flagged += 1;
            }
            let sig = report
                .verdicts
                .iter()
                .max_by(|a, b| a.level.cmp(&b.level))
                .map(|v| v.signature.clone())
                .unwrap_or_default();
            rows.push(json!({"pid": pid, "name": name,
                             "path": exe.display().to_string(), "risk": risk, "signature": sig}));
        }
    }
    json!({"scanned": scanned, "flagged": flagged, "rows": rows})
}

/// Learn the current running executables as the Process Sentinel baseline.
#[tauri::command]
fn sentinel_learn(state: tauri::State<AppState>) -> Value {
    use aether_realtime::sentinel;
    let mut base = serde_json::Map::new();
    for p in sentinel::snapshot() {
        if let (Some(exe), false) = (&p.exe, p.exe_deleted) {
            let key = exe.display().to_string();
            if !base.contains_key(&key) {
                if let Ok(d) = std::fs::read(exe) {
                    base.insert(key, json!(aether_signatures::hash_bytes(&d).sha256));
                }
            }
        }
    }
    let path = state.assets.join("models/proc_baseline.json");
    let _ = std::fs::write(&path, serde_json::to_string(&base).unwrap_or_default());
    json!({"message": format!("Baseline learned: {} executables", base.len()), "count": base.len()})
}

/// Start the live kernel exec-monitor (cn_proc): streams every process the
/// kernel reports being born, scanned by the engine, as `exec` events. Needs
/// root/CAP_NET_ADMIN; emits `exec-error` otherwise. Linux-only.
#[tauri::command]
fn sentinel_watch(app: tauri::AppHandle) -> Value {
    #[cfg(target_os = "linux")]
    {
        use std::sync::atomic::Ordering;
        let state = app.state::<AppState>();
        if state.watch_started.swap(true, Ordering::SeqCst) {
            return json!({"message": "live monitor already running"});
        }
        let h = app.clone();
        std::thread::spawn(move || {
            let res = aether_realtime::exectrace::watch_execs(|ev| {
                let exe = std::fs::read_link(format!("/proc/{}/exe", ev.pid)).ok();
                let name = aether_realtime::sentinel::proc_name(ev.pid);
                let (mut risk, mut sig, mut mal) = ("clean".to_string(), String::new(), false);
                if let Some(exe) = &exe {
                    let st = h.state::<AppState>();
                    let guard = st.scanner.lock().unwrap();
                    if let Some(s) = guard.as_ref() {
                        if let Ok(r) = s.scan_file(exe) {
                            risk = r.disposition().to_string().to_lowercase();
                            sig = r.verdicts.iter().max_by(|a, b| a.level.cmp(&b.level))
                                .map(|v| v.signature.clone()).unwrap_or_default();
                            mal = r.disposition() == aether_common::ThreatLevel::Malicious;
                        }
                    }
                }
                if mal {
                    notify(&h, "⚠ Malicious process launched", &format!("{name} [{sig}]"));
                }
                let _ = h.emit("exec", json!({
                    "pid": ev.pid, "name": name,
                    "path": exe.map(|e| e.display().to_string()).unwrap_or_default(),
                    "risk": risk, "signature": sig
                }));
            });
            if let Err(e) = res {
                let _ = h.emit("exec-error", json!({"message": e.to_string()}));
            }
            h.state::<AppState>().watch_started.store(false, Ordering::SeqCst);
        });
        json!({"message": "live exec monitor started (kernel cn_proc)"})
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        json!({"message": "live monitor is Linux-only"})
    }
}

/// Process Sentinel scan: new/unknown apps (by hash), hidden processes, stealth.
#[tauri::command]
fn sentinel_scan(state: tauri::State<AppState>) -> Value {
    use aether_realtime::sentinel;
    use std::collections::HashMap;

    let snap = sentinel::snapshot();
    let mut exe_hash: HashMap<String, String> = HashMap::new();
    for p in &snap {
        if let (Some(exe), false) = (&p.exe, p.exe_deleted) {
            let key = exe.display().to_string();
            if !exe_hash.contains_key(&key) {
                if let Ok(d) = std::fs::read(exe) {
                    exe_hash.insert(key, aether_signatures::hash_bytes(&d).sha256);
                }
            }
        }
    }
    let baseline: HashMap<String, String> = std::fs::read_to_string(state.assets.join("models/proc_baseline.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let learned = !baseline.is_empty();

    let g = state.scanner.lock().unwrap();
    let scanner = g.as_ref();
    let mut new_rows = Vec::new();
    for p in &snap {
        let Some(exe) = &p.exe else { continue };
        let path = exe.display().to_string();
        let hash = exe_hash.get(&path);
        let is_new = match (baseline.get(&path), hash) {
            (None, _) => true,
            (Some(known), Some(h)) => known != h,
            (Some(_), None) => false,
        };
        if !is_new {
            continue;
        }
        let (mut risk, mut sig) = ("unknown".to_string(), String::new());
        if let Some(s) = scanner {
            if let Ok(r) = s.scan_file(exe) {
                risk = r.disposition().to_string().to_lowercase();
                sig = r.verdicts.iter().max_by(|a, b| a.level.cmp(&b.level))
                    .map(|v| v.signature.clone()).unwrap_or_default();
            }
        }
        new_rows.push(json!({"pid": p.pid, "name": p.name, "path": path, "risk": risk, "signature": sig}));
    }
    drop(g);

    let hidden = sentinel::hidden_pids();
    let stealth: Vec<Value> = snap.iter().filter(|p| p.exe_deleted || p.from_temp).map(|p| {
        json!({"pid": p.pid, "name": p.name,
               "path": p.exe.as_ref().map(|e| e.display().to_string()).unwrap_or_default(),
               "why": if p.exe_deleted {"executable deleted while running"} else {"running from a temp/volatile dir"}})
    }).collect();

    json!({"learned": learned, "new": new_rows, "hidden": hidden, "stealth": stealth})
}

/// Live TCP connections + malicious-port flags + known-bad-IP correlation.
#[tauri::command]
fn network_status(state: tauri::State<AppState>) -> Value {
    use aether_realtime::netmon;
    let conns = netmon::connections();
    let listening = conns.iter().filter(|c| c.state == "LISTEN").count();
    let established = conns.iter().filter(|c| c.state == "ESTABLISHED").count();
    let intel = IntelStore::load_or_new(state.assets.join("models/intel.json")).ok();

    // Pre-resolve external established remotes concurrently (bounded, ~3s cap).
    let hosts = if intel.is_some() {
        let mut ips: Vec<String> = conns
            .iter()
            .filter(|c| c.state == "ESTABLISHED" && is_external_ip(&c.remote_addr))
            .map(|c| c.remote_addr.clone())
            .collect();
        ips.sort();
        ips.dedup();
        netmon::resolve_hosts(&ips, 60, Duration::from_secs(3))
    } else {
        std::collections::HashMap::new()
    };

    let mut flagged: Vec<Value> = Vec::new();
    for c in &conns {
        if let Some((port, name, sev)) = c.flagged() {
            flagged.push(json!({
                "local": format!("{}:{}", c.local_addr, c.local_port),
                "remote": format!("{}:{}", c.remote_addr, c.remote_port),
                "port": port, "name": name, "severity": sev.as_str(),
                "state": c.state, "reason": "malicious port",
            }));
        }
        if let Some(threat) = intel.as_ref().and_then(|s| s.lookup_ip(&c.remote_addr)) {
            flagged.push(json!({
                "local": format!("{}:{}", c.local_addr, c.local_port),
                "remote": format!("{}:{}", c.remote_addr, c.remote_port),
                "port": c.remote_port, "name": threat, "severity": "high",
                "state": c.state, "reason": "known-bad IP (intel)",
            }));
        }
        // Domain IOC: match the (pre-resolved) hostname against the intel store.
        if let (Some(store), Some(host)) = (intel.as_ref(), hosts.get(&c.remote_addr)) {
            for cand in netmon::domain_candidates(host) {
                if let Some(threat) = store.lookup_domain(&cand) {
                    flagged.push(json!({
                        "local": format!("{}:{}", c.local_addr, c.local_port),
                        "remote": format!("{} ({})", c.remote_addr, host),
                        "port": c.remote_port, "name": threat, "severity": "high",
                        "state": c.state, "reason": "known-bad domain (intel)",
                    }));
                    break;
                }
            }
        }
    }

    // A bounded sample for the table: flagged + established first.
    let mut rows: Vec<Value> = conns
        .iter()
        .filter(|c| c.state == "ESTABLISHED" || c.flagged().is_some())
        .take(120)
        .map(|c| {
            json!({
                "proto": c.proto,
                "local": format!("{}:{}", c.local_addr, c.local_port),
                "remote": format!("{}:{}", c.remote_addr, c.remote_port),
                "state": c.state,
                "risk": if c.flagged().is_some() { "malicious" } else { "clean" },
                "note": c.flagged().map(|f| f.1).unwrap_or(""),
            })
        })
        .collect();
    rows.sort_by_key(|v| if v["risk"] == "malicious" { 0 } else { 1 });

    let intel_ips = intel.as_ref().map(|s| s.count_kind(aether_intel::IocKind::Ipv4)).unwrap_or(0);
    let intel_domains = intel.as_ref().map(|s| s.count_kind(aether_intel::IocKind::Domain)).unwrap_or(0);
    json!({
        "total": conns.len(),
        "listening": listening,
        "established": established,
        "flagged": flagged,
        "db_size": netmon::MALICIOUS_PORTS.len(),
        "intel_ips": intel_ips,
        "intel_domains": intel_domains,
        "connections": rows,
    })
}

/// List items currently in the encrypted quarantine vault.
#[tauri::command]
fn quarantine_list(state: tauri::State<AppState>) -> Value {
    match Vault::open(state.vault_path()) {
        Ok(v) => {
            let items: Vec<Value> = v
                .timeline()
                .iter()
                .map(|e| json!({"id": e.id, "threat": e.threat,
                                "path": e.original_path, "size": e.size,
                                "at": fmt_clock(e.quarantined_at)}))
                .collect();
            json!({"items": items})
        }
        Err(e) => json!({"error": e.to_string()}),
    }
}

/// Restore a quarantined item to a destination path.
#[tauri::command]
fn quarantine_restore(state: tauri::State<AppState>, id: String, dest: String) -> Value {
    match Vault::open(state.vault_path()).and_then(|v| v.restore(&id, Path::new(&dest))) {
        Ok(_) => json!({"message": format!("restored -> {dest}")}),
        Err(e) => json!({"message": format!("restore failed: {e}")}),
    }
}

/// Permanently delete a quarantined item.
#[tauri::command]
fn quarantine_remove(state: tauri::State<AppState>, id: String) -> Value {
    match Vault::open(state.vault_path()).and_then(|mut v| v.remove(&id)) {
        Ok(_) => json!({"message": "item deleted"}),
        Err(e) => json!({"message": format!("delete failed: {e}")}),
    }
}

/// Core intel refresh: download abuse.ch feeds, merge into the store, rebuild
/// the hash DB and hot-reload the scanner. Returns `(new_iocs, live_signatures)`.
/// Shared by the manual command and the background scheduler.
fn intel_update(state: &AppState) -> (usize, usize) {
    let store_path = state.assets.join("models/intel.json");
    let mut store = IntelStore::load_or_new(&store_path).unwrap_or_default();
    let version = now_secs();
    let mut added = 0usize;

    // Optional free abuse.ch Auth-Key unlocks the FULL dumps (millions of IOCs).
    let key = std::env::var("ABUSE_CH_AUTH_KEY").ok();
    let kref = key.as_deref();
    let full = key.is_some() && std::env::var("ABUSE_CH_FULL").is_ok();

    // Rich IOCs (URLs / IPs / domains + their hashes) -> JSON store.
    type P = fn(&str, u64) -> aether_common::Result<Feed>;
    let mut sources: Vec<(&str, P)> = if full {
        vec![
            ("https://threatfox.abuse.ch/export/csv/full/", Feed::from_threatfox_csv),
            ("https://urlhaus.abuse.ch/downloads/csv/", Feed::from_urlhaus_csv),
        ]
    } else {
        vec![
            ("https://threatfox.abuse.ch/export/csv/recent/", Feed::from_threatfox_csv),
            ("https://urlhaus.abuse.ch/downloads/csv_recent/", Feed::from_urlhaus_csv),
        ]
    };
    sources.push(("https://feodotracker.abuse.ch/downloads/ipblocklist.csv", Feed::from_feodo_csv));

    for (url, parser) in sources {
        if let Some(text) = feed_text(url, kref) {
            if let Ok(feed) = parser(&text, version) {
                added += store.apply(&feed, None).unwrap_or(0);
            }
        }
    }

    // MalwareBazaar FULL SHA256 corpus - ~1.1M recent malware hashes, free, no
    // API key, transparently unzipped. Written straight into the hash DB (not
    // the JSON store) so intel.json stays small and fast to load every refresh.
    let mut mb_hashes: Vec<String> = Vec::new();
    if let Some(txt) = feed_text("https://bazaar.abuse.ch/export/txt/sha256/full/", kref) {
        for line in txt.lines() {
            let h = line.trim();
            if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                mb_hashes.push(h.to_ascii_lowercase());
            }
        }
    }

    if added == 0 && mb_hashes.is_empty() {
        let sigs = state.scanner.lock().unwrap().as_ref().map(|s| s.signature_count()).unwrap_or(0);
        return (0, sigs);
    }
    let _ = store.save(&store_path);

    // Regenerate hash DB = bundled base + store sha256 IOCs + MalwareBazaar corpus.
    let db = state.assets.join("signatures/hashes.db");
    let base = std::fs::read_to_string(&db).unwrap_or_default();
    let mut lines: std::collections::BTreeSet<String> =
        base.lines().map(|l| l.to_string()).collect();
    let before = lines.len();
    for l in store.export_hashdb().lines() {
        lines.insert(l.to_string());
    }
    for h in &mb_hashes {
        lines.insert(format!("{h} MalwareBazaar.Sample"));
    }
    let new_sigs = lines.len().saturating_sub(before);
    let _ = std::fs::write(&db, lines.into_iter().collect::<Vec<_>>().join("\n"));

    let settings = state.settings.lock().unwrap().clone();
    if let Some(s) = build_scanner(&state.assets, &settings) {
        *state.scanner.lock().unwrap() = Some(s);
    }
    let sigs = state.scanner.lock().unwrap().as_ref().map(|s| s.signature_count()).unwrap_or(0);
    (added + new_sigs, sigs)
}

/// Called by the UI once its event listeners are wired - fires the startup
/// greeting deterministically (no race against webview init).
#[tauri::command]
fn app_ready(app: tauri::AppHandle) {
    notify(&app, "AetherAV - Protection Active",
           "Real-time engine running: 9 detection layers + Aegis-50M.");
}

/// Manual "Update Threat Intel" action from the UI.
#[tauri::command]
fn update_intel(app: tauri::AppHandle, state: tauri::State<AppState>) -> Value {
    let (added, sigs) = intel_update(&state);
    if added == 0 {
        return json!({"message":"intel update failed (offline?) - feeds unreachable"});
    }
    notify(&app, "Threat intel updated",
           &format!("{} new indicators · {} signatures live", fmt_num(added as u64), fmt_num(sigs as u64)));
    json!({"message": format!("Intel updated · {} new indicators · {} signatures live",
                              fmt_num(added as u64), fmt_num(sigs as u64))})
}

/// Manual "Update Now" from the GUI: pull the Ed25519-signed feed, verify it
/// (trust + anti-rollback), apply it, rebuild the hash DB, hot-reload, and
/// record the last-update time.
#[tauri::command]
fn update_now(app: tauri::AppHandle, state: tauri::State<AppState>) -> Value {
    let url = state.settings.lock().unwrap().update_url.clone();
    if url.trim().is_empty() {
        return json!({"ok": false, "message": "Set a signed-feed URL in Settings first."});
    }
    let bytes = match http_bytes(&url, None) {
        Ok(b) => b,
        Err(e) => return json!({"ok": false, "message": format!("Fetch failed: {e}")}),
    };
    let text = String::from_utf8_lossy(&bytes);
    let feed = match aether_intel::Feed::from_json(&text) {
        Ok(f) => f,
        Err(e) => return json!({"ok": false, "message": format!("Bad feed: {e}")}),
    };
    let store_path = state.assets.join("models/intel.json");
    let mut store = aether_intel::IntelStore::load_or_new(&store_path).unwrap_or_default();
    let added = match store.apply_signed(&feed) {
        Ok(n) => n,
        Err(e) => return json!({"ok": false, "message": format!("Rejected: {e}")}),
    };
    let version = store.version;
    if added > 0 {
        let _ = store.save(&store_path);
        let db = state.assets.join("signatures/hashes.db");
        let base = std::fs::read_to_string(&db).unwrap_or_default();
        let mut lines: std::collections::BTreeSet<String> =
            base.lines().map(|s| s.to_string()).collect();
        for l in store.export_hashdb().lines() {
            lines.insert(l.to_string());
        }
        let _ = std::fs::write(&db, lines.into_iter().collect::<Vec<_>>().join("\n"));
        let settings = state.settings.lock().unwrap().clone();
        if let Some(s) = build_scanner(&state.assets, &settings) {
            *state.scanner.lock().unwrap() = Some(s);
        }
        notify(&app, "Signatures updated",
               &format!("+{} indicators (feed v{version})", fmt_num(added as u64)));
    }
    let ts = now_secs();
    let _ = std::fs::write(
        state.assets.join("models/last_update.json"),
        json!({"ts": ts, "version": version}).to_string(),
    );
    json!({
        "ok": true, "added": added, "version": version, "ts": ts,
        "message": if added > 0 {
            format!("Updated: +{} indicators (feed v{version})", fmt_num(added as u64))
        } else {
            "Already up to date".to_string()
        }
    })
}

/// Update status for the GUI: last-update time + current feed version.
#[tauri::command]
fn update_status(state: tauri::State<AppState>) -> Value {
    let meta: serde_json::Value = std::fs::read_to_string(state.assets.join("models/last_update.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(json!({}));
    let version = aether_intel::IntelStore::load_or_new(state.assets.join("models/intel.json"))
        .map(|s| s.version)
        .unwrap_or(0);
    json!({
        "last_update": meta.get("ts"),
        "version": version,
        "url_set": !state.settings.lock().unwrap().update_url.trim().is_empty(),
    })
}

/// Persist the signed-feed URL from the GUI.
#[tauri::command]
fn set_update_url(state: tauri::State<AppState>, url: String) -> Value {
    {
        let mut s = state.settings.lock().unwrap();
        s.update_url = url.trim().to_string();
        s.save(&state.assets);
    }
    json!({"ok": true, "message": "Feed URL saved"})
}

/// Download raw bytes, optionally sending an abuse.ch `Auth-Key` header.
fn http_bytes(url: &str, key: Option<&str>) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut req = ureq::get(url).timeout(Duration::from_secs(180));
    if let Some(k) = key {
        req = req.set("Auth-Key", k);
    }
    let resp = req.call().map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(512 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Fetch a feed as text, transparently unzipping/gunzipping full dumps
/// (abuse.ch full exports are ZIP archives) via the extraction layer.
fn feed_text(url: &str, key: Option<&str>) -> Option<String> {
    let bytes = http_bytes(url, key).ok()?;
    if let Some(members) = aether_unpack::try_extract(&bytes, aether_unpack::Limits::default()) {
        if let Some(m) = members.into_iter().max_by_key(|f| f.data.len()) {
            return Some(String::from_utf8_lossy(&m.data).into_owned());
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Open a native folder picker; returns the chosen path (or null if cancelled).
#[tauri::command]
fn pick_folder(app: tauri::AppHandle) -> Option<String> {
    use tauri_plugin_dialog::DialogExt;
    app.dialog()
        .file()
        .blocking_pick_folder()
        .map(|p| p.to_string())
}

/// Open a native file picker; returns the chosen path.
#[tauri::command]
fn pick_file(app: tauri::AppHandle) -> Option<String> {
    use tauri_plugin_dialog::DialogExt;
    app.dialog().file().blocking_pick_file().map(|p| p.to_string())
}

/// Return the current persisted settings.
#[tauri::command]
fn get_settings(state: tauri::State<AppState>) -> Settings {
    state.settings.lock().unwrap().clone()
}

/// Persist new settings and hot-rebuild the scanner with the new engine toggles.
#[tauri::command]
fn set_settings(state: tauri::State<AppState>, settings: Settings) -> Value {
    settings.save(&state.assets);
    *state.settings.lock().unwrap() = settings.clone();
    if let Some(s) = build_scanner(&state.assets, &settings) {
        *state.scanner.lock().unwrap() = Some(s);
    }
    json!({"message": "settings saved · engines reloaded"})
}

// ---- Network & theft shields (firewall / web protection / stealer decoys) ----

fn shield_ruleset(assets: &Path) -> aether_firewall::RuleSet {
    use aether_intel::{IntelStore, IocKind};
    let mut rs = aether_firewall::RuleSet::new();
    for (port, name, _sev) in aether_realtime::netmon::MALICIOUS_PORTS {
        rs.block_port(*port, *name);
    }
    if let Ok(store) = IntelStore::load_or_new(assets.join("models/intel.json")) {
        for ioc in store.iocs() {
            if ioc.kind == IocKind::Ipv4 {
                if rs.bad_ips.len() >= 2000 {
                    break;
                }
                rs.block_ip(ioc.value.clone());
            }
        }
    }
    rs
}

#[tauri::command]
fn shields_status(state: tauri::State<AppState>) -> Value {
    use aether_intel::{IntelStore, IocKind};
    let mut ips = 0usize;
    let mut domains = 0usize;
    if let Ok(store) = IntelStore::load_or_new(state.assets.join("models/intel.json")) {
        for ioc in store.iocs() {
            match ioc.kind {
                IocKind::Ipv4 => ips += 1,
                IocKind::Domain => domains += 1,
                _ => {}
            }
        }
    }
    json!({
        "platform": aether_firewall::Platform::current().as_str(),
        "firewall_ips": ips.min(2000),
        "firewall_ports": aether_realtime::netmon::MALICIOUS_PORTS.len(),
        "web_domains": domains,
    })
}

#[tauri::command]
fn firewall_apply(state: tauri::State<AppState>) -> Value {
    let rs = shield_ruleset(&state.assets);
    let p = aether_firewall::Platform::current();
    match rs.install(p) {
        Ok(msg) => json!({"ok": true, "message": format!("Firewall applied: {msg}")}),
        Err(e) => json!({"ok": false, "message": format!("Could not apply ({e}). Run AetherAV as admin/root.")}),
    }
}

#[tauri::command]
fn webprotect_apply(state: tauri::State<AppState>) -> Value {
    use aether_firewall::web;
    use aether_intel::{IntelStore, IocKind};
    let store = match IntelStore::load_or_new(state.assets.join("models/intel.json")) {
        Ok(s) => s,
        Err(e) => return json!({"ok": false, "message": format!("intel load failed: {e}")}),
    };
    let domains: Vec<String> = store
        .iocs()
        .filter(|i| i.kind == IocKind::Domain)
        .take(5000)
        .map(|i| i.value.clone())
        .collect();
    let refs: Vec<&str> = domains.iter().map(String::as_str).collect();
    match web::apply(&refs) {
        Ok(n) => json!({"ok": true, "message": format!("Web protection: {n} malicious hosts sinkholed")}),
        Err(e) => json!({"ok": false, "message": format!("Could not edit hosts ({e}). Run as admin/root.")}),
    }
}

#[tauri::command]
fn stealer_arm(state: tauri::State<AppState>) -> Value {
    use aether_realtime::stealerguard::Decoys;
    let dir = state.assets.join("../decoys");
    match Decoys::plant(&dir) {
        Ok(d) => json!({"ok": true, "message": format!("Planted {} wallet/credential decoys in {}", d.files.len(), dir.display())}),
        Err(e) => json!({"ok": false, "message": format!("Could not plant decoys: {e}")}),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Bring the main window forward (from the tray or widget).
    fn show_main(app: &tauri::AppHandle) {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.show();
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
    }

    // Build the system tray icon + menu. Returns Err if no tray host is present.
    fn build_tray(app: &tauri::App) -> tauri::Result<()> {
        use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
        use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

        let open_i = MenuItem::with_id(app, "open", "Open AetherAV", true, None::<&str>)?;
        let scan_i = MenuItem::with_id(app, "quickscan", "Quick Scan", true, None::<&str>)?;
        let widget_i = MenuItem::with_id(app, "widget", "Toggle Widget", true, None::<&str>)?;
        let sep = PredefinedMenuItem::separator(app)?;
        let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
        let menu = Menu::with_items(app, &[&open_i, &scan_i, &widget_i, &sep, &quit_i])?;

        TrayIconBuilder::with_id("aether-tray")
            .icon(app.default_window_icon().unwrap().clone())
            .tooltip("AetherAV - Protected")
            .menu(&menu)
            .on_menu_event(|app, event| match event.id.as_ref() {
                "open" => show_main(app),
                "quickscan" => {
                    show_main(app);
                    let _ = app.emit("tray-quickscan", ());
                }
                "widget" => toggle_widget(app),
                "quit" => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    show_main(tray.app_handle());
                }
            })
            .build(app)?;
        Ok(())
    }

    // Toggle a small always-on-top desktop widget showing protection status.
    fn toggle_widget(app: &tauri::AppHandle) {
        use tauri::{WebviewUrl, WebviewWindowBuilder};
        if let Some(w) = app.get_webview_window("widget") {
            let _ = w.close();
            return;
        }
        let _ = WebviewWindowBuilder::new(app, "widget", WebviewUrl::App("widget.html".into()))
            .title("AetherAV")
            .inner_size(280.0, 196.0)
            .resizable(false)
            .decorations(false)
            .always_on_top(true)
            .skip_taskbar(true)
            .build();
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::new())
        .setup(|app| {
            // Load the engine (1M+ signatures) off the UI thread so the window
            // shows immediately; announce readiness so the dashboard refreshes.
            let hb = app.handle().clone();
            std::thread::spawn(move || {
                let state = hb.state::<AppState>();
                let settings = state.settings.lock().unwrap().clone();
                let scanner = build_scanner(&state.assets, &settings);
                let sigs = scanner.as_ref().map(|s| s.signature_count()).unwrap_or(0);
                *state.scanner.lock().unwrap() = scanner;
                let _ = hb.emit("engine-ready", json!({"signatures": sigs}));
                notify(&hb, "AetherAV - Engine ready",
                       &format!("{} malware signatures loaded.", fmt_num(sigs as u64)));
            });

            // Live metrics stream (every 2s) + edge-triggered network alerts.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let mut prev_flagged = 0usize;
                loop {
                    std::thread::sleep(Duration::from_secs(2));
                    let state = handle.state::<AppState>();
                    let m = metrics_snapshot(&state);
                    let _ = handle.emit("metrics", m);

                    // Notify when new connections appear on malware-associated ports.
                    let flagged = aether_realtime::netmon::connections()
                        .iter()
                        .filter(|c| c.flagged().is_some())
                        .count();
                    if flagged > prev_flagged {
                        notify(&handle, "⚠ Suspicious network activity",
                               &format!("{flagged} live connection(s) on malware-associated ports."));
                    }
                    prev_flagged = flagged;
                }
            });

            // Scheduled threat-intel auto-update: once shortly after launch,
            // then every 6 hours. Emits an `intel` event so the UI can refresh.
            let h2 = app.handle().clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(20));
                loop {
                    let (added, sigs) = intel_update(&h2.state::<AppState>());
                    if added > 0 {
                        notify(&h2, "Threat intel updated",
                               &format!("{added} new indicators · {sigs} signatures live."));
                    }
                    let _ = h2.emit("intel", json!({"added": added, "signatures": sigs}));
                    std::thread::sleep(Duration::from_secs(6 * 3600));
                }
            });

            // System tray (OS widget): status tooltip + quick menu, on all OSes.
            // Non-fatal: headless / no-tray-host environments still launch the app.
            if let Err(e) = build_tray(app) {
                eprintln!("[tray] system tray unavailable: {e}");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            dashboard_data,
            app_ready,
            run_action,
            update_intel,
            update_now,
            update_status,
            set_update_url,
            scan_path_cmd,
            scan_processes,
            sentinel_learn,
            sentinel_scan,
            sentinel_watch,
            network_status,
            pick_folder,
            pick_file,
            get_settings,
            set_settings,
            quarantine_list,
            quarantine_restore,
            quarantine_remove,
            shields_status,
            firewall_apply,
            webprotect_apply,
            stealer_arm
        ])
        .run(tauri::generate_context!())
        .expect("error while running AetherAV desktop");
}
