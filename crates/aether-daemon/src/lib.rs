//! `aether-daemon` - a minimal HTTP/JSON API exposing the engine as a service.
//!
//! Routes:
//! ```text
//!   GET  /health           liveness + engine status
//!   GET  /version          build info
//!   POST /scan             body = raw file bytes        -> scan report (JSON)
//!   POST /behavior         body = JSON event trace      -> behavioral report
//! ```
//!
//! The server is a blocking, thread-per-connection loop over `std::net` - no
//! async runtime - which is the right size for a local control-plane endpoint.
//! [`Daemon::route`] is pure and unit-tested; [`Daemon::serve`] wires it to a
//! socket.

pub mod http;

use aether_behavior::BehaviorEngine;
use aether_core::Scanner;
use std::io::BufReader;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;

/// The API server: shared, immutable engine state.
pub struct Daemon {
    scanner: Arc<Scanner>,
    behavior: BehaviorEngine,
}

impl Daemon {
    pub fn new(scanner: Scanner) -> Daemon {
        Daemon {
            scanner: Arc::new(scanner),
            behavior: BehaviorEngine::new(),
        }
    }

    /// Route a request to a `(status, json)` pair. Pure and testable.
    pub fn route(&self, method: &str, path: &str, body: &[u8]) -> (u16, String) {
        match (method, path) {
            ("GET", "/health") => (
                200,
                serde_json::json!({
                    "status": "ok",
                    "ml": self.scanner.ml_loaded(),
                    "signatures": self.scanner.signature_count(),
                })
                .to_string(),
            ),
            ("GET", "/version") => (
                200,
                serde_json::json!({
                    "name": "AetherAV",
                    "version": env!("CARGO_PKG_VERSION"),
                })
                .to_string(),
            ),
            ("POST", "/scan") => {
                let report = self.scanner.scan_bytes(Path::new("<api>"), body);
                match serde_json::to_string(&report) {
                    Ok(j) => (200, j),
                    Err(e) => (500, err_json(&e.to_string())),
                }
            }
            ("POST", "/behavior") => {
                let text = match std::str::from_utf8(body) {
                    Ok(t) => t,
                    Err(_) => return (400, err_json("body must be UTF-8 JSON")),
                };
                match self.behavior.analyze_json(text) {
                    Ok(report) => (
                        200,
                        serde_json::json!({
                            "disposition": report.disposition().to_string(),
                            "techniques": report.techniques(),
                            "verdicts": report.verdicts,
                            "graph": { "nodes": report.nodes, "edges": report.edges },
                        })
                        .to_string(),
                    ),
                    Err(e) => (400, err_json(&e)),
                }
            }
            _ => (404, err_json("not found")),
        }
    }

    /// Serve forever on `addr` (e.g. `"127.0.0.1:8088"`).
    pub fn serve(self, addr: impl ToSocketAddrs) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        tracing::info!(addr = ?listener.local_addr().ok(), "aether daemon listening");
        self.serve_listener(listener)
    }

    /// Serve on an already-bound listener (lets callers pick an ephemeral port).
    pub fn serve_listener(self, listener: TcpListener) -> std::io::Result<()> {
        let this = Arc::new(self);
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let this = Arc::clone(&this);
                    std::thread::spawn(move || {
                        if let Err(e) = this.handle_connection(stream) {
                            tracing::debug!(error = %e, "connection error");
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, "accept failed"),
            }
        }
        Ok(())
    }

    fn handle_connection(&self, stream: TcpStream) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        if let Some(req) = http::parse_request(&mut reader)? {
            let (status, body) = self.route(&req.method, &req.path, &req.body);
            http::write_response(&mut writer, status, &body)?;
        }
        Ok(())
    }
}

fn err_json(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_config::Config;

    fn daemon() -> Daemon {
        // Hermetic: disable on-disk engines so tests need no assets.
        let mut cfg = Config::default();
        cfg.engines.hash = false;
        cfg.engines.yara = false;
        cfg.engines.ml = false;
        Daemon::new(Scanner::new(cfg).unwrap())
    }

    #[test]
    fn health_and_version() {
        let d = daemon();
        let (s, body) = d.route("GET", "/health", b"");
        assert_eq!(s, 200);
        assert!(body.contains("\"status\":\"ok\""));
        assert_eq!(d.route("GET", "/version", b"").0, 200);
    }

    #[test]
    fn scan_route_returns_report() {
        let d = daemon();
        let (s, body) = d.route("POST", "/scan", b"some bytes");
        assert_eq!(s, 200);
        assert!(body.contains("\"sha256\""));
    }

    #[test]
    fn behavior_route_detects_injection() {
        let d = daemon();
        let trace = br#"[
            {"pid":500,"action":"mem_alloc","target_pid":900,"protection":"RWX"},
            {"pid":500,"action":"remote_thread","target_pid":900}
        ]"#;
        let (s, body) = d.route("POST", "/behavior", trace);
        assert_eq!(s, 200);
        assert!(body.contains("T1055"), "got {body}");
    }

    #[test]
    fn unknown_route_404() {
        assert_eq!(daemon().route("GET", "/nope", b"").0, 404);
    }

    #[test]
    fn behavior_route_rejects_bad_json() {
        assert_eq!(daemon().route("POST", "/behavior", b"not json").0, 400);
    }
}
