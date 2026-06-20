//! Structured logging setup, shared by the CLI and (later) the daemon.
//!
//! We use `tracing` rather than `log` because the behavioral/graph engines on
//! the roadmap emit spans (process trees, scan pipelines) that benefit from
//! structured, nestable instrumentation.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Output format for logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-friendly, colored, single-line records (default for the CLI).
    Pretty,
    /// One JSON object per line - for the daemon / SIEM ingestion.
    Json,
}

/// Initialize the global tracing subscriber.
///
/// `directive` follows the `RUST_LOG` syntax (e.g. `info`, `aether_core=debug`).
/// Respects the `RUST_LOG` env var when present, falling back to `directive`.
///
/// Safe to call once at startup; subsequent calls are ignored by `tracing`.
pub fn init(directive: &str, format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directive));

    let registry = tracing_subscriber::registry().with(filter);

    // Logs always go to stderr so stdout stays clean for scan output (JSON
    // piping, ClamAV-style `| grep FOUND`, etc.).
    match format {
        LogFormat::Pretty => {
            let layer = fmt::layer()
                .with_target(false)
                .with_level(true)
                .with_writer(std::io::stderr);
            let _ = registry.with(layer).try_init();
        }
        LogFormat::Json => {
            let layer = fmt::layer()
                .json()
                .with_current_span(true)
                .with_writer(std::io::stderr);
            let _ = registry.with(layer).try_init();
        }
    }
}
