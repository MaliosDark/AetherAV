# AetherAV Desktop (Tauri v2)

A cross-platform desktop GUI for the AetherAV engine - **Windows, macOS and
Linux** from one codebase. Rust backend (`src-tauri`, a thin shell over the
engine crates) + a dependency-free static frontend (`ui/`, plain HTML/CSS/JS,
no bundler/npm build step).

```
desktop/
+-- ui/                 # frontend (open ui/index.html in any browser to preview)
|   +-- index.html
|   +-- styles.css
|   +-- app.js          # renders the dashboard; talks to the engine via Tauri
+-- src-tauri/          # Rust app (its own workspace; not part of the engine workspace)
    +-- Cargo.toml
    +-- tauri.conf.json # window = 1672×941, dark theme, frontendDist = ../ui
    +-- build.rs
    +-- icons/
    +-- src/{main.rs,lib.rs}   # #[tauri::command] dashboard_data / run_action
```

## How it connects to the engine

`src-tauri` depends on `aether-core`, `aether-config` and `aether-common`. The
`dashboard_data` command feeds the UI (signature count, ML status, …) and
`run_action("quick")` runs a real `Scanner::scan_path`. The frontend ships an
identical data fallback, so `ui/index.html` renders the full dashboard even in a
plain browser (no Tauri runtime needed) - handy for design iteration.

## Run / build

Prereqgs: Rust, and the platform webview libs (Linux: `webkit2gtk-4.1`,
`libsoup-3.0`; Windows: WebView2; macOS: built-in WKWebView).

```bash
# from desktop/src-tauri  (no Tauri CLI required - it's a normal cargo binary)
cargo run                      # dev run
cargo build --release          # release binary -> target/release/aether-desktop

# Optional, with the Tauri CLI for installers (.msi/.dmg/.AppImage/.deb):
cargo install tauri-cli --version "^2"
cargo tauri build
```

## Preview the UI without building

```bash
# renders identically using the JS data fallback
xdg-open ui/index.html         # or: open ui/index.html  (macOS)
```

The window is sized 1672×941 to match the reference design; the layout is
responsive and degrades gracefully on smaller windows.
