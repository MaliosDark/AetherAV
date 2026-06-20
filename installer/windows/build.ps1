# Build the AetherAV Windows installer. Run on Windows with Rust + NSIS installed.
#
# The CLI engine is required; the Tauri desktop GUI is best-effort - if it does
# not build (e.g. missing WebView2 tooling) we still ship a working CLI-only
# installer (engine + real-time protection + PATH + context menu).
#
# Optional Authenticode signing (SmartScreen-clean download):
#   $env:WIN_CERT_PFX  = "C:\path\aetherav.pfx"
#   $env:WIN_CERT_PASS = "..."
param([string]$Version = "2026.1.0")
$ErrorActionPreference = "Stop"
# PowerShell 7.4+ otherwise THROWS on any native non-zero exit (e.g. the
# best-effort GUI build), aborting before our explicit $LASTEXITCODE checks.
# We handle native exit codes ourselves, so disable that auto-throw.
$PSNativeCommandUseErrorActionPreference = $false
Set-Location (Resolve-Path "$PSScriptRoot\..\..")

Write-Host ">> building CLI engine (required)"
cargo build --release -p aether-cli
if ($LASTEXITCODE -ne 0) { throw "aether-cli build failed (exit $LASTEXITCODE)" }

Write-Host ">> building desktop GUI (best-effort)"
$gui = $false
cargo build --release --manifest-path desktop/src-tauri/Cargo.toml
if ($LASTEXITCODE -eq 0 -and (Test-Path "desktop\src-tauri\target\release\aether-desktop.exe")) {
  $gui = $true
  Write-Host "   desktop GUI built OK"
} else {
  Write-Host "   desktop GUI did not build -> CLI-only installer"
}

$payload = "installer\windows\payload"
New-Item -ItemType Directory -Force -Path $payload, "$payload\assets" | Out-Null
Copy-Item "target\release\aether.exe" "$payload\aether.exe" -Force
if ($gui) { Copy-Item "desktop\src-tauri\target\release\aether-desktop.exe" "$payload\aether-desktop.exe" -Force }
Copy-Item "assets\*" "$payload\assets\" -Recurse -Force

function Sign-File($file) {
  if ($env:WIN_CERT_PFX) {
    Write-Host ">> signing $file"
    & signtool sign /f $env:WIN_CERT_PFX /p $env:WIN_CERT_PASS /fd SHA256 `
        /tr http://timestamp.digicert.com /td SHA256 $file
  } else {
    Write-Host "   (skip signing $file - set WIN_CERT_PFX to enable)"
  }
}

Sign-File "$payload\aether.exe"
if ($gui) { Sign-File "$payload\aether-desktop.exe" }

Write-Host ">> running makensis (GUI=$gui)"
if ($gui) {
  & makensis /DWITH_GUI "installer\windows\aetherav.nsi"
} else {
  & makensis "installer\windows\aetherav.nsi"
}
if ($LASTEXITCODE -ne 0) { throw "makensis failed (exit $LASTEXITCODE)" }

$setup = "installer\windows\AetherAV-Setup.exe"
Sign-File $setup
New-Item -ItemType Directory -Force -Path dist | Out-Null
Copy-Item $setup "dist\AetherAV-Setup-$Version.exe" -Force
Write-Host ">> built: dist\AetherAV-Setup-$Version.exe (GUI=$gui)"
