# Build the AetherAV Windows installer. Run on Windows with Rust + NSIS installed.
#
# Optional Authenticode signing (required for a SmartScreen-clean download):
#   $env:WIN_CERT_PFX  = "C:\path\aetherav.pfx"
#   $env:WIN_CERT_PASS = "..."
param([string]$Version = "2026.1.0")
$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path "$PSScriptRoot\..\..")

Write-Host ">> building release binaries"
cargo build --release -p aether-cli
cargo build --release --manifest-path desktop/src-tauri/Cargo.toml

$payload = "installer\windows\payload"
New-Item -ItemType Directory -Force -Path $payload, "$payload\assets" | Out-Null
Copy-Item "target\release\aether.exe" "$payload\aether.exe" -Force
Copy-Item "desktop\src-tauri\target\release\aether-desktop.exe" "$payload\aether-desktop.exe" -Force
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

# Sign the binaries before packaging, then build + sign the installer.
Sign-File "$payload\aether.exe"
Sign-File "$payload\aether-desktop.exe"

Write-Host ">> running makensis"
& makensis "installer\windows\aetherav.nsi"

$setup = "installer\windows\AetherAV-Setup.exe"
Sign-File $setup

New-Item -ItemType Directory -Force -Path dist | Out-Null
Copy-Item $setup "dist\AetherAV-Setup-$Version.exe" -Force
Write-Host ">> built: dist\AetherAV-Setup-$Version.exe"
