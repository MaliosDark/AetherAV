# AetherAV Windows minifilter (kernel-level real-time)

This is the **blueprint/scaffold** for true pre-execution blocking on Windows -
the equivalent of Linux `fanotify` (`aether protect`). It is a file-system
**minifilter**: it intercepts every file open/execute (`IRP_MJ_CREATE`), asks the
user-mode AetherAV service to scan the file, and **denies the open** when the
verdict is malicious - before the code can run.

## Architecture
```
kernel: aetherav.sys (this minifilter)  <-- FltSendMessage -->  user mode: AetherAV service (aether-core scanner)
            IRP_MJ_CREATE pre-op                                    scans bytes, returns allow/deny
```
- `aetherav.c`  - the minifilter (pre-create callback + communication port).
- `aetherav.inf` - install/altitude/service registration (load group "FSFilter Anti-Virus").
- User-mode side: a small Windows service that opens `\AetherAVPort` and answers
  scan requests using the existing engine (reuse `aether-core`).

## Build (Windows only)
1. Install **Visual Studio + the Windows Driver Kit (WDK)**.
2. Create a "Kernel Mode Driver (KMDF/empty)" project, add `aetherav.c` + `aetherav.inf`.
3. Build `aetherav.sys` (x64).

## Signing (required to load on modern Windows)
Kernel drivers need more than Authenticode:
1. An **EV code-signing certificate**.
2. Register on the **Microsoft Partner Center** and submit the driver for
   **attestation signing** (or full WHQL). Without this, 64-bit Windows refuses
   to load the driver (except in test-signing mode).

## Why it is not built here
It requires the WDK + a Windows kernel toolchain (cannot compile on Linux) and a
signed driver to load. Until then, AetherAV's Windows real-time protection runs
in **user mode** (the on-access watcher auto-started by the installer), which
detects + quarantines on file change but does not block pre-execution. This
minifilter is the upgrade path to kernel-level blocking.

## Run the user-mode service (`aether-rtsvc`)
Build (on Windows): `cargo build --release` inside `rtsvc/` -> `aether-rtsvc.exe`.
Register + start as an auto-start Windows Service (run elevated):
```cmd
sc create AetherAVRealtime binPath= "C:\Program Files\AetherAV\aether-rtsvc.exe" start= auto
sc description AetherAVRealtime "AetherAV real-time on-access scanning"
sc start AetherAVRealtime
```
Debug in the foreground: `aether-rtsvc.exe --console`.

Note: the service needs `aetherav.sys` loaded to connect to `\AetherAVPort`.
Until the signed driver is deployed, the installer's Real-Time component uses the
user-mode on-access watcher (`aether watch`) instead, which works without a driver.
