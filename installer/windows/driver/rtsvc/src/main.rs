//! AetherAV real-time user-mode service (Windows).
//!
//! Companion to the `aetherav.sys` minifilter. It connects to the driver's
//! `\AetherAVPort`, receives a scan request for every file the kernel is about
//! to open/execute, scans the bytes with the real AetherAV engine, and replies
//! allow/deny - so the driver can block malware BEFORE it runs.
//!
//! Runs as a proper Windows Service (auto-start) or, with `--console`, in the
//! foreground for debugging. SCAFFOLD: Windows-only (fltlib via `windows-sys` +
//! `windows-service`); excluded from the root workspace, not compiled on Linux.

#[cfg(not(windows))]
fn main() {
    eprintln!("aether-rtsvc is Windows-only (it drives the aetherav.sys minifilter).");
}

#[cfg(windows)]
fn main() {
    imp::main();
}

#[cfg(windows)]
mod imp {
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    const SERVICE_NAME: &str = "AetherAVRealtime";

    pub fn main() {
        // Foreground debug mode.
        if std::env::args().any(|a| a == "--console") {
            let _ = scan_loop(&AtomicBool::new(true));
            return;
        }
        // Started by the Service Control Manager; if not, fall back to console.
        if service_dispatcher::start(SERVICE_NAME, ffi_service_main).is_err() {
            let _ = scan_loop(&AtomicBool::new(true));
        }
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        let _ = run_service();
    }

    fn run_service() -> windows_service::Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let stop_flag = running.clone();
        let handler = move |control| -> ServiceControlHandlerResult {
            match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    stop_flag.store(false, Ordering::SeqCst);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status = service_control_handler::register(SERVICE_NAME, handler)?;
        let mut report = |state: ServiceState, accept: ServiceControlAccept| {
            status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
        };
        report(ServiceState::Running, ServiceControlAccept::STOP)?;
        let _ = scan_loop(&running);
        report(ServiceState::Stopped, ServiceControlAccept::empty())?;
        Ok(())
    }

    /// Connect to the minifilter and answer scan requests until `running` clears.
    fn scan_loop(running: &AtomicBool) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::InstallableFileSystems::{
            FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage,
            FILTER_MESSAGE_HEADER, FILTER_REPLY_HEADER,
        };

        // Must match the structs in aetherav.c.
        #[repr(C)]
        struct ScanRequest {
            header: FILTER_MESSAGE_HEADER,
            path: [u16; 520],
        }
        #[repr(C)]
        struct ScanReply {
            header: FILTER_REPLY_HEADER,
            block: u32,
        }

        let cfg = aether_config::Config::load_or_default(None).unwrap_or_default();
        let scanner = aether_core::Scanner::new(cfg).map_err(|e| format!("engine: {e}"))?;

        let port_name: Vec<u16> = std::ffi::OsStr::new("\\AetherAVPort")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut port: HANDLE = 0;
        let hr = unsafe {
            FilterConnectCommunicationPort(
                port_name.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                &mut port,
            )
        };
        if hr != 0 {
            return Err(format!(
                "could not connect to \\AetherAVPort (hr=0x{hr:08x}); is aetherav.sys loaded?"
            ));
        }

        while running.load(Ordering::SeqCst) {
            let mut req: ScanRequest = unsafe { std::mem::zeroed() };
            let hr = unsafe {
                FilterGetMessage(
                    port,
                    &mut req.header,
                    std::mem::size_of::<ScanRequest>() as u32,
                    std::ptr::null_mut(),
                )
            };
            if hr != 0 {
                break;
            }
            let len = req.path.iter().position(|&c| c == 0).unwrap_or(req.path.len());
            let path = String::from_utf16_lossy(&req.path[..len]);
            let block = match scanner.scan_file(std::path::Path::new(&path)) {
                Ok(report) => report.disposition().is_malicious() as u32,
                Err(_) => 0, // fail open: never block on a scan error
            };
            let mut reply = ScanReply {
                header: FILTER_REPLY_HEADER {
                    Status: 0,
                    MessageId: req.header.MessageId,
                },
                block,
            };
            unsafe {
                FilterReplyMessage(
                    port,
                    &mut reply.header,
                    std::mem::size_of::<ScanReply>() as u32,
                );
            }
        }
        Ok(())
    }
}
