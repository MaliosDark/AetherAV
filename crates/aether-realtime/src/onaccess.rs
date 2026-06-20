//! Real-time **on-access** protection via Linux `fanotify` - the capability
//! that turns a scanner into a *protector*. We register for permission events
//! (`FAN_OPEN_PERM` / `FAN_OPEN_EXEC_PERM`) on a mount, so the kernel **pauses
//! every open/exec and asks us** whether to allow it. We scan the bytes and
//! reply `FAN_ALLOW` or `FAN_DENY` - blocking malware *before* it runs, exactly
//! like a commercial endpoint agent's minifilter/ES-extension.
//!
//! Requires `CAP_SYS_ADMIN` (run as root). Linux-only.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::mem::size_of;
use std::path::{Path, PathBuf};

// fanotify constants (stable kernel ABI; defined locally to avoid libc version
// skew on the newer FAN_* flags).
const FAN_CLOEXEC: u32 = 0x0000_0001;
const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;
const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_MOUNT: u32 = 0x0000_0010;
const METADATA_VERSION: u8 = 3;

#[repr(C)]
struct EventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[repr(C)]
struct Response {
    fd: i32,
    response: u32,
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// A running on-access protection guard bound to one or more mounts.
pub struct OnAccessGuard {
    fd: i32,
    self_pid: i32,
}

impl OnAccessGuard {
    /// Initialise fanotify and mark the mount(s) containing `paths` for
    /// open/exec permission events.
    pub fn new(paths: &[PathBuf]) -> Result<OnAccessGuard, String> {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_fanotify_init,
                (FAN_CLOEXEC | FAN_CLASS_CONTENT) as libc::c_uint,
                (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE) as libc::c_uint,
            )
        } as i32;
        if fd < 0 {
            let e = errno();
            if e == libc::EPERM {
                return Err("fanotify_init failed: needs root / CAP_SYS_ADMIN".into());
            }
            return Err(format!("fanotify_init failed (errno {e})"));
        }

        for p in paths {
            let c = CString::new(p.as_os_str().to_string_lossy().as_bytes())
                .map_err(|_| "path contains NUL".to_string())?;
            let r = unsafe {
                libc::syscall(
                    libc::SYS_fanotify_mark,
                    fd,
                    (FAN_MARK_ADD | FAN_MARK_MOUNT) as libc::c_uint,
                    FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM,
                    libc::AT_FDCWD,
                    c.as_ptr(),
                )
            };
            if r < 0 {
                let e = errno();
                unsafe { libc::close(fd) };
                return Err(format!("fanotify_mark({}) failed (errno {e})", p.display()));
            }
        }

        Ok(OnAccessGuard {
            fd,
            self_pid: std::process::id() as i32,
        })
    }

    /// Resolve the path behind an event fd via `/proc/self/fd/<fd>`.
    fn fd_path(fd: i32) -> PathBuf {
        let link = format!("/proc/self/fd/{fd}");
        std::fs::read_link(&link).unwrap_or_else(|_| PathBuf::from("<unknown>"))
    }

    /// Read up to `cap` bytes from an event fd without moving its offset.
    fn read_fd(fd: i32, cap: usize) -> Vec<u8> {
        let mut buf = vec![0u8; cap];
        let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, cap, 0) };
        if n > 0 {
            buf.truncate(n as usize);
            buf
        } else {
            Vec::new()
        }
    }

    fn respond(&self, fd: i32, allow: bool) {
        let resp = Response {
            fd,
            response: if allow { FAN_ALLOW } else { FAN_DENY },
        };
        unsafe {
            libc::write(
                self.fd,
                &resp as *const Response as *const libc::c_void,
                size_of::<Response>(),
            );
        }
    }

    /// Blocking event loop. For each open/exec, `decide(path, bytes)` returns
    /// `true` to allow or `false` to block. Our own process's opens are always
    /// allowed (prevents self-deadlock). `max_read` caps bytes handed to
    /// `decide` per file.
    pub fn run<F>(&self, max_read: usize, mut decide: F) -> Result<(), String>
    where
        F: FnMut(&Path, &[u8]) -> bool,
    {
        self.run_detailed(max_read, |_pid, path, data| decide(path, data))
    }

    /// Like [`run`](Self::run) but the callback also receives the opening PID,
    /// so callers can block the *source* process (e.g. kill an infostealer that
    /// reads a decoy). Returns `true` to allow, `false` to deny.
    pub fn run_detailed<F>(&self, max_read: usize, mut decide: F) -> Result<(), String>
    where
        F: FnMut(i32, &Path, &[u8]) -> bool,
    {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n =
                unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return Err(format!("read failed (errno {e})"));
            }
            if n == 0 {
                continue;
            }

            let mut off: usize = 0;
            let total = n as usize;
            while total - off >= size_of::<EventMetadata>() {
                // SAFETY: we verified at least one metadata struct remains.
                let meta = unsafe { &*(buf.as_ptr().add(off) as *const EventMetadata) };
                if meta.vers != METADATA_VERSION
                    || (meta.event_len as usize) < size_of::<EventMetadata>()
                {
                    break;
                }
                let is_perm = meta.mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM) != 0;
                if meta.fd >= 0 {
                    if is_perm {
                        // Never gate our own I/O (would deadlock the loop).
                        let allow = if meta.pid == self.self_pid {
                            true
                        } else {
                            let path = Self::fd_path(meta.fd);
                            let data = Self::read_fd(meta.fd, max_read);
                            decide(meta.pid, &path, &data)
                        };
                        self.respond(meta.fd, allow);
                    }
                    unsafe { libc::close(meta.fd) };
                }
                off += meta.event_len as usize;
            }
        }
    }
}

impl Drop for OnAccessGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
