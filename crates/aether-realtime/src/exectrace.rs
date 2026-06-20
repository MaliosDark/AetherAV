//! Phase 2 - kernel-sourced live process tracing via the **process events
//! connector** (`cn_proc`) over a `NETLINK_CONNECTOR` socket.
//!
//! Where the userland Sentinel infers novelty from `/proc` snapshots, this
//! subscribes to a **kernel broadcast** of every `exec()` as it happens. The
//! events originate in the kernel, so a userland rootkit that hooks `ps` /
//! `readdir` cannot suppress them - we see a process the instant it is born,
//! before it can hide. (A *kernel* rootkit can still tamper; the strongest
//! guarantee is a kernel/eBPF agent - this is the no-toolchain pure-Rust step.)
//!
//! Requires `CAP_NET_ADMIN` (root) to bind the connector multicast group.
//! Linux-only.

#![cfg(target_os = "linux")]

use std::io;
use std::mem::size_of;

const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;

/// A kernel-reported exec event.
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub pid: i32,
    pub tgid: i32,
}

#[repr(C)]
struct NlMsgHdr {
    len: u32,
    typ: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

/// Subscribe to kernel exec events and invoke `cb` for each `exec()`.
/// Blocks; returns only on a fatal socket error. Needs root/CAP_NET_ADMIN.
pub fn watch_execs<F: FnMut(ExecEvent)>(mut cb: F) -> io::Result<()> {
    // socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR)
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_CONNECTOR,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let guard = FdGuard(fd);

    // bind to the proc connector multicast group.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = std::process::id();
    addr.nl_groups = CN_IDX_PROC;
    let r = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::EPERM) {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cn_proc needs root / CAP_NET_ADMIN",
            )
        } else {
            e
        });
    }

    send_listen(fd)?;

    // Receive loop. cn_proc delivers one event per datagram.
    let mut buf = [0u8; 1024];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            drop(guard);
            return Err(e);
        }
        let n = n as usize;
        // Layout in the datagram (little-endian on all supported arches):
        //   nlmsghdr(16) | cn_msg(20) | proc_event{ what(4) cpu(4) ts(8) union }
        // EXEC union: process_pid(i32) process_tgid(i32) at proc_event+16.
        const WHAT_OFF: usize = 16 + 20; // 36
        const EXEC_PID_OFF: usize = WHAT_OFF + 16; // 52
        if n < EXEC_PID_OFF + 8 {
            continue;
        }
        let what = u32::from_le_bytes([
            buf[WHAT_OFF],
            buf[WHAT_OFF + 1],
            buf[WHAT_OFF + 2],
            buf[WHAT_OFF + 3],
        ]);
        if what == PROC_EVENT_EXEC {
            let pid = i32::from_le_bytes([
                buf[EXEC_PID_OFF],
                buf[EXEC_PID_OFF + 1],
                buf[EXEC_PID_OFF + 2],
                buf[EXEC_PID_OFF + 3],
            ]);
            let tgid = i32::from_le_bytes([
                buf[EXEC_PID_OFF + 4],
                buf[EXEC_PID_OFF + 5],
                buf[EXEC_PID_OFF + 6],
                buf[EXEC_PID_OFF + 7],
            ]);
            cb(ExecEvent { pid, tgid });
        }
    }
}

/// Send the PROC_CN_MCAST_LISTEN subscription message.
fn send_listen(fd: i32) -> io::Result<()> {
    // nlmsghdr | cn_msg{ id{idx,val}, seq, ack, len, flags } | u32 op
    const CN_MSG_LEN: usize = 20;
    const OP_LEN: usize = 4;
    let payload_len = CN_MSG_LEN + OP_LEN;
    let total = size_of::<NlMsgHdr>() + payload_len;
    let mut msg = vec![0u8; total];

    // nlmsghdr
    msg[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    msg[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_le_bytes());
    // flags=0, seq=0
    msg[12..16].copy_from_slice(&std::process::id().to_le_bytes());

    // cn_msg
    let c = size_of::<NlMsgHdr>();
    msg[c..c + 4].copy_from_slice(&CN_IDX_PROC.to_le_bytes()); // id.idx
    msg[c + 4..c + 8].copy_from_slice(&CN_VAL_PROC.to_le_bytes()); // id.val
                                                                   // seq, ack = 0
    msg[c + 16..c + 18].copy_from_slice(&(OP_LEN as u16).to_le_bytes()); // len
                                                                         // flags = 0

    // op = PROC_CN_MCAST_LISTEN
    let o = c + CN_MSG_LEN;
    msg[o..o + 4].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_le_bytes());

    let sent = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct FdGuard(i32);
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}
