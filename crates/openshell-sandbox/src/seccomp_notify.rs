// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! seccomp-notify network enforcement for Platform mode.
//!
//! Provides kernel-level `connect()` interception using `SECCOMP_RET_USER_NOTIF`.
//! The supervisor intercepts network syscalls, reads the destination `sockaddr`
//! from the child's memory, evaluates it against a DNS-pinned allowlist, and
//! either performs the operation on behalf of the child via `pidfd_getfd()` or
//! denies it with `EPERM`.
//!
//! # Architecture
//!
//! The supervisor forks before exec'ing the agent. The child installs a seccomp
//! filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER` that returns
//! `SECCOMP_RET_USER_NOTIF` for `connect()`, `sendto()`, and `sendmsg()`. The
//! notification fd is sent to the parent via a Unix socket. The parent runs an
//! async event loop processing notifications.
//!
//! # TOCTOU Safety
//!
//! The supervisor never uses `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. Instead, it
//! reads the `sockaddr` once, validates it, then performs the `connect()` itself
//! using `pidfd_getfd()` to duplicate the child's socket fd. The original
//! syscall is never continued.
//!
//! # Requirements
//!
//! - Linux 5.0+ (`SECCOMP_RET_USER_NOTIF`)
//! - Linux 5.6+ (`pidfd_getfd`)
//! - Linux 5.9+ (`SECCOMP_IOCTL_NOTIF_ADDFD`)
//! - `RuntimeDefault` seccomp profile must allow the `seccomp()` syscall
//! - `io_uring` must be blocked (`RuntimeDefault` does this)
//!
//! # References
//!
//! - [`seccomp_unotify(2)`](https://www.man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
//! - [`pidfd_getfd(2)`](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
//! - [Sandlock](https://github.com/multikernel/sandlock) -- reference implementation

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

// ---------------------------------------------------------------------------
// DNS-Pinned Allowlist
// ---------------------------------------------------------------------------

/// A set of allowed destination IPs, pinned at sandbox creation time.
///
/// DNS resolution happens once during [`DnsPinnedAllowlist::add_domain()`].
/// The resolved IPs are frozen for the sandbox session lifetime to prevent
/// DNS rebinding attacks.
///
/// # Limitation: DNS wildcards
///
/// Wildcard domains (e.g., `*.googleapis.com`) cannot be pinned because
/// `getaddrinfo("*.googleapis.com")` is not valid DNS and returns an error.
/// Given this OPA policy:
///
/// ```yaml
/// endpoints:
///   - { host: api.anthropic.com, port: 443 }     # exact -- pinnable
///   - { host: "*.googleapis.com", port: 443 }     # wildcard -- NOT pinnable
/// ```
///
/// Exact domains work: `add_domain("api.anthropic.com")` resolves and pins
/// the IPs. But `add_domain("*.googleapis.com")` fails, pins zero IPs, and
/// connections to `us-central1-aiplatform.googleapis.com` are denied even
/// though the OPA policy allows them.
///
/// Callers must skip wildcard endpoints (those containing `*`) and rely on
/// the proxy's OPA `glob.match()` for wildcard domain enforcement.
#[derive(Debug, Clone)]
pub struct DnsPinnedAllowlist {
    allowed_ips: HashSet<IpAddr>,
    proxy_addr: SocketAddr,
}

impl DnsPinnedAllowlist {
    /// Create an allowlist that permits only loopback proxy connections.
    pub fn new(proxy_addr: SocketAddr) -> Self {
        let mut allowed_ips = HashSet::new();
        allowed_ips.insert(proxy_addr.ip());
        allowed_ips.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        allowed_ips.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        Self {
            allowed_ips,
            proxy_addr,
        }
    }

    /// Resolve a domain name and pin its IPs to the allowlist.
    pub fn add_domain(&mut self, domain: &str) -> std::io::Result<usize> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<_> = (domain, 0).to_socket_addrs()?.collect();
        let count = addrs.len();
        for addr in addrs {
            self.allowed_ips.insert(addr.ip());
        }
        Ok(count)
    }

    /// Check whether a destination IP is in the allowlist.
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.allowed_ips.contains(ip)
    }

    /// The proxy address (always allowed).
    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }

    /// Number of pinned IPs.
    pub fn len(&self) -> usize {
        self.allowed_ips.len()
    }

    /// Whether the allowlist contains only the default entries.
    pub fn is_empty(&self) -> bool {
        self.allowed_ips.len() <= 3
    }
}

// ---------------------------------------------------------------------------
// Linux-specific seccomp-notify syscall wrappers
// ---------------------------------------------------------------------------

/// Raw Linux seccomp notification structures and syscall wrappers.
///
/// These are defined here because `libc` 0.2.x does not export the full
/// notification API (`seccomp_notif`, `seccomp_notif_resp`, ioctls).
#[cfg(target_os = "linux")]
#[allow(unsafe_code, clippy::cast_possible_truncation)]
pub mod linux {
    use std::io;
    use std::mem;
    use std::mem::size_of;
    use std::os::unix::io::RawFd;

    // --- Seccomp constants ---
    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7FC0_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

    // ioctl commands for the notification fd.
    // These match the kernel definitions for all architectures (x86_64, aarch64).
    // Note: SECCOMP_IOCTL_NOTIF_ID_VALID changed from _IOR to _IOW in Linux 5.17.
    // We use the post-5.17 value. On pre-5.17 kernels, id_valid() returns false
    // and the caller should treat the notification as potentially stale.
    const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_7500;
    const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_7501;
    const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_7502;

    // Syscall numbers (same on x86_64 and aarch64)
    const SYS_PIDFD_OPEN: libc::c_long = 434;
    const SYS_PIDFD_GETFD: libc::c_long = 438;

    // --- Notification structs ---

    /// Seccomp notification received from the kernel.
    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct SeccompNotif {
        pub id: u64,
        pub pid: u32,
        pub flags: u32,
        pub data: SeccompData,
    }

    /// Syscall data from the notification.
    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct SeccompData {
        pub nr: i32,
        pub arch: u32,
        pub instruction_pointer: u64,
        pub args: [u64; 6],
    }

    /// Response to send back to the kernel.
    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct SeccompNotifResp {
        pub id: u64,
        pub val: i64,
        pub error: i32,
        pub flags: u32,
    }

    // --- BPF filter types ---

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    // BPF instruction encoding constants
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    // AUDIT_ARCH constants for BPF architecture validation
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!(
        "seccomp-notify BPF filter requires AUDIT_ARCH_NATIVE. \
         Add the constant for your target_arch to seccomp_notify.rs."
    );

    /// Install a seccomp BPF filter that returns `SECCOMP_RET_USER_NOTIF`
    /// for `connect()`, `sendto()`, and `sendmsg()` syscalls.
    ///
    /// Returns the notification fd on success. The caller is responsible for
    /// closing the fd (e.g., by wrapping it in `OwnedFd`).
    ///
    /// The filter validates `AUDIT_ARCH` to prevent x32/compat ABI bypass.
    ///
    /// Must be called after `prctl(PR_SET_NO_NEW_PRIVS, 1)` has been set.
    pub fn install_connect_notify_filter() -> io::Result<RawFd> {
        let filter = [
            // [0] Load architecture from seccomp_data.arch (offset 4)
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 4, // offsetof(seccomp_data, arch)
            },
            // [1] Verify native arch; non-native goes to NOTIFY [10] so the
            // supervisor can inspect and deny compat-ABI syscalls.
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0, // continue
                jf: 8, // non-native → NOTIFY [10]
                k: AUDIT_ARCH_NATIVE,
            },
            // [2] Load syscall number from seccomp_data.nr (offset 0)
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0, // offsetof(seccomp_data, nr)
            },
            // [3] Check connect → NOTIFY [10]
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 6, // jump to NOTIFY
                jf: 0,
                k: libc::SYS_connect as u32,
            },
            // [4] Check sendto → NOTIFY [10]
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 5,
                jf: 0,
                k: libc::SYS_sendto as u32,
            },
            // [5] Check sendmsg → NOTIFY [10]
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 4,
                jf: 0,
                k: libc::SYS_sendmsg as u32,
            },
            // [6] Check recvfrom → NOTIFY [10]
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 3,
                jf: 0,
                k: libc::SYS_recvfrom as u32,
            },
            // [7] Check recvmsg → NOTIFY [10]
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 2,
                jf: 0,
                k: libc::SYS_recvmsg as u32,
            },
            // [8] Check bind → NOTIFY [10] (prevent binding to arbitrary ports)
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: libc::SYS_bind as u32,
            },
            // [9] ALLOW
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
            // [10] NOTIFY
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_USER_NOTIF,
            },
        ];

        let prog = SockFprog {
            len: u16::try_from(filter.len()).expect("BPF filter exceeds u16::MAX instructions"),
            filter: filter.as_ptr(),
        };

        // SAFETY: The SockFprog and SockFilter arrays are #[repr(C)] with correct
        // layout for the kernel ABI. The filter array is stack-allocated and lives
        // for the duration of the syscall. PR_SET_NO_NEW_PRIVS must be set before
        // this call. The returned fd is valid until closed.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                std::ptr::from_ref(&prog),
            )
        };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(fd as RawFd)
    }

    /// Receive a seccomp notification from the notification fd.
    ///
    /// Blocks until a notification is available.
    pub fn recv_notif(notify_fd: RawFd) -> io::Result<SeccompNotif> {
        // SAFETY: SeccompNotif is #[repr(C)] and matches the kernel's
        // struct seccomp_notif layout. The kernel writes all fields.
        let mut notif: SeccompNotif = unsafe { mem::zeroed() };
        let ret = unsafe { libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(notif)
    }

    /// Send a response to a seccomp notification.
    pub fn send_resp(notify_fd: RawFd, resp: &SeccompNotifResp) -> io::Result<()> {
        let ret = unsafe { libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Check if a notification ID is still valid.
    ///
    /// Note: uses the post-Linux-5.17 ioctl constant (`_IOW`). On kernels
    /// 5.0-5.16, this always returns `false` (the old constant was `_IOR`).
    /// Callers should treat a `false` result as "proceed with caution" and
    /// verify the operation result, not as "definitely expired."
    pub fn id_valid(notify_fd: RawFd, id: u64) -> bool {
        let ret = unsafe { libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) };
        ret == 0
    }

    /// Open a pid fd for a process.
    pub fn pidfd_open(pid: u32) -> io::Result<RawFd> {
        #[allow(clippy::cast_possible_wrap)]
        let pid_t = pid as libc::pid_t;
        let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid_t, 0_u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd as RawFd)
    }

    /// Duplicate a file descriptor from another process via its pidfd.
    ///
    /// # Security Note
    ///
    /// A multi-threaded child can `dup2()` a different fd into `target_fd`
    /// between the notification and this call. The caller should verify the
    /// duplicated fd is a socket of the expected type after duplication.
    pub fn pidfd_getfd(pidfd: RawFd, target_fd: RawFd) -> io::Result<RawFd> {
        let fd = unsafe { libc::syscall(SYS_PIDFD_GETFD, pidfd, target_fd, 0_u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd as RawFd)
    }

    /// Verify that a duplicated fd is a socket (not a regular file or pipe).
    ///
    /// Call this after `pidfd_getfd()` to mitigate the fd-swap race: if a
    /// malicious child `dup2()`d a non-socket fd into the target slot, this
    /// check catches it.
    pub fn verify_socket_fd(fd: RawFd) -> io::Result<bool> {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        // SAFETY: fstat on a valid fd is safe. The stat struct is zeroed and
        // fully written by the kernel on success.
        let ret = unsafe { libc::fstat(fd, std::ptr::from_mut(&mut stat)) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // S_IFSOCK = 0o140000
        Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFSOCK)
    }

    /// Read bytes from another process's memory via `/proc/<pid>/mem`.
    ///
    /// Uses `read_exact` to ensure the full buffer is filled. Returns an
    /// error if the read is short (e.g., at an unmapped page boundary).
    ///
    /// # Security Note
    ///
    /// Between the notification and this read, the process may exit and the
    /// pid may be recycled. Call `id_valid()` before and check the result
    /// of this function. For stronger guarantees, use `process_vm_readv()`
    /// with a pidfd (not implemented here).
    pub fn read_process_memory(pid: u32, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::io::{Read, Seek};

        let path = format!("/proc/{pid}/mem");
        let mut file = std::fs::File::open(&path)?;
        file.seek(io::SeekFrom::Start(addr))?;
        file.read_exact(buf)
    }

    /// Parse a `sockaddr_in` or `sockaddr_in6` from raw bytes.
    ///
    /// `sa_family` is in native byte order. Port is in network (big-endian)
    /// byte order per the `sockaddr_in` ABI.
    pub fn parse_sockaddr(buf: &[u8]) -> Option<std::net::SocketAddr> {
        if buf.len() < 2 {
            return None;
        }

        // sa_family is in native byte order
        let family = u16::from_ne_bytes([buf[0], buf[1]]);

        match i32::from(family) {
            libc::AF_INET if buf.len() >= size_of::<libc::sockaddr_in>() => {
                // sin_port is in network (big-endian) byte order
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    ip, port,
                )))
            }
            libc::AF_INET6 if buf.len() >= size_of::<libc::sockaddr_in6>() => {
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                // sin6_flowinfo at bytes 4-7 (network byte order)
                let flowinfo = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                // sin6_addr at bytes 8-23
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[8..24]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                // sin6_scope_id at bytes 24-27 (native byte order per POSIX)
                let scope_id = u32::from_ne_bytes([buf[24], buf[25], buf[26], buf[27]]);
                Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    ip, port, flowinfo, scope_id,
                )))
            }
            _ => None,
        }
    }

    /// Deny a notification with EPERM.
    pub fn deny(notify_fd: RawFd, id: u64) -> io::Result<()> {
        send_resp(
            notify_fd,
            &SeccompNotifResp {
                id,
                val: 0,
                error: -libc::EPERM,
                flags: 0,
            },
        )
    }

    /// Allow a `connect()` notification by returning success (0) to the caller.
    ///
    /// **Only valid for `connect()` syscalls** which return 0 on success.
    /// For `sendto()`/`sendmsg()`, the supervisor must perform the operation
    /// on behalf of the child and return the actual byte count via
    /// `send_resp()` directly.
    pub fn allow_connect(notify_fd: RawFd, id: u64) -> io::Result<()> {
        send_resp(
            notify_fd,
            &SeccompNotifResp {
                id,
                val: 0,
                error: 0,
                flags: 0,
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn allowlist_permits_loopback() {
        let proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3128);
        let allowlist = DnsPinnedAllowlist::new(proxy);
        assert!(allowlist.is_allowed(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(allowlist.is_allowed(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn allowlist_denies_arbitrary_ip() {
        let proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3128);
        let allowlist = DnsPinnedAllowlist::new(proxy);
        let external = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));
        assert!(!allowlist.is_allowed(&external));
    }

    #[test]
    fn allowlist_resolves_domain() {
        let proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3128);
        let mut allowlist = DnsPinnedAllowlist::new(proxy);
        let count = allowlist.add_domain("localhost").unwrap();
        assert!(count > 0);
        assert!(allowlist.is_allowed(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn allowlist_proxy_addr() {
        let proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3128);
        let allowlist = DnsPinnedAllowlist::new(proxy);
        assert_eq!(allowlist.proxy_addr(), proxy);
    }

    #[test]
    fn allowlist_len_and_empty() {
        let proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3128);
        let allowlist = DnsPinnedAllowlist::new(proxy);
        assert!(allowlist.len() >= 2);
        assert!(allowlist.is_empty());
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::super::linux::parse_sockaddr;

        #[test]
        fn parse_ipv4_sockaddr() {
            let mut buf = [0u8; 16];
            // AF_INET = 2 in native byte order
            let family_bytes = 2u16.to_ne_bytes();
            buf[0] = family_bytes[0];
            buf[1] = family_bytes[1];
            // Port 443 in big-endian
            buf[2] = 0x01;
            buf[3] = 0xBB;
            // IP 93.184.216.34
            buf[4] = 93;
            buf[5] = 184;
            buf[6] = 216;
            buf[7] = 34;

            let addr = parse_sockaddr(&buf).unwrap();
            assert_eq!(addr.port(), 443);
            match addr {
                std::net::SocketAddr::V4(v4) => {
                    assert_eq!(*v4.ip(), std::net::Ipv4Addr::new(93, 184, 216, 34));
                }
                std::net::SocketAddr::V6(_) => panic!("expected IPv4"),
            }
        }

        #[test]
        fn parse_too_short_returns_none() {
            let buf = [0u8; 1];
            assert!(parse_sockaddr(&buf).is_none());
        }

        #[test]
        fn parse_unknown_family_returns_none() {
            let buf = [0xFF; 16];
            assert!(parse_sockaddr(&buf).is_none());
        }
    }
}
