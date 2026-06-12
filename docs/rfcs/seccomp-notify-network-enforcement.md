# seccomp-notify Network Enforcement for Platform Mode

**Status:** Proposal
**Depends on:** Platform Mode (PR #12)
**Related:** NVIDIA/OpenShell#899, Landlock TCP port restriction (PR #13)

## Goal

Add kernel-level domain/IP filtering to Platform Mode using seccomp-notify
(SECCOMP_RET_USER_NOTIF). The supervisor intercepts connect(), sendto(),
and sendmsg() at the syscall dispatch boundary, evaluates the destination
against a DNS-pinned OPA allowlist, and performs the operation on behalf of
the child -- or denies it with EPERM.

This provides mandatory, kernel-enforced domain filtering without any
capabilities, as an alternative to the Landlock TCP port restriction (PR #13)
which only filters by port.

## When to use this vs Landlock TCP port restriction

| | Landlock port (PR #13) | seccomp-notify (this) |
|---|---|---|
| Filters by | TCP port only | IP + port + domain |
| Proxy required | Yes (domain filtering at proxy) | No (domain filtering at syscall) |
| Overhead | Negligible (LSM hook) | ~35us per mediated syscall |
| Complexity | Low (~40 LOC) | High (~300-500 LOC) |
| Best for | Deployments WITH a proxy | Standalone WITHOUT a proxy |

## Architecture

The supervisor forks before exec'ing the agent. The child installs a seccomp
filter with SECCOMP_FILTER_FLAG_NEW_LISTENER. The parent handles notifications
asynchronously and performs on-behalf-of operations via pidfd_getfd().

## RHEL 9 / OpenShift 4.18 compatibility

All required features available: SECCOMP_RET_USER_NOTIF (5.0),
SECCOMP_IOCTL_NOTIF_ADDFD (5.9), pidfd_getfd (5.6), crun SCMP_ACT_NOTIFY.

## Effort

~300-500 LOC, 2-3 weeks.

## Reference

- Sandlock: https://github.com/multikernel/sandlock
- Paper: https://arxiv.org/html/2605.26298v1
- seccomp_unotify(2): https://www.man7.org/linux/man-pages/man2/seccomp_unotify.2.html
