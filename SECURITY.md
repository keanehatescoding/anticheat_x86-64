# Security Policy

## Overview

This repo ships a Linux kernel-mode anticheat: a loadable kernel module (LKM) that performs kernel-level integrity checks and process protection, plus a userspace daemon/CLI that talks to it over an ioctl interface (`/dev/anticheat`). Because the kernel module runs in ring 0, a bug here can have far more impact than a typical userspace bug — up to and including local privilege escalation or full system compromise. Kernel-module and ioctl-boundary issues are treated as the highest-priority class of report.

## Supported Versions

This project is under active, pre-1.0 development. Only the latest commit on `master` is supported — please confirm an issue reproduces there before reporting.

## Reporting a Vulnerability

Please **do not** open a public issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/keanehatescoding/anticheat_x86-64/security/advisories/new)**

This opens a private advisory visible only to you and the maintainer until a fix ships.

### What to include

- A clear description of the issue and its impact
- Affected component: kernel module (`anticheat.ko`), ioctl interface, userspace daemon/CLI, render-hook/ELF-parsing logic, or the optional report server (`ac_server.py`)
- Steps to reproduce, PoC code, or a crash/panic log
- Kernel version, distro, and architecture
- Whether the bug is reachable without the module already protecting a process

## Scope

**Treated as a security vulnerability:**
- Memory-safety bugs in the kernel module or its ioctl handlers (overflows, use-after-free, races, missing bounds/permission checks) — especially anything reachable from an unprivileged, unprotected process
- A way for an unprivileged process to issue privileged ioctls (protect/unprotect/lock/etc.) without proper authorization
- Memory-safety issues in the userspace daemon when parsing untrusted input (a monitored process's ELF file, `/proc/<pid>/mem`, ioctl-supplied data)
- Vulnerabilities in the optional report server (`ac_server.py`) — injection, auth bypass, ban-list tampering
- Crashes or kernel panics triggerable by a process the module hasn't (yet) protected

**Not a security report — open a normal issue instead:**
- New detection-evasion techniques against the current heuristics (expected, ongoing cat-and-mouse for anticheat software, not a vulnerability in the traditional sense)
- False positives / false negatives in detection

## Response

This is a solo/student project, not a company with an SLA, so please bear with realistic turnaround — I'll aim to acknowledge new reports within a few days and keep you updated as I work on a fix. I'd appreciate coordinated disclosure: a reasonable window to ship a fix before any public write-up.

## Safe Harbor

Good-faith research under this policy — testing against your own systems, avoiding privacy violations, data destruction, or disrupting others, and reporting privately first — won't be met with legal action from me.
