# Threat model

This is a single place stating the adversary this project defends against,
what's explicitly out of scope, and what "production-ready" does and
doesn't claim today. Every individual limitation named here is already
documented inline where the relevant code lives (mostly in README's
"Design notes & limitations" and the render-hook/LD_PRELOAD sections) —
this doc compiles them into one place rather than introducing anything
new.

## Adversary

Root shows up on both sides of this model, in two different roles that
must not be conflated:

- **Trusted root — the operator.** Loading `anticheat.ko`, running the
  daemon, and calling its ioctls (`protect`, `lock`, `scan`, ...) all
  require root/`CAP_SYS_ADMIN` themselves. That's assumed trusted
  throughout this document — it's the prerequisite for running the tool
  at all, the same way `sudo make install`/DKMS's Secure Boot signing
  already assume the person running them is legitimate. Nothing here
  defends against the machine's own administrator; if the operator is
  the adversary, no client-side or kernel-side tool can help.
- **The attacker — a cheat author with ordinary user-level access to
  their own machine.** This is the realistic adversary the project
  actually defends against: the same starting privilege as any other
  process the player can run, not someone who already has kernel-level
  code execution equal to or greater than `anticheat.ko`'s own. Most
  detections here don't check the *caller's* privilege at all — the
  ptrace kprobe, syscall-table integrity check, and memory scans all run
  in-kernel regardless of who's asking — so an attacker who escalates to
  root *userspace* privilege (e.g. via `sudo`) *after* `anticheat.ko` is
  already loaded and protecting a process does not, by itself, defeat
  those checks. Two capabilities are explicit exceptions to that,
  already called out below: `SIGKILL`-ing the daemon outright, and
  unloading the module if it isn't `lock`ed. Loading their own kernel
  module is also within this model's actual detection surface — module
  enumeration exists specifically to catch a cheat's own loaded module
  running alongside `anticheat.ko` — but a cheat module capable of
  operating at full, undetectable kernel privilege (a genuine rootkit,
  not just a hidden LKM) crosses into the next case.

**Out of scope: an attacker who already has kernel-privileged code
execution** — via a sufficiently sophisticated kernel module of their
own, an unrelated kernel exploit, or any other means. See "Explicitly
out of scope" below. This is a fundamental limit, not a gap specific to
this project: no purely in-kernel detector can defend against an
adversary operating at its own privilege level or higher.

Everything this project detects follows from the middle case above:
syscall-table hooks, hidden kernel modules, ptrace attaches and
`process_vm_readv`/`process_vm_writev` calls against a protected process,
RWX/anon-exec memory regions, runtime code patching, and render-API inline
hooks are all things a user-level-to-root-userspace attacker can attempt
against a protected process without yet having kernel-level code execution
of their own.

## Trust boundaries

- **`anticheat.ko`** — ring 0, trusted, the actual root of trust. If this
  is compromised or was never loaded, nothing else in the system holds.
- **The daemon (`anticheat`/`start`)** — userspace, runs as root,
  self-protects on startup (registers its own pid so it can't be
  ptrace-attached the same way a protected game process can't be) but is
  otherwise an ordinary process.
- **The protected process** — the thing being defended; untrusted from
  the module's point of view until proven otherwise by the checks above.
- **`server/ac_server.py`** — a separate trust domain regardless of where
  it's physically deployed. The README documents it running on localhost,
  on the LAN, or on a genuinely separate host as equally supported —
  "separate trust domain" describes the *authorization* boundary (it
  never trusts a report as ground truth, no matter who's asking), not a
  requirement to run it on different hardware. It receives reports from
  daemon instances it does not control and treats every report as an
  **unverified claim**, never as ground truth (see "Reports never
  auto-ban" in the README) — this is deliberate: the daemon runs on the
  exact machine a cheat author controls, so a report can be wrong,
  spoofed, or replayed, whether the server happens to be co-located on
  that same machine or not.

## Explicitly out of scope

These are known, accepted gaps — not oversights — each already noted
where the relevant code lives:

- **A kernel-privileged attacker.** Anything that already has ring-0 code
  execution (a more-privileged rootkit, a kernel exploit unrelated to
  this project) can defeat any in-band detector, including this one. No
  purely in-kernel detection scheme can defend against an adversary with
  equal or greater kernel privilege — this is a fundamental limit, not
  something more engineering effort closes.
- **A PID-reuse race in the ptrace/process_vm kprobes.** Both kprobes
  resolve the target pid to a `task_struct`, decide protected-or-not, and
  release that reference *before* the real syscall body (`ptrace()`'s own
  dispatch, `process_vm_rw_core()`'s `find_get_task_by_vpid()`) does its
  own, separate lookup of the same pid number. If the target task exits
  and that exact pid is reused by a newly-registered protected process
  inside that window, the kprobe's "not protected" verdict was correct at
  the time but stale by the time the real lookup runs. The window is a
  single syscall's worth of ordinary (non-atomic, preemptible,
  page-fault-capable) kernel C code, not a scheduler-atomic instant, so
  this isn't purely theoretical — but it requires winning a race on a
  specific pid being freed and immediately reused by a process the
  operator happens to register as protected in that same window, which
  is far outside attacker control. Fixing it properly means binding the
  protection decision to the exact `task_struct` the real syscall body
  resolves (or revalidating it immediately before memory access) instead
  of a separate, earlier lookup — a real architectural change to how
  these two kprobes enforce policy, not a one-line fix, and not attempted
  here.
- **DXVK/VKD3D-internal hooks and Vulkan loader dispatch-table hooks.**
  Render-hook detection verifies the exported symbol's own bytes in
  `libvulkan.so`/`libGL.so`/`libEGL.so`; a hook placed inside a
  translation layer's own code, or in the loader's internal dispatch
  table rather than the exported symbol, is invisible to this check.
- **LD_PRELOAD symbol interposition and malicious Vulkan layers that
  never touch target bytes.** `--check-preload`/`--check-vklayers`/
  `--check-implicit-layers` are heuristic environment/manifest signals
  for a human to correlate, not verdicts — a sufficiently disguised
  layer (named to blend into the allowlist) or a preload library that
  does nothing detectably wrong isn't flagged by name alone.
- **Within-core-kernel-text redirects.** The syscall-integrity range
  check flags entries pointing outside `[_stext, _etext)` or into a
  module; a hook that redirects one core-kernel syscall handler to
  another (e.g. `sys_read` → `sys_write`) stays inside kernel text and
  is invisible to that check alone. A boot-time checksum of every
  handler address (`AC_EV_SYSCALL_REDIRECT`, see #63) raises the
  detection bar for this: an in-text redirect installed any time after
  module load is caught the next periodic/on-demand check, without
  needing to identify it by range. This does **not** close the gap
  against the adversary this document is actually scoped to exclude —
  an attacker with kernel-write privilege equal to or greater than
  `anticheat.ko`'s own can patch the in-kernel baseline the same way it
  patches the table, and a redirect already present before the module's
  own load-time snapshot is captured as the new "normal" and never
  flagged. Still considered a narrow, mostly-theoretical gap against the
  actual in-scope adversary (ordinary user-to-root-userspace, or a cheat
  module installing the redirect *after* this module has already
  snapshotted the table) — also visually detectable by other means.
- **`SIGKILL` of the daemon by a root-privileged attacker.** Daemon
  self-protection only stops ptrace-based attacks via the same kprobe
  everything else uses; nothing here hides or hardens the daemon process
  itself against an attacker who already has root.
- **Anonymous-executable *content*.** `AC_EV_ANON_EXEC` flags presence of
  new anon-exec mappings, not their content — it can't distinguish
  injected shellcode from a legitimate JIT engine's freshly-generated
  code. The baseline-delta design and `--jit` allowlist reduce noise, not
  eliminate the ambiguity.
- **Report authenticity.** The server never auto-bans on a report alone —
  a report is one client's unverified claim about itself, reviewed by a
  human before any ban.
- **A hypervisor deliberately configured to hide itself.** `vmcheck`'s
  CPUID hypervisor-present bit and DMI/SMBIOS strings are both attacker-
  controllable at the hypervisor-configuration level (VMware's
  `hypervisor.cpuid.v0 = FALSE`, VirtualBox's equivalent, KVM/QEMU CPUID
  masking, QEMU's `-smbios` flag) — an attacker who controls the VM
  configuration itself, not just the guest OS, can suppress both
  signatures. Fundamental to the technique, not something more detection
  logic closes.

## Operating assumptions

- **x86-64 only.** Kprobe names (`__x64_sys_*`/`__ia32_sys_*`), the CI
  matrix, and the kernel-fetch job (`ARCH=x86_64`) all assume this.
  Porting to another architecture is unscoped work, not a bug.
- **`CONFIG_KPROBES`/`CONFIG_KALLSYMS_ALL`** must be enabled in the target
  kernel; if a probe can't register, the module still loads and logs the
  limitation rather than failing to load.
- **`kallsyms_lookup_name`/`module_mutex` are not exported** as of the
  targeted kernel floor (6.12+), so syscall-table discovery and the
  module-list walk are hand-implemented (kprobe-based address discovery;
  an RCU-protected, 1024-entry-capped single-pass walk of `THIS_MODULE->
  list`). The walk is memory-safe, not merely best-effort: it uses
  `rcu_read_lock()` + `list_for_each_entry_rcu()`, the same protection
  the kernel's own `is_module_address()`/`is_module_text_address()` use
  for this exact list. Module unload (`free_module()` in
  `kernel/module/main.c`) does `list_del_rcu()` followed by
  `synchronize_rcu()` *before* freeing the core memory a `struct module`
  lives in, so `synchronize_rcu()` cannot complete — and the module can't
  be freed — while this walk still holds the RCU read lock; a `struct
  module *` handed out mid-walk is guaranteed live for the duration of
  the walk. What remains racy, by design, is the list's *membership* and
  *content* during that window: a module load/unload landing mid-walk can
  make a single snapshot miss a module or see one still mid-`ac_module_
  sane()`-filtered init/teardown state, and a concurrent writer can
  change `mod->state`/`mod->mem[]` under the reader between individual
  field reads (no UAF — the memory itself outlives the read; just a torn
  logical snapshot). That residual raciness is bounded and tolerated by
  callers exactly as before; see #2 for the prior weaker
  (`preempt_disable()`-only) version of this walk and why it was upgraded.
- **Secure Boot enrollment is a manual, one-time, interactive step** (MOK
  enrollment via the firmware's "MOK Management" screen) — nothing here
  can or should auto-approve a new trusted key.

## What "production-ready" claims today

Everything above is a *design* boundary — accepted scope, not a bug to
fix. Separately, there are engineering gates not yet closed that this
doc does **not** paper over:

- The kernel module (`src/anticheat_module.c`) has had no independent
  security audit — a memory-safety bug there is a ring-0 crash or
  exploit, a materially worse failure mode than a userspace bug anywhere
  else in this project. CI does run `sparse` over it on every push
  (currently clean) — real, but narrow: sparse catches type/context/
  locking-annotation violations, not general logic bugs, use-after-free,
  or races. A fuzz harness for the ioctl interface exists
  (`test/ioctl_fuzz.c`); every push only runs its dry run against the
  userspace mock, which proves the harness itself is correct, not that
  the kernel survives malformed input (the mock has none of the kernel's
  own `copy_from_user()`/`access_ok()` to stress). The real run — root,
  a real loaded module, full pointer-corruption fuzzing, watching the
  kernel's own console/`dmesg` output — now happens too, automated, just
  not on every push: see the next point.
- KASAN/lockdep-instrumented boot testing now runs, nightly plus
  on-demand (`.github/workflows/kasan-boot.yml`,
  `scripts/kasan_boot_test.sh`): a KASAN+lockdep kernel boots in a VM,
  the real module loads, the daemon CLI and the real (non-safe-mode)
  ioctl fuzz harness both run against it, and the job fails if the
  in-VM run never reaches its own completion marker (something crashed
  or hung partway through) or if the captured VM console log (which
  includes the kernel's printk/dmesg stream) shows a KASAN report,
  lockdep splat, or oops/warning/GPF. This is nightly rather than
  per-push deliberately — it builds a full instrumented kernel from
  source and boots it in a VM (minutes, not seconds), and GitHub-hosted
  runners don't officially or reliably offer
  `/dev/kvm`, so a per-push gate on that infrastructure risked being
  slow and flaky rather than a real quality bar. Until this has actually
  run clean a meaningful number of times, treat it as recently-added
  coverage, not yet a long-proven baseline the way `sparse`'s clean run
  is.

Until those close, "production-ready" means: safe to run in the
deployment this project has actually been built and tested against — a
machine you control, with the server on localhost or on a trusted,
isolated LAN, or behind the documented TLS reverse proxy for anything
else. That LAN case is narrower than it sounds: `ac_server.service` runs
`ac_server.py` with no TLS, so `Authorization: Bearer` keys go out in
plaintext — fine on a network with no untrusted parties able to observe
traffic, not fine on a LAN an attacker (or just another tenant) can
sniff or sit on-path of, where the reverse proxy is required, not
optional. None of this is yet a claim that this is safe to distribute to
end users' machines you don't control, or to expose to the open internet
without the operator's own additional review.

**Unix-domain-socket transport extends the safely-supported deployment
surface (#67).** `AC_REPORT_URL=unix:///path/to/socket` on the daemon
side, paired with `ac_server.py --unix-socket PATH`, sends the same
HTTP/1.1 request over an `AF_UNIX` `SOCK_STREAM` socket instead of a TCP
connection — the daemon and server co-located on one host is, in
practice, the more likely deployment than the LAN case above, and this
option removes the plaintext-network-credential exposure entirely for
it: there is no network segment for the `Authorization: Bearer` key to
traverse in the first place. This changes what the relevant trust
boundary *is*, not just narrows it — for the Unix-socket transport it's
filesystem permissions on the socket path, not network reachability.
`ac_server.py` creates the socket file `0600` (owner-only, mirroring the
report DB's own permissions — see `Store.__init__`) and reapplies that
mode on every start, so anyone able to open that socket has already
cleared the same bar as reading the SQLite DB directly. That mode isn't
durably widenable: a daemon running as a different user than the server
cannot be accommodated by loosening the socket's group/ACL after the
fact, since the next (re)start resets it to `0600` again -- the daemon
and server must run as the same user (or the daemon as root). `0600` on
the socket file is also not the whole boundary: it only gates *opening*
the bound socket, not deleting or replacing the path before the server
binds to it, so the containing directory (e.g. `/run/anticheat/`) must
itself be writable only by that same user, not by anyone else who might
squat the path first. Before binding, `ac_server.py` also refuses to
touch a stale path that turns out not to be a socket, and refuses to
steal a path something is still actively listening on, rather than
unconditionally unlinking whatever it finds there. This is additive,
not a replacement: plain HTTP-over-TCP keeps working unchanged for
existing LAN/reverse-proxy deployments, and per-source-IP rate limiting
doesn't apply in any meaningful way to the Unix-socket transport (every
connection over it is attributed to a single fixed placeholder identity,
since there's no per-peer network address to key on, and `--trust-proxy`
is rejected outright alongside `--unix-socket` rather than letting a
client forge that identity via `X-Forwarded-For`) — acceptable because
reaching the socket at all is already permission-gated, unlike an open
TCP port.
HTTPS with a pinned certificate — the other half of #67 — remains a
documented follow-up, not attempted here; it's the right answer for a
genuinely remote, over-the-network deployment, which the Unix-socket
option does not address.
