# Contributing

Thanks for considering a contribution. This is a Linux kernel module paired
with a userspace daemon/CLI, so a few things work differently than a typical
userspace-only project — read on before diving in.

## Before you open a PR

- **Found a security vulnerability?** Don't open a public PR or issue for it
  — see `SECURITY.md`.
- **Touching the kernel module or anything security-relevant?** Skim
  `THREAT_MODEL.md` first. It defines the adversary model and trust
  boundaries this code actually needs to hold, so changes are easier to
  reason about (and review) against that context.

## Prerequisites

- Linux with kernel headers **>= 6.12** if you're building/testing the
  module itself — it uses APIs (`sized_strscpy`, the `_noprof` allocators,
  `for_class_mod_mem_type`, maple-tree VMA iteration) that don't exist on
  older kernels. The daemon, mock tests, and server don't need this.
- `gcc` or `clang` (the Makefile auto-detects `LLVM=1` if your running
  kernel was itself built with clang).
- Python 3, for the report server and its tests.
- `shellcheck` and `sparse` if you want to run the same static analysis CI
  does, locally (`apt install shellcheck sparse` on Debian/Ubuntu).

## Building

- `make` — builds both the module and the daemon
- `make module` / `make daemon` — build just one
- `make clean`

## Testing — pick the tier that matches your change

Most changes don't need root or a VM:

- **Daemon/CLI logic** — `make test-mock` runs the daemon against an
  `LD_PRELOAD` mock of the kernel interface (`test/mock_anticheat.c`), no
  module load, no root. This is exactly what CI's `userspace` job runs via
  `make ci`.
- **Server** — `./server/test_server.sh` and
  `python3 server/test_ratelimiter_unit.py`, both plain userspace.
- **A specific kernel-side behavior** — there's a purpose-built live test
  helper for most of the trickier ones: `priv-drop-test`, `render-hook-test`,
  `mount-ns-test`, `anon-exec-test`, `thread-exit-migration-test`,
  `thread-spawn-after-protect-test`. Each needs root and the real module
  loaded; each proves one specific thing (see the comment above its target
  in the `Makefile`).
- **Full end-to-end** — `sudo ./test.sh`. Needs root and loads the real
  module. **Run this in a VM, not your main machine** — a bug in a loaded
  kernel module can panic or corrupt the host, not just crash a process.
- **ioctl fuzzing** — `make ioctl-fuzz`, then
  `./test/ioctl_fuzz [iterations] [seed]`. Against the mock this only
  proves the harness itself doesn't crash; the real test is against a
  loaded module as root, watching `dmesg` for anything the nightly
  KASAN/lockdep job would also flag (oops, warning, GPF, KASAN report).
  See the README's "ioctl fuzzing" section for more.

## Before opening a PR

Run what CI runs: `make ci` (userspace build with `-Wall -Wextra -Werror`,
plus the full mock suite). If you touched the kernel module, also build it
against your own headers and, if you can, boot-test it in a VM — the
per-push CI job only compiles and sparse-checks the module (against pinned
6.12 headers), it doesn't load it. Real load-time testing happens in the
nightly KASAN/lockdep job, not on every PR.

## Code conventions

- New C files: `SPDX-License-Identifier: MIT OR GPL-2.0-only` plus a short comment
  describing the file's purpose, matching the existing files in `src/`.
- Kernel-side changes should stay sparse-clean — `make module` currently
  has zero sparse warnings; keep it that way.
- Shell scripts must pass `shellcheck` and keep their executable bit (a
  rebase or auto-fix commit can silently drop it — CI checks for this
  specifically because it's happened before).
- Commit messages generally follow conventional-commit style (`fix(...):`,
  `feat(...):`, etc.) — keep new ones consistent with recent history.

## Touching the ioctl ABI

If a change alters the layout of a struct shared between the kernel module
and the daemon (`src/anticheat.h`), say so explicitly in the PR description.
That determines whether `AC_IOCTL_VERSION` needs to bump — see
`RELEASING.md` — independently of the normal version bump.

## What happens after you open a PR

- `ci.yml` runs automatically: a userspace build + mock/server test suite,
  and a kernel-module compile + sparse + DKMS-signing smoke test against
  pinned linux-6.12 headers.
- An automated Claude Code Review comment will show up — treat it as a
  first-pass reviewer, not a merge gate.
- Heavier jobs (the real KASAN/lockdep boot fuzz, the stress test) run
  nightly rather than per-PR, so a green CI run doesn't cover everything —
  for a security-relevant change, expect to wait for or manually trigger
  one of those before it's merged.

## License

Dual-licensed MIT OR GPL-2.0-only, same as the rest of the project (see
`LICENSE-MIT` and `LICENSE-GPL`). By submitting a PR you agree your
contribution is under the same dual license.
