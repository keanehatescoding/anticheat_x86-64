# kernel-anticheat: kernel module + userspace daemon
#
#   make            build both
#   make module     build anticheat.ko only
#   make daemon     build the userspace binary only
#   make clean
#   sudo make install         (binary -> /usr/local/sbin, module -> /lib/modules/.../extra)
#   sudo make uninstall
#   make install-deck         (SteamOS / immutable distros — see below)
#   make uninstall-deck
#
# Kernel module build requires linux headers for the running kernel:
#   /lib/modules/$(uname -r)/build
#
# For a distro with automatic kernel-update rebuilds and Secure Boot signing,
# use DKMS instead of `make install` — see scripts/dkms-install.sh.
#
# `install`/`uninstall` write to /usr/local and /lib/modules, which is fine
# on a normal distro but is read-only (or wiped on the next OTA update) on
# SteamOS and other immutable/atomic-image systems. `install-deck` instead
# stages everything under a user-writable directory and loads the module
# with plain `insmod` (which only needs a valid .ko for the running kernel,
# unlike `modprobe`, which needs /lib/modules to be writable and depmod'd).
# This does NOT survive a kernel update by itself — rebuild and reload after
# one, since DKMS's auto-rebuild-on-kernel-postinst hook assumes a distro
# where /lib/modules is writable.

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
PWD  := $(shell pwd)
CC   ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?= -Wl,-z,relro,-z,now
DECK_PREFIX ?= $(HOME)/.local/share/anticheat

# If the running kernel was built with clang/LLVM, build the module with
# the same toolchain (Kbuild flags are not compatible with gcc).
# Prefer $(KDIR)/.config (authoritative); some minimal/embedded
# headers packages omit it or ship it unreadable, in which case grep
# quietly fails and the old single-check logic silently defaulted to gcc
# -- surfacing later as an opaque `Invalid module format` at insmod time.
# /proc/version is only a fallback for the running kernel itself: for a
# different target (KDIR override) the host's version string says nothing
# about the target, so warn and require an explicit LLVM=1/CC=... instead.
# CONFIG_CC_IS_CLANG covers only the C compiler -- a kernel can pair clang
# with GNU as/ld, where full LLVM=1 (llvm-as/ld) would pick the wrong
# binutils -- so select LLVM=1 only for a fully-LLVM target (CC+AS+LD all
# LLVM) and pass CC=clang alone for a mixed toolchain. The /proc/version
# fallback is compiler-only too (it names the CC, never AS/LD), so it also
# selects CC=clang only; pass LLVM=1 explicitly for a known full-LLVM
# target. Explicit LLVM=/CC= on the command line or environment always
# wins over auto-detection.
AC_KCONFIG_READABLE := $(shell test -r $(KDIR)/.config && echo 1 || echo 0)
AC_CC_CLANG := $(shell grep -q '^CONFIG_CC_IS_CLANG=y' $(KDIR)/.config 2>/dev/null && echo 1 || echo 0)
AC_AS_LLVM := $(shell grep -q '^CONFIG_AS_IS_LLVM=y' $(KDIR)/.config 2>/dev/null && echo 1 || echo 0)
AC_LD_LLD := $(shell grep -q '^CONFIG_LD_IS_LLD=y' $(KDIR)/.config 2>/dev/null && echo 1 || echo 0)
AC_PROC_CLANG := $(shell grep -q 'clang version' /proc/version 2>/dev/null && echo 1 || echo 0)
AC_RUNNING_KDIR := /lib/modules/$(shell uname -r)/build
AC_IS_RUNNING := $(shell test "$(KDIR)" = "$(AC_RUNNING_KDIR)" && echo 1 || echo 0)
# An explicit CC=... (command line or environment) is authoritative: skip
# LLVM auto-detection entirely so CC=gcc can never end up paired with
# LLVM binutils, and forward it as a Kbuild command-line variable (an
# environment-only CC would be inheritable but overridable inside Kbuild).
AC_CC_EXPLICIT := $(if $(filter command\ line environment,$(origin CC)),1,0)
ifeq ($(origin LLVM),undefined)
ifeq ($(AC_CC_EXPLICIT),0)
ifeq ($(AC_CC_CLANG),1)
ifeq ($(AC_AS_LLVM),1)
ifeq ($(AC_LD_LLD),1)
LLVM := 1
else
AC_KBUILD_CC := clang
endif
else
AC_KBUILD_CC := clang
endif
else ifeq ($(AC_KCONFIG_READABLE),0)
ifeq ($(AC_IS_RUNNING),1)
ifeq ($(AC_PROC_CLANG),1)
AC_KBUILD_CC := clang
else
$(warning $(KDIR)/.config not readable and /proc/version does not mention clang -- defaulting to gcc; if the running kernel was built with clang, the module may fail to load with 'Invalid module format')
endif
else
$(warning $(KDIR)/.config not readable and KDIR does not target the running kernel ($(AC_RUNNING_KDIR)) -- cannot infer the target toolchain from host /proc/version; pass LLVM=1 (full LLVM) or CC=clang (mixed clang/GNU) explicitly if the target kernel was built with clang)
endif
endif
endif
endif
# Effective CC for the recursive Kbuild call: explicit user CC wins,
# otherwise the mixed-toolchain fallback (if any). Passed as a command-line
# variable so Kbuild cannot override it.
AC_MODULE_CC := $(if $(filter 1,$(AC_CC_EXPLICIT)),$(CC),$(AC_KBUILD_CC))

obj-m += anticheat.o
anticheat-objs := src/anticheat_module.o src/sha256.o

all: module daemon

module:
	$(MAKE) -C $(KDIR) M=$(PWD) LLVM=$(LLVM) $(if $(AC_MODULE_CC),CC="$(AC_MODULE_CC)") modules

daemon: src/anticheat_daemon.c src/sha256.c src/sha256.h src/anticheat.h
	$(CC) $(CFLAGS) -o anticheat src/anticheat_daemon.c src/sha256.c $(LDFLAGS) -pie

mock: test/libmock_anticheat.so

test/libmock_anticheat.so: test/mock_anticheat.c src/anticheat.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl $(LDFLAGS)

# real (non-mock) live test helper: proves ac_ioctl() rechecks
# CAP_SYS_ADMIN by opening /dev/anticheat as root, dropping privileges,
# and confirming the ioctl is rejected. Needs the module loaded and root
# to run -- see test.sh.
priv-drop-test: test/priv_drop_test

test/priv_drop_test: test/priv_drop_test.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# render-hook live test helper: self-hooks vkQueuePresentKHR in its own
# process (harmless -- the patched bytes are never called) so `scan
# --check-hooks` has a real, known-tampered target to detect. Needs root
# to run the scan against it (uses the device) -- see test.sh.
render-hook-test: test/render_hook_test

test/render_hook_test: test/render_hook_test.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $< -ldl $(LDFLAGS)

# mount-namespace live test helper: dlopen()s an explicit path inside a
# private mount namespace test.sh sets up, so the render-hook check's
# /proc/<pid>/root/ resolution can be proven against a real target whose
# view of a path differs from the host's. Needs root (mount namespaces,
# the module) -- see test.sh.
mount-ns-test: test/mount_ns_probe

test/mount_ns_probe: test/mount_ns_probe.c
	$(CC) $(CFLAGS) -o $@ $< -ldl $(LDFLAGS)

# anon-exec/JIT-allowlist live test helper: on SIGUSR1, maps one new
# anonymous executable page in itself (the same signal a JIT or injected
# shellcode produces) so the --jit allowlist's severity-downgrade path
# can be proven against a real, controllable growth event. Needs root to
# run the scan against it -- see test.sh.
anon-exec-test: test/anon_exec_test

test/anon_exec_test: test/anon_exec_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# thread-exit-migration live test helper: single leader thread + one
# worker, protected by the leader's tid, then the leader alone exits via
# pthread_exit() while the worker keeps running -- exercises
# ac_exit_pre()'s registry-migration path (ac_replace_prot_task()). Needs
# root and the module loaded -- see test.sh.
thread-exit-migration-test: test/thread_exit_migration_test

test/thread_exit_migration_test: test/thread_exit_migration_test.c src/anticheat.h
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

# thread-spawn-after-protect live test helper: a pthread_create() by an
# already-protected thread must not get its own registry slot -- exercises
# ac_clone_ret()'s CLONE_THREAD dedup (guards against duplicate registry
# entries / AC_PROT_MAX exhaustion). Needs root and the module loaded --
thread-spawn-after-protect-test: test/thread_spawn_after_protect_test

test/thread_spawn_after_protect_test: test/thread_spawn_after_protect_test.c src/anticheat.h
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

# process_vm denial test: proves process_vm_readv/writev against a
# protected victim are rewritten to -ESRCH and emit AC_EV_PROCESS_VM,
# and with ac_policy 0x1 / AC_MOCK_ATTACK=1 the attacker is SIGKILLed.
# Runs both natively and (on x86-64) via int $0x80 compat numbers when
# available -- see test/process_vm_test.c.
process-vm-test: test/process_vm_test

test/process_vm_test: test/process_vm_test.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
# surface any local process holding an open fd can reach. Against the
# mock this only proves the harness itself doesn't crash (see its own
# header comment); the real run is against a loaded module, as root,
# watching dmesg -- see README's "ioctl fuzzing" section.
ioctl-fuzz: test/ioctl_fuzz

test/ioctl_fuzz: test/ioctl_fuzz.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# baseline-file unit test (#51): pulls anticheat_daemon.c in directly (no
# kernel/mock scan involved -- baseline_save_record()/baseline_load_records()/
# baseline_find_record() are pure file I/O) and proves a second (inode,
# offset) segment saved to the same path's baseline file doesn't clobber
# the first. See test/baseline_test.c.
baseline-test: test/baseline_test
	./test/baseline_test

test/baseline_test: test/baseline_test.c src/anticheat_daemon.c src/sha256.c src/sha256.h src/anticheat.h
	$(CC) $(CFLAGS) -o $@ test/baseline_test.c src/sha256.c $(LDFLAGS)

# ac_report() HTTP status-line parsing unit test (#57): pulls
# anticheat_daemon.c in directly and proves ac_http_status_code() decides
# success/failure from the status line only, not a substring match on the
# raw response, and rejects a malformed status code (e.g. a leading sign).
# See test/ac_report_status_test.c.
ac-report-status-test: test/ac_report_status_test
	./test/ac_report_status_test

test/ac_report_status_test: test/ac_report_status_test.c src/anticheat_daemon.c src/sha256.c src/sha256.h src/anticheat.h
	$(CC) $(CFLAGS) -o $@ test/ac_report_status_test.c src/sha256.c $(LDFLAGS)

# ac_report() AC_REPORT_URL parsing unit test (#67): pulls
# anticheat_daemon.c in directly and proves ac_report_parse_url() accepts
# both the existing "host:port" TCP form and the new "unix:///path"
# AF_UNIX form, and rejects a malformed/oversized one. See
# test/ac_report_url_test.c; the real AF_UNIX connect()/send()/recv()
# path this feeds is exercised against a real server in
test/ac_report_url_test: test/ac_report_url_test.c src/anticheat_daemon.c src/sha256.c src/sha256.h src/anticheat.h
	$(CC) $(CFLAGS) -o $@ test/ac_report_url_test.c src/sha256.c $(LDFLAGS)

# pagination/cap smoke test (Phase 5.4): mock returns n_vmas=5000, n_mods=1100,
# n_events=70 when AC_MOCK_PAGINATION=1; pagination_test proves begin/get/end
# truncation and AC_GET_EVENTS_MAX_BLOCK_MS clamping.
pagination-test: test/pagination_test
	./test/pagination_test

test/pagination_test: test/pagination_test.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
# run the daemon CLI against the userspace mock (no kernel module, no root)
test-mock: mock daemon
	./test/mock_test.sh

# CI entry point: rebuild all userspace with warnings-as-errors and run the
# full no-root test suite.  (The kernel module build needs real kernel
# headers and is exercised separately in CI against a prepared kernel tree.)
ci:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O2 -Wall -Wextra -Werror" daemon mock baseline-test ac-report-status-test ac-report-url-test
	./test/mock_test.sh

clean:
	@if [ -d $(KDIR) ]; then $(MAKE) -C $(KDIR) M=$(PWD) clean; fi
	rm -f anticheat test/libmock_anticheat.so test/priv_drop_test test/render_hook_test test/mount_ns_probe test/anon_exec_test test/thread_exit_migration_test test/thread_spawn_after_protect_test test/process_vm_test test/pagination_test test/ioctl_fuzz test/baseline_test test/ac_report_status_test test/ac_report_url_test
install: all
	install -D -m 0755 anticheat /usr/local/sbin/anticheat
	install -D -m 0644 anticheat.ko /lib/modules/$(KVER)/extra/anticheat.ko
	install -d -m 0755 /var/lib/anticheat/baselines
	depmod -a
	@echo "installed. load with: sudo modprobe anticheat  (or insmod ./anticheat.ko)"

uninstall:
	rm -f /usr/local/sbin/anticheat
	rm -f /lib/modules/$(KVER)/extra/anticheat.ko
	depmod -a

# SteamOS / immutable-distro install: everything lives under $(DECK_PREFIX)
# (default: ~/.local/share/anticheat), which survives OTA image updates
# because it's in the user's home, not the read-only system image. No
# /lib/modules write, no depmod — the module is loaded directly by path.
install-deck: all
	install -D -m 0755 anticheat $(DECK_PREFIX)/bin/anticheat
	install -D -m 0644 anticheat.ko $(DECK_PREFIX)/anticheat.ko
	install -d -m 0755 $(DECK_PREFIX)/baselines
	@echo "installed under $(DECK_PREFIX)"
	@echo "load with: sudo insmod $(DECK_PREFIX)/anticheat.ko"
	@echo "run the daemon with: sudo AC_BASELINE_DIR=$(DECK_PREFIX)/baselines $(DECK_PREFIX)/bin/anticheat start"

uninstall-deck:
	rm -rf $(DECK_PREFIX)

.PHONY: all module daemon mock test-mock priv-drop-test render-hook-test mount-ns-test thread-exit-migration-test thread-spawn-after-protect-test process-vm-test pagination-test ioctl-fuzz baseline-test ac-report-status-test ac-report-url-test ci clean install uninstall install-deck uninstall-deck
