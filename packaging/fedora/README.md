# Fedora / RPM packaging

`hypranticheat.spec` is a standard rpmbuild spec producing the same
`hypranticheat` / `hypranticheat-dkms` split as the AUR (`packaging/aur/`)
and Debian (`packaging/debian/`) packages.

## Building

```sh
rpmdev-setuptree                      # once, if not already done
spectool -g -R hypranticheat.spec     # fetches Source0 into ~/rpmbuild/SOURCES
rpmbuild -ba hypranticheat.spec
```

(`spectool` is part of `rpmdevtools`.) `Source0` points at the same
tag-pinned GitHub release tarball the AUR `PKGBUILD` uses — this only
resolves once the version in the spec is actually tagged upstream (see
`RELEASING.md`). To build before a tag exists, generate a local tarball
the same way the AUR README describes for testing:

```sh
git archive --format=tar --prefix=anticheat_x86-64-<version>/ HEAD \
    | gzip > ~/rpmbuild/SOURCES/v<version>.tar.gz
rpmbuild -ba hypranticheat.spec
```

## Split package

Same split, for the same reason (either half can be reinstalled or
rebuilt independently):

- **`hypranticheat`** — the userspace daemon/CLI (`anticheat`), docs, and
  the `/var/lib/anticheat/baselines` state directory.
- **`hypranticheat-dkms`** — the kernel module source, registered with
  DKMS. Its `%post`/`%preun` scriptlets do the same dkms-add/build/install
  + Secure Boot MOK signing-key setup as `scripts/dkms-install.sh` and the
  AUR package's `.install` hooks, using rpm's own `%post $1`/`%preun $1`
  install-vs-upgrade-vs-removal argument convention instead of pacman's —
  with one deliberate difference: Fedora packaging guidelines forbid
  interactive scriptlets, so `%post` never runs the MOK enrollment prompt
  itself (unlike `dkms-install.sh` and the AUR package); it only prints
  the `mokutil --import` command for you to run manually. See
  `%description dkms` in the spec.

`x86-64` only (`ExclusiveArch: x86_64`) — see README.md's "Build" section
for why.

## Not yet verified

Unlike the AUR package (built and `namcap`-checked on a real Arch
machine — see `packaging/aur/README.md`), this spec has **not** been run
through a real `rpmbuild`/`rpmlint`/`dnf install` cycle — none of
`rpmbuild`, `rpmlint`, or `rpmdevtools` were available in the environment
this was authored in. Before relying on this for a real install, build it
and check `rpmlint ~/rpmbuild/RPMS/x86_64/hypranticheat*.rpm` comes back
clean, and run through a real
`dnf install ~/rpmbuild/RPMS/x86_64/hypranticheat*.rpm` /
`dnf remove hypranticheat-dkms` cycle on a disposable VM (the DKMS + MOK
setup mutates real system state — `/etc/dkms/`, `/var/lib/dkms/`, the
running kernel's module tree — same reason the AUR README gives for not
testing `pacman -U` on the authoring machine). A container isn't enough
for the full cycle: it shares the host kernel, so it can't actually build
against or load a real kernel module, and has no UEFI to enroll a MOK
into — it only exercises package install/removal and the scriptlets'
own logic (the dkms-status parsing, the `--force`/upgrade handling, the
non-interactive MOK messaging), not the DKMS build or Secure Boot
enrollment themselves.
