Name:           hypranticheat
Version:        1.0.0
Release:        1%{?dist}
Summary:        Kernel-mode anticheat: syscall/module integrity, ptrace denial, RWX/anon-exec detection

License:        GPL-2.0-only
URL:            https://github.com/keanehatescoding/anticheat_x86-64
# Same immutable, tag-pinned release tarball the AUR PKGBUILD uses (see
# packaging/aur/PKGBUILD). GitHub names the directory inside it after the
# *repository* (anticheat_x86-64-%{version}/), not after this package
# (hypranticheat) and not after the tarball's own filename -- verified
# against a real archive; %%autosetup's -n below has to match that.
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
Requires:       glibc

# Only x86-64 is supported: the kernel module hooks __x64_sys_*/
# __ia32_sys_* kprobe symbols specifically -- see README.md's "Build"
# section. ExclusiveArch (rather than just documenting it) makes an
# accidental %{?dist}-wide rebuild fail loudly instead of shipping a
# package that can never actually load its module.
ExclusiveArch:  x86_64

%description
A Linux kernel-mode anticheat: a loadable kernel module (LKM) performing
kernel-level integrity checks and process protection, plus this userspace
daemon/CLI that talks to it over a small ioctl interface
(/dev/anticheat) -- protect/scan/baseline/monitor commands, see
`anticheat --help`.

This package installs the daemon and CLI (anticheat) only. Real
kernel-level detection needs the companion hypranticheat-dkms package;
without it the daemon can only run against its userspace mock.

%package dkms
Summary:        Kernel module (DKMS) for a kernel-mode anticheat
# mok_signing_key/mok_certificate/framework.conf.d support (what %%post's
# /etc/dkms/framework.conf.d/anticheat.conf fragment relies on) only
# exists from DKMS 3.0 -- an older dkms would silently ignore that
# fragment and build unsigned.
Requires:       dkms >= 3.0
Requires:       %{name} = %{version}-%{release}
Provides:       anticheat-dkms
ExclusiveArch:  x86_64

%description dkms
Kernel module source for hypranticheat (syscall/module integrity, ptrace
denial, RWX/anon-exec detection), registered with DKMS so it is rebuilt
automatically on every kernel package upgrade. Building it needs Linux
kernel headers for the running kernel.

On install this package also points DKMS's built-in Secure Boot signing
at a self-generated Machine Owner Key (MOK) under /var/lib/anticheat/mok/.
Fedora packaging guidelines don't allow an interactive scriptlet, so unlike
upstream's scripts/dkms-install.sh and the AUR package, this package does
NOT run the MOK enrollment prompt for you -- if Secure Boot is on, enroll
it yourself once after installing with "sudo mokutil --import
/var/lib/anticheat/mok/mok.der", then reboot and approve it in the blue
"MOK Management" screen (Enroll MOK -> Continue -> enter the one-time
password -> Reboot). Until you do this, the signed module will fail to
load.

%prep
%autosetup -n anticheat_x86-64-%{version}

%build
# The daemon only -- the kernel module isn't buildable at package-build
# time (it needs the *installing* machine's own running kernel's
# headers, not the builder's); DKMS handles that at install time via the
# dkms subpackage below, same division as the AUR PKGBUILD.
%make_build CFLAGS="%{optflags}" daemon

%install
install -Dm755 anticheat %{buildroot}%{_bindir}/anticheat
install -dm755 %{buildroot}%{_localstatedir}/lib/anticheat/baselines

_dkmsdir=%{buildroot}%{_usrsrc}/anticheat-%{version}
install -Dm644 Makefile "${_dkmsdir}/Makefile"
install -Dm644 dkms.conf "${_dkmsdir}/dkms.conf"
cp -a src "${_dkmsdir}/"

install -Dm644 /dev/stdin \
    %{buildroot}%{_sysconfdir}/dkms/framework.conf.d/anticheat.conf <<-EOF
	mok_signing_key="/var/lib/anticheat/mok/mok.priv"
	mok_certificate="/var/lib/anticheat/mok/mok.der"
	EOF
# DKMS's own signing step creates the MOK key pair here on first build;
# pre-create the (empty, private) directory so that has somewhere to
# write regardless of install order.
install -dm700 %{buildroot}%{_localstatedir}/lib/anticheat/mok

%files
%license LICENSE
%doc README.md THREAT_MODEL.md TROUBLESHOOTING.md
%{_bindir}/anticheat
%dir %attr(0755,root,root) %{_localstatedir}/lib/anticheat
%dir %{_localstatedir}/lib/anticheat/baselines

%files dkms
%license LICENSE
%dir %{_usrsrc}/anticheat-%{version}
%{_usrsrc}/anticheat-%{version}/Makefile
%{_usrsrc}/anticheat-%{version}/dkms.conf
%{_usrsrc}/anticheat-%{version}/src
%config(noreplace) %{_sysconfdir}/dkms/framework.conf.d/anticheat.conf
%dir %attr(0700,root,root) %{_localstatedir}/lib/anticheat/mok

# DKMS's own exit code for "kernel headers for this kernel cannot be found"
# is 21 (see prepare_kernel() in dkms itself) -- stable, documented in
# dkms's own source, and distinct from every other failure class. Only
# that specific code is a "this will build itself later via AUTOINSTALL"
# situation (see dkms.conf); every other nonzero exit is a real failure.
%post dkms
# Remove any previously-registered anticheat DKMS version other than this
# one, so an upgrade doesn't leave a stale build registered alongside the
# new one -- same reasoning as the AUR package's post_upgrade hook, but
# done by asking dkms directly rather than diffing old/new version
# strings, since rpm %%post's "$1 == 2 means upgrade" doesn't tell us
# what the *previous* version actually was.
#
# dkms status prints "<module>/<version>, <kernel>, <arch>: <status>" per
# built kernel (or just "<module>/<version>: added" before any kernel
# build exists) -- the module *version* is inside field 1, not field 2
# (that's the kernel version); field 1 can also carry a trailing
# ": <status>" when there's no kernel/arch part, hence the extra `cut -d:`.
# sort -u collapses the one-line-per-built-kernel duplication down to
# distinct versions.
for old in $(dkms status -m anticheat 2>/dev/null | cut -d, -f1 | cut -d: -f1 | cut -d/ -f2 | tr -d ' ' | sort -u); do
    [ "$old" = "%{version}" ] && continue
    dkms remove -m anticheat -v "$old" --all >/dev/null 2>&1 || true
done

# --force: without it, `dkms install` for a version DKMS already has
# registered as installed (a Release-only reinstall/upgrade that didn't
# change Version, so %{version} is unchanged and the stale-version cleanup
# loop above deliberately left it alone) can fail instead of rebuilding
# against the just-updated /usr/src/anticheat-%{version} source -- same
# reasoning as the AUR package's post_upgrade hook, which passes --force
# here for exactly this case.
dkms add -m anticheat -v %{version} >/dev/null 2>&1 || true
dkms install --force -m anticheat -v %{version}
rc=$?
case "$rc" in
    0)
        ;;
    21)
        echo "==> dkms install deferred -- no matching kernel headers yet;"
        echo "==> it will build automatically the next time a kernel with"
        echo "==> headers installed is booted (AUTOINSTALL, see dkms.conf)."
        echo "==> note: the Secure Boot signing key also won't exist until"
        echo "==> that later build actually happens -- once it has (check"
        echo "==> 'dkms status -m anticheat'), re-run:"
        echo "==>   sudo mokutil --import /var/lib/anticheat/mok/mok.der"
        echo "==> if Secure Boot is on, to pick up enrollment."
        rc=0
        ;;
    *)
        echo "==> dkms install FAILED (exit $rc, not the missing-headers" >&2
        echo "==> case above) -- see the dkms output above for the real" >&2
        echo "==> error, and 'sudo dkms status -m anticheat' /" >&2
        echo "==> /var/lib/dkms/anticheat/%{version}/*/log/make.log for detail." >&2
        ;;
esac

# Fedora packaging guidelines require scriptlets to never be interactive
# (rpm-scriptlets(7); a %post can run with both stdin/stdout attached to a
# real terminal during an interactive `dnf install`, unlike Debian's more
# permissive-when-a-tty's-present policy -- see the tty-gated version of
# this in packaging/debian/hypranticheat-dkms.postinst), so unlike that
# script, this one never calls `mokutil --import` itself at all -- only
# ever prints the manual command (also documented in %description dkms).
cert=/var/lib/anticheat/mok/mok.der
if [ -e "$cert" ]; then
    if ! command -v mokutil >/dev/null 2>&1; then
        echo "==> mokutil not found -- if Secure Boot is on, install it and run:"
        echo "==>   sudo mokutil --import $cert"
    elif mokutil --sb-state 2>/dev/null | grep -qi enabled; then
        if mokutil --test-key "$cert" 2>/dev/null | grep -qi "already enrolled"; then
            :
        else
            echo "==> Secure Boot is ON and hypranticheat's signing key is not yet trusted."
            echo "==> Enroll it manually (this scriptlet won't prompt for you):"
            echo "==>   sudo mokutil --import $cert"
            echo "==> then REBOOT and approve it in the blue 'MOK Management' screen"
            echo "==> (Enroll MOK -> Continue -> enter the password -> Reboot). Until you"
            echo "==> do this, the signed module will still fail to load."
        fi
    fi
fi

[ "$rc" -eq 0 ] && echo "==> load it with: sudo modprobe anticheat"
exit "$rc"

%preun dkms
# $1 == 0 is a real, final removal; $1 == 1 is "being removed as part of
# an upgrade" (the new package's own %%post above already re-added and
# rebuilt for the new version) -- only tear the module down in the
# former case, matching the AUR package's pre_remove hook.
if [ "$1" = "0" ]; then
    dkms remove -m anticheat -v %{version} --all >/dev/null 2>&1 || true
fi
exit 0

%changelog
* Wed Aug 26 2026 keanehatescoding <noreply@users.noreply.github.com> - 1.0.0-1
- Initial Fedora packaging: hypranticheat (daemon/CLI) and
  hypranticheat-dkms (kernel module via DKMS + Secure Boot MOK signing,
  same setup as scripts/dkms-install.sh and the AUR package).
