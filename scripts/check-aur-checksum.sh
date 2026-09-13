#!/usr/bin/env bash
# check-aur-checksum.sh — arm the AUR PKGBUILD's `sha256sums=('SKIP')`
# placeholder so it can't outlive the tag it's waiting on.
#
# packaging/aur/PKGBUILD points `source=` at an immutable, tag-pinned
# GitHub release tarball specifically so `sha256sums` can be a real,
# checkable digest rather than the `SKIP` a mutable `git+#tag=` source
# would force (see that file's own comment).  Until v<pkgver> is actually
# tagged upstream there is nothing to hash, so `SKIP` sits there as a
# documented placeholder — harmless while it's true, a silent
# supply-chain hole the moment the tarball exists and nobody remembers
# RELEASING.md's `updpkgsums` step.
#
# So: tolerate `SKIP` only while the tag genuinely doesn't exist, and
# turn it into a hard failure the moment it does.  Nothing has to be
# remembered; the check arms itself.
#
# Usage: ./scripts/check-aur-checksum.sh [--offline]
#
#   --offline   Skip every network lookup.  Only the PKGBUILD/.SRCINFO
#               consistency checks run, and the placeholder verdict is
#               reported as undetermined rather than enforced.
#
# Exit status: 0 ok (or undetermined), 1 a check failed.
set -euo pipefail

OFFLINE=0
case "${1-}" in
    --offline) OFFLINE=1 ;;
    "") ;;
    *) echo "usage: $0 [--offline]" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKGBUILD="$ROOT/packaging/aur/PKGBUILD"
SRCINFO="$ROOT/packaging/aur/.SRCINFO"

for f in "$PKGBUILD" "$SRCINFO"; do
    [ -r "$f" ] || { echo "check-aur-checksum: missing $f" >&2; exit 1; }
done

fail=0
err() { echo "check-aur-checksum: ERROR: $*" >&2; fail=1; }
note() { echo "check-aur-checksum: $*"; }

# --- parse PKGBUILD ------------------------------------------------------
# Deliberately parsed, not sourced.  Sourcing would be shorter, but it
# also runs the file's build()/package_*() definitions through the
# current shell, and the whole point of this script is to be safe to run
# on a PKGBUILD nobody has re-read since it was last edited.
field() { sed -n "s/^$1=\\(.*\\)\$/\\1/p" "$PKGBUILD" | head -1; }

pkgbase="$(field pkgbase)"
pkgver="$(field pkgver)"
[ -n "$pkgbase" ] || err "no pkgbase= in PKGBUILD"
[ -n "$pkgver" ] || err "no pkgver= in PKGBUILD"

# source=("name::url") — take the url half, then expand the only two
# variables the line is allowed to use.
src_raw="$(sed -n 's/^source=(\([^)]*\)).*$/\1/p' "$PKGBUILD" | head -1)"
src_entry="${src_raw%\"}"; src_entry="${src_entry#\"}"
src_url="${src_entry#*::}"
src_url="${src_url//\$\{pkgver\}/$pkgver}"
src_url="${src_url//\$pkgver/$pkgver}"
src_url="${src_url//\$\{pkgbase\}/$pkgbase}"
src_url="${src_url//\$pkgbase/$pkgbase}"
[ -n "$src_url" ] || err "could not parse source= url from PKGBUILD"

# sha256sums=('...')  — trailing '# comment' is fine and is stripped.
sums_raw="$(sed -n "s/^sha256sums=(\\([^)]*\\)).*\$/\\1/p" "$PKGBUILD" | head -1)"
sha="${sums_raw//\'/}"
sha="${sha// /}"
[ -n "$sha" ] || err "could not parse sha256sums= from PKGBUILD"

note "pkgbase=$pkgbase pkgver=$pkgver"
note "source=$src_url"
note "sha256sums=$sha"

# A single-element sha256sums is the only shape this script (and the
# PKGBUILD's single-element source=) is written for; a second source
# added later without a matching digest must not slip through as "fine".
case "$sums_raw" in
    *\ * ) err "sha256sums has more than one element — this guard only" \
               "understands the single-source PKGBUILD it was written for;" \
               "extend it alongside whatever added the second source" ;;
esac

# --- PKGBUILD vs .SRCINFO -----------------------------------------------
# AUR itself reads .SRCINFO, not PKGBUILD, for the metadata it shows and
# for `sha256sums`.  A real digest computed by `updpkgsums` that never
# made it through `makepkg --printsrcinfo` is exactly as unprotected as
# the placeholder it replaced, so the two files disagreeing is its own
# failure, independent of the placeholder verdict below.
si_field() { sed -n "s/^[[:space:]]*$1 = \\(.*\\)\$/\\1/p" "$SRCINFO" | head -1; }

si_pkgver="$(si_field pkgver)"
si_sha="$(si_field sha256sums)"
si_src="$(si_field source)"
si_url="${si_src#*::}"

[ "$si_pkgver" = "$pkgver" ] || \
    err ".SRCINFO pkgver ($si_pkgver) != PKGBUILD pkgver ($pkgver)"
[ "$si_sha" = "$sha" ] || \
    err ".SRCINFO sha256sums ($si_sha) != PKGBUILD sha256sums ($sha)"
[ "$si_url" = "$src_url" ] || \
    err ".SRCINFO source url ($si_url) != PKGBUILD source url ($src_url)"

if [ "$fail" -eq 0 ]; then
    note ".SRCINFO is in sync with PKGBUILD"
else
    note "regenerate it with: cd packaging/aur && makepkg --printsrcinfo > .SRCINFO"
fi

# --- shape of the digest itself -----------------------------------------
# A value that is neither the placeholder nor a well-formed digest makes
# every verdict below meaningless, so note it and skip them rather than
# reporting "OK: a real digest" about a string that plainly isn't one.
shape_ok=1
if [ "$sha" != "SKIP" ] && ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    err "sha256sums is neither 'SKIP' nor a 64-hex-digit sha256: '$sha'"
    shape_ok=0
fi

# --- does the tag this placeholder is waiting on exist yet? -------------
# Derived from the PKGBUILD's own source= url rather than from this
# checkout's `origin`, so the thing being checked is the thing the
# package would actually download.
tag="v$pkgver"
repo_url="${src_url%%/archive/refs/tags/*}"
tag_state="unknown"

if [ "$OFFLINE" -eq 1 ]; then
    note "--offline: not looking up $tag"
elif [ "$repo_url" = "$src_url" ]; then
    err "source= url is not a github /archive/refs/tags/ tarball — can't" \
        "derive the repo to look $tag up in"
elif ! command -v git >/dev/null 2>&1; then
    note "git not found — cannot look up $tag"
else
    note "looking up $tag in $repo_url"
    # --exit-code is what makes "connected fine, no such ref" (status 2)
    # distinguishable from "couldn't talk to the remote at all" (any
    # other non-zero).  Without it both are 0 and an unreachable remote
    # would read as "tag absent" — i.e. as permission to keep SKIP.
    ls_status=0
    ls_out="$(GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=true \
                  git ls-remote --tags --exit-code \
                  "$repo_url" "refs/tags/$tag" 2>&1)" || ls_status=$?
    if [ "$ls_status" -eq 0 ]; then
        tag_state="present"
        note "$tag exists upstream: ${ls_out%%$'\n'*}"
    elif [ "$ls_status" -eq 2 ]; then
        tag_state="absent"
        note "$tag does not exist upstream yet"
    else
        note "WARNING: could not reach $repo_url (git ls-remote exited" \
             "$ls_status) — placeholder verdict undetermined this run"
        note "  ${ls_out%%$'\n'*}"
    fi
fi

# --- the verdict ---------------------------------------------------------
if [ "$shape_ok" -eq 1 ]; then
    case "$tag_state:$sha" in
        present:SKIP)
            err "$tag is tagged upstream but sha256sums is still the 'SKIP'" \
                "placeholder — the tarball it points at exists now, so this" \
                "ships an unverifiable source. Fix it before publishing:" \
                $'\n    cd packaging/aur && updpkgsums && makepkg --printsrcinfo > .SRCINFO' \
                $'\n  (RELEASING.md step 7; see also keanehatescoding/anticheat-arm64#46)'
            ;;
        absent:SKIP)
            note "OK: 'SKIP' is still the documented placeholder — $tag is not" \
                 "tagged yet, so there is no tarball to hash. This check fails" \
                 "on its own the moment that stops being true."
            ;;
        unknown:SKIP)
            note "NOTE: 'SKIP' not enforced this run (tag state undetermined)."
            ;;
        absent:*)
            err "sha256sums is a real digest but $tag does not exist upstream —" \
                "it cannot have been computed against the tarball this PKGBUILD" \
                "downloads"
            ;;
        *)
            note "OK: sha256sums is a real digest, not the placeholder"
            ;;
    esac
fi

# --- and does that digest actually match the tarball? -------------------
# Only reachable once a real digest is in place, so this costs nothing
# (no download at all) for as long as the placeholder is legitimately
# still there.  A mismatch is fatal; not being able to fetch is not —
# this reports what it verified rather than implying more.
if [ "$fail" -eq 0 ] && [ "$OFFLINE" -eq 0 ] && [ "$sha" != "SKIP" ] \
   && [ "$tag_state" = "present" ] && command -v curl >/dev/null 2>&1; then
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT
    note "verifying sha256sums against $src_url"
    if curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors \
            -o "$tmp" "$src_url"; then
        got="$(sha256sum "$tmp" | cut -d' ' -f1)"
        if [ "$got" = "$sha" ]; then
            note "OK: tarball hashes to the declared sha256sums"
        else
            err "tarball sha256 mismatch: declared $sha, downloaded $got." \
                "Re-run \`updpkgsums\` (and regenerate .SRCINFO). GitHub's" \
                "auto-generated tag archives have changed bytes before —" \
                "if the tag itself was never moved, that is the likely cause."
        fi
    else
        note "WARNING: could not download $src_url — digest not verified" \
             "against the real tarball this run"
    fi
fi

exit "$fail"
