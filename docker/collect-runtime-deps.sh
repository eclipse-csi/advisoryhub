#!/usr/bin/env bash
# Assemble a staging tree with everything the shell-less production stage
# needs beyond the DHI python runtime base: git, ssh, libnss_wrapper, the
# shared-library closure they load, and dpkg metadata so image scanners
# still see the staged packages. The final Dockerfile stage does
# `COPY --from=runtime-deps /staging/ /` and nothing else.
#
# Runs in the runtime-deps build stage (DHI *dev* variant: bash + apt).
# Source and destination are the same Debian 13 release line — the dev and
# runtime variants of one DHI python release — so any library staged over
# an existing base file is byte-identical.
set -euo pipefail

STAGING="${1:?usage: collect-runtime-deps.sh <staging-dir>}"
PACKAGES=(git openssh-client libnss-wrapper)

# Stage one path, preserving symlinks hop by hop (a soname symlink such as
# libcurl-gnutls.so.4 -> libcurl-gnutls.so.4.x must survive as a symlink or
# the loader can't resolve it). Directories are canonicalized through
# realpath: Debian 13 is usr-merged (/lib -> /usr/lib), and a real
# /staging/lib directory would collide with the base's symlink when the
# final stage COPYs /staging/ onto /.
stage() {
    local p="$1"
    while :; do
        local dir name src dest
        dir="$(realpath -e "$(dirname "$p")")"
        name="$(basename "$p")"
        src="$dir/$name"
        dest="$STAGING$src"
        if [ ! -e "$dest" ] && [ ! -L "$dest" ]; then
            mkdir -p "$(dirname "$dest")"
            if [ -L "$src" ]; then
                cp -P "$src" "$dest"
            else
                # -l keeps the git/git-core hardlink dedupe; plain copy as
                # a cross-filesystem fallback.
                cp -l "$src" "$dest" 2>/dev/null || cp "$src" "$dest"
            fi
        fi
        [ -L "$src" ] || break
        local target
        target="$(readlink "$src")"
        case "$target" in
            /*) p="$target" ;;
            *) p="$(dirname "$src")/$target" ;;
        esac
    done
}

# 1. Full package payloads, minus documentation that serves no runtime
# purpose (Debian policy: keep the copyright files).
for pkg in "${PACKAGES[@]}"; do
    while IFS= read -r f; do
        { [ -f "$f" ] || [ -L "$f" ]; } || continue
        case "$f" in
            /usr/share/man/* | /usr/share/locale/* | /usr/share/lintian/*) continue ;;
            /usr/share/doc/*) [[ $f == */copyright ]] || continue ;;
        esac
        stage "$f"
    done < <(dpkg -L "$pkg")
done

# 2. Shared-library closure of every staged ELF. ldd resolves the
# transitive tree in one pass, so this covers chains the top-level
# binaries never link directly (git-remote-https -> libcurl-gnutls ->
# gnutls -> nettle/p11-kit/...). ldd exits non-zero on non-ELF input —
# that is the filter.
while IFS= read -r f; do
    ldd "$f" 2>/dev/null | awk '/=> \//{print $3}' || true
done < <(find "$STAGING" -type f) | sort -u | while IFS= read -r lib; do
    stage "$lib"
done

# 3. The CA bundle gnutls is compiled to read. It is a *generated* file
# (update-ca-certificates output), absent from every dpkg -L listing. The
# runtime base ships it too, but stage it so git-over-HTTPS never depends
# on that assumption.
stage /etc/ssl/certs/ca-certificates.crt

# 4. dpkg metadata for scanners (the distroless status.d convention):
# every package owning a staged file gets its control stanza, so Trivy
# keeps flagging git/openssh/libcurl CVEs despite the file-level copy. A
# package may then appear both here and in the runtime base's status file
# at the same version — cosmetic duplication, gate behaviour unchanged.
mkdir -p "$STAGING/var/lib/dpkg/status.d"
find "$STAGING" -type f ! -path "$STAGING/var/lib/dpkg/*" -printf '/%P\n' \
    | { xargs -r dpkg -S 2>/dev/null || true; } \
    | sed 's|: /.*$||' | tr ',' '\n' | tr -d ' ' | sort -u \
    | while IFS= read -r pkg; do
        out="$STAGING/var/lib/dpkg/status.d/${pkg%%:*}"
        dpkg -s "$pkg" >"$out" 2>/dev/null || rm -f "$out"
    done

echo "staged $(find "$STAGING" -type f | wc -l) files," \
    "$(find "$STAGING/var/lib/dpkg/status.d" -type f | wc -l) package stanzas"
