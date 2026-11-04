#!/usr/bin/env bash
#
# setup.sh - installs everything needed to build textrealm/ (see
# textrealm/README.md's Dependencies section for the full rationale).
#
# Installs:
#   - build-essential (gcc, make)                 - linux/textrealm_server
#   - gcc-mingw-w64-x86-64                         - windows/textrealm_server.exe (64-bit)
#   - gcc-mingw-w64-i686                           - windows/textrealm_server32.exe (SEH demo)
#   - curl, unzip                                  - needed to fetch/extract cosmocc below
#   - cosmocc (Cosmopolitan toolchain), to $HOME/cosmocc - textrealm.com supervisor
#
# Safe to re-run: skips anything already installed/present.
#
# Usage: ./setup.sh

set -euo pipefail

COSMOCC_DIR="$HOME/cosmocc"
COSMOCC_URL="https://cosmo.zip/pub/cosmocc/cosmocc.zip"

log() { printf '\n==> %s\n' "$1"; }
ok()  { printf '    [ok] %s\n' "$1"; }
die() { printf 'error: %s\n' "$1" >&2; exit 1; }

# --- sanity checks ----------------------------------------------------------

if ! command -v apt-get >/dev/null 2>&1; then
    die "this script only supports Debian/Ubuntu (apt-get). Install these manually: gcc, make, gcc-mingw-w64-x86-64, gcc-mingw-w64-i686, and cosmocc (${COSMOCC_URL})."
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "not running as root and 'sudo' isn't available."
    SUDO="sudo"
fi

# --- apt packages ------------------------------------------------------------

log "Installing build tools via apt (gcc, make, MinGW-w64 cross-compilers, curl, unzip)"
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    gcc-mingw-w64-x86-64 \
    gcc-mingw-w64-i686 \
    curl \
    unzip

for tool in gcc make x86_64-w64-mingw32-gcc i686-w64-mingw32-gcc curl unzip; do
    command -v "$tool" >/dev/null 2>&1 && ok "$tool" || die "$tool still not found after apt install - check the apt output above."
done

# --- cosmocc ------------------------------------------------------------------

log "Checking for cosmocc (Cosmopolitan toolchain)"
if command -v "$COSMOCC_DIR/bin/cosmocc" >/dev/null 2>&1; then
    ok "cosmocc already installed at $COSMOCC_DIR/bin/cosmocc"
else
    log "Downloading and installing cosmocc to $COSMOCC_DIR"
    tmp_zip="$(mktemp -t cosmocc.XXXXXX.zip)"
    trap 'rm -f "$tmp_zip"' EXIT
    curl -fL -o "$tmp_zip" "$COSMOCC_URL"
    mkdir -p "$COSMOCC_DIR"
    unzip -q -o "$tmp_zip" -d "$COSMOCC_DIR"
    rm -f "$tmp_zip"
    trap - EXIT
    command -v "$COSMOCC_DIR/bin/cosmocc" >/dev/null 2>&1 \
        || die "cosmocc extraction finished but $COSMOCC_DIR/bin/cosmocc still isn't there - check $COSMOCC_URL is still valid."
    ok "cosmocc installed at $COSMOCC_DIR/bin/cosmocc"
fi

# --- python3 (used by the PoC scripts under poc-scripts/) -------------------

log "Checking for python3 (used by poc-scripts/*.py)"
command -v python3 >/dev/null 2>&1 || die "python3 not found - install it with: $SUDO apt-get install -y python3"
ok "python3 found"

log "All set."
cat <<'EOF'

Next steps:
    cd textrealm
    make clean
    make
    ./textrealm.com        # or ./linux/textrealm_server

(The Makefile looks for cosmocc at $HOME/cosmocc/bin/cosmocc automatically.)
EOF
