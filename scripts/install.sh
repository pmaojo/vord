#!/usr/bin/env sh
# yunq installer.
#
#   curl -fsSL https://raw.githubusercontent.com/pmaojo/yunq/main/scripts/install.sh | sh
#
# Downloads the release binary for this platform, verifies its published
# SHA-256, and installs it. POSIX sh on purpose: this is the first thing a
# new user runs, so it must not assume bash, and it must fail loudly rather
# than half-install.
#
# Environment:
#   YUNQ_VERSION  tag to install (default: latest)
#   YUNQ_BIN_DIR  install directory (default: /usr/local/bin, else ~/.local/bin)
#   YUNQ_LSP      set to 1 to also install the language server

set -eu

REPO="pmaojo/yunq"
VERSION="${YUNQ_VERSION:-latest}"

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }
need uname
need mktemp

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
else
  die "neither curl nor wget is available"
fi

# --- platform -------------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)  os_part="unknown-linux-musl" ;;
  Darwin) os_part="apple-darwin" ;;
  MINGW*|MSYS*|CYGWIN*)
    die "Windows: download yunq-x86_64-pc-windows-msvc.exe from https://github.com/$REPO/releases/latest" ;;
  *) die "unsupported OS: $os" ;;
esac

case "$arch" in
  x86_64|amd64)  arch_part="x86_64" ;;
  arm64|aarch64) arch_part="aarch64" ;;
  *) die "unsupported architecture: $arch" ;;
esac

target="${arch_part}-${os_part}"

# --- install directory ----------------------------------------------------
if [ -n "${YUNQ_BIN_DIR:-}" ]; then
  bin_dir="$YUNQ_BIN_DIR"
elif [ -w /usr/local/bin ] 2>/dev/null; then
  bin_dir="/usr/local/bin"
else
  bin_dir="$HOME/.local/bin"
fi
mkdir -p "$bin_dir" || die "cannot create $bin_dir"
[ -w "$bin_dir" ] || die "$bin_dir is not writable — set YUNQ_BIN_DIR or re-run with sudo"

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$tmp'" EXIT INT TERM

# --- download + verify ----------------------------------------------------
install_one() {
  name="$1"          # yunq | yunq-lsp
  asset="$2"         # release asset filename

  info "Downloading $asset"
  fetch "$base/$asset" "$tmp/$asset" \
    || die "download failed: $base/$asset (does a release exist for $VERSION?)"

  # A checksum we cannot fetch is reported, never silently skipped: "we
  # verified nothing" and "we verified successfully" must not look alike.
  if fetch "$base/$asset.sha256" "$tmp/$asset.sha256" 2>/dev/null; then
    expected="$(awk '{print $1}' "$tmp/$asset.sha256")"
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
    else
      actual=""
      printf '\033[33mwarning:\033[0m no sha256 tool found — checksum NOT verified\n' >&2
    fi
    if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
      die "checksum mismatch for $asset (expected $expected, got $actual) — refusing to install"
    fi
  else
    printf '\033[33mwarning:\033[0m no published checksum for %s — not verified\n' "$asset" >&2
  fi

  chmod +x "$tmp/$asset"
  mv "$tmp/$asset" "$bin_dir/$name"
  info "Installed $bin_dir/$name"
}

install_one yunq "yunq-${target}"
[ "${YUNQ_LSP:-0}" = "1" ] && install_one yunq-lsp "yunq-lsp-${target}"

# --- report ---------------------------------------------------------------
printf '\n'
"$bin_dir/yunq" --version || die "the installed binary does not run on this machine"

case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) printf '\n\033[33mNote:\033[0m %s is not on your PATH. Add it:\n  export PATH="%s:$PATH"\n' "$bin_dir" "$bin_dir" ;;
esac

cat <<'EOF'

Next steps:
  yunq scan .              analyze this repository
  yunq hook install        gate an AI agent's writes before they reach disk
  yunq init                add the CI workflow

Docs: https://github.com/pmaojo/yunq
EOF
