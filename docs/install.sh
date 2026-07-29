#!/bin/sh
# field-cage installer for Linux
# Usage: curl -sSL https://takihito.github.io/field-cage/install.sh | sh
#
# field-cage requires Linux eBPF (cgroup/connect4, connect6, tracepoints) to
# run, so only linux/amd64 and linux/arm64 binaries are published. There is
# no macOS or Windows build.
set -eu

REPO="takihito/field-cage"
INSTALL_DIR="${FIELD_CAGE_INSTALL_DIR:-${HOME}/.local/bin}"

# Resolve INSTALL_DIR to absolute path
case "$INSTALL_DIR" in
  /*) ;;
  ~/*) INSTALL_DIR="${HOME}/${INSTALL_DIR#~/}" ;;
  *) INSTALL_DIR="$(pwd)/${INSTALL_DIR}" ;;
esac

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux*) OS="linux" ;;
  *)
    echo "Error: field-cage requires Linux (eBPF). Unsupported OS: $OS"
    exit 1
    ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)             echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

# Select checksum tool
SHASUM=""
if command -v sha256sum >/dev/null 2>&1; then
  SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHASUM="shasum -a 256"
else
  echo "Error: neither sha256sum nor shasum found. Install one and retry."
  exit 1
fi

# Resolve version: positional arg > FIELD_CAGE_VERSION env var > latest release
VERSION="${1:-${FIELD_CAGE_VERSION:-}}"
if [ -z "$VERSION" ]; then
  echo "Fetching latest version..."
  VERSION="$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"
  if [ -z "$VERSION" ]; then
    echo "Error: failed to fetch latest version"
    exit 1
  fi
fi
echo "Version: $VERSION"

# Download to temp directory
BINARY="field-cage_${OS}_${ARCH}"
CHECKSUMS="checksums.txt"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
WORK="$(mktemp -d 2>/dev/null || mktemp -d -t field-cage)"
trap 'rm -rf "$WORK"' EXIT

echo "Downloading ${BINARY}..."
curl -sSL -o "${WORK}/${BINARY}" "${BASE_URL}/${BINARY}"
curl -sSL -o "${WORK}/${CHECKSUMS}" "${BASE_URL}/${CHECKSUMS}"

# Verify checksum
echo "Verifying checksum..."
EXPECTED="$(grep " ${BINARY}\$" "${WORK}/${CHECKSUMS}" | cut -d ' ' -f 1)"
if [ -z "$EXPECTED" ]; then
  echo "Error: checksum not found for ${BINARY}"
  exit 1
fi
ACTUAL="$($SHASUM "${WORK}/${BINARY}" | cut -d ' ' -f 1)"
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Error: checksum mismatch"
  echo "  expected: $EXPECTED"
  echo "  actual:   $ACTUAL"
  exit 1
fi

# Install
chmod +x "${WORK}/${BINARY}"
if [ ! -d "$INSTALL_DIR" ]; then
  mkdir -p "$INSTALL_DIR" 2>/dev/null || {
    echo "Error: cannot create ${INSTALL_DIR} (permission denied)"
    echo "Choose a writable directory or run with sudo:"
    echo "  curl -sSL https://takihito.github.io/field-cage/install.sh | sudo FIELD_CAGE_INSTALL_DIR=${INSTALL_DIR} sh"
    exit 1
  }
fi
if [ -w "$INSTALL_DIR" ]; then
  mv "${WORK}/${BINARY}" "${INSTALL_DIR}/field-cage"
else
  echo "Error: ${INSTALL_DIR} is not writable"
  echo "Choose a writable directory or run with sudo:"
  echo "  curl -sSL https://takihito.github.io/field-cage/install.sh | sudo FIELD_CAGE_INSTALL_DIR=${INSTALL_DIR} sh"
  exit 1
fi
echo "Installed to ${INSTALL_DIR}/field-cage"

# Check if INSTALL_DIR is in PATH
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "Note: ${INSTALL_DIR} is not in your PATH."
    echo "Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    echo ""
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac

echo ""
echo "field-cage ${VERSION} installed successfully!"
echo "Run 'field-cage --version' to verify."
echo "Note: running the agent requires root (sudo) for eBPF. See:"
echo "  https://takihito.github.io/field-cage/usage"
