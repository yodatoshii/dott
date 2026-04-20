#!/bin/sh
set -eu

REPO="yodatoshicom/dott"
BIN="dott"

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64)  TARGET="aarch64-apple-darwin" ;;
      x86_64) TARGET="x86_64-apple-darwin" ;;
      *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      x86_64)        TARGET="x86_64-unknown-linux-gnu" ;;
      aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
      *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac
    ;;
  *) echo "Unsupported OS: $OS" && exit 1 ;;
esac

# prefer /opt/homebrew/bin on Apple Silicon; /usr/local/bin otherwise
if [ -d /opt/homebrew/bin ]; then
  INSTALL_DIR=/opt/homebrew/bin
else
  INSTALL_DIR=/usr/local/bin
fi

VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' | head -n1 | sed 's/.*"v\([^"]*\)".*/\1/')

if [ -z "$VERSION" ]; then
  echo "Could not determine latest version" && exit 1
fi

URL="https://github.com/$REPO/releases/download/v${VERSION}/${BIN}-${TARGET}.tar.gz"
SUM_URL="${URL}.sha256"

echo "Installing dott v${VERSION} (${TARGET})..."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# download tarball + sidecar to temp, then verify before extracting
curl -fsSL "$URL"     -o "$TMP/dott.tar.gz"
curl -fsSL "$SUM_URL" -o "$TMP/dott.tar.gz.sha256"

EXPECTED=$(awk '{print $1}' "$TMP/dott.tar.gz.sha256")
if command -v sha256sum > /dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMP/dott.tar.gz" | awk '{print $1}')
else
  ACTUAL=$(shasum -a 256 "$TMP/dott.tar.gz" | awk '{print $1}')
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "SHA256 mismatch — refusing to install."
  echo "  expected: $EXPECTED"
  echo "  actual:   $ACTUAL"
  exit 1
fi

tar xz -C "$TMP" -f "$TMP/dott.tar.gz"

if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP/$BIN" "$INSTALL_DIR/$BIN"
else
  sudo mv "$TMP/$BIN" "$INSTALL_DIR/$BIN"
fi

echo "Installed to $INSTALL_DIR/$BIN"
echo "Run: dott"
