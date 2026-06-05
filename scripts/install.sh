#!/usr/bin/env sh
set -e

REPO="Anipaleja/nginx-defender"
BIN_NAME="nginx-defender"
VERSION="${NGINX_DEFENDER_VERSION:-latest}"
INSTALL_DIR="${NGINX_DEFENDER_INSTALL_DIR:-/usr/local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  aarch64|arm64)
    ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
 esac

case "$OS" in
  linux|darwin|freebsd)
    ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
 esac

ASSET="nginx-defender_${OS}_${ARCH}.tar.gz"
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
else
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

DOWNLOAD_OK=0
if command -v curl >/dev/null 2>&1; then
  if curl -fsSL "$URL" -o "$tmpdir/$ASSET"; then
    DOWNLOAD_OK=1
  fi
elif command -v wget >/dev/null 2>&1; then
  if wget -qO "$tmpdir/$ASSET" "$URL"; then
    DOWNLOAD_OK=1
  fi
fi

if [ "$DOWNLOAD_OK" -ne 1 ]; then
  echo "Release asset download failed."
  if command -v go >/dev/null 2>&1; then
    echo "Falling back to go install..."
    if [ "$VERSION" = "latest" ]; then
      GO_VERSION="latest"
    else
      GO_VERSION="$VERSION"
    fi
    go install "github.com/${REPO}/cmd/nginx-defender@${GO_VERSION}"
    GOBIN=$(go env GOBIN)
    if [ -n "$GOBIN" ]; then
      echo "Installed to $GOBIN/$BIN_NAME"
    else
      GOPATH=$(go env GOPATH | cut -d: -f1)
      echo "Installed to $GOPATH/bin/$BIN_NAME"
    fi
    exit 0
  fi
  echo "Go not found. Install Go or use Docker." >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  echo "tar is required to unpack the release." >&2
  exit 1
fi

tar -xzf "$tmpdir/$ASSET" -C "$tmpdir"

BIN_PATH="$tmpdir/$BIN_NAME"
if [ ! -f "$BIN_PATH" ]; then
  BIN_PATH=$(find "$tmpdir" -type f -name "$BIN_NAME" | head -n 1)
fi

if [ ! -f "$BIN_PATH" ]; then
  echo "Binary not found in release archive." >&2
  exit 1
fi

DEST_DIR="$INSTALL_DIR"
if [ ! -d "$DEST_DIR" ] || [ ! -w "$DEST_DIR" ]; then
  DEST_DIR="$HOME/.local/bin"
  mkdir -p "$DEST_DIR"
  echo "Install dir not writable. Using $DEST_DIR"
fi

if command -v install >/dev/null 2>&1; then
  install -m 0755 "$BIN_PATH" "$DEST_DIR/$BIN_NAME"
else
  cp "$BIN_PATH" "$DEST_DIR/$BIN_NAME"
  chmod 0755 "$DEST_DIR/$BIN_NAME"
fi

echo "nginx-defender installed to $DEST_DIR/$BIN_NAME"
if ! echo ":$PATH:" | grep -q ":$DEST_DIR:"; then
  echo "Add $DEST_DIR to your PATH if needed."
fi
