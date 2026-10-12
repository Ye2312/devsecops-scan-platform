#!/bin/sh
# Install a pinned Trivy release after verifying its published SHA-256.
# Single source of truth for the Trivy version used by the worker image and by CI.
set -eu

TRIVY_VERSION="0.74.0"
DEST="${1:-/usr/local/bin}"

case "$(uname -m)" in
  x86_64 | amd64) asset="Linux-64bit" sha256="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a" ;;
  aarch64 | arm64) asset="Linux-ARM64" sha256="b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL --retry 3 -o "$tmp/trivy.tar.gz" \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${asset}.tar.gz"
echo "${sha256}  $tmp/trivy.tar.gz" | sha256sum -c -
tar -xzf "$tmp/trivy.tar.gz" -C "$tmp" trivy
install -m 0755 "$tmp/trivy" "$DEST/trivy"
