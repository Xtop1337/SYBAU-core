#!/usr/bin/env bash
# Builds the reference cores (real Xray and sing-box) that SYBAU-CORE is
# tested against. Binaries land in tests/interop/.bin.
set -euo pipefail
cd "$(dirname "$0")"

XRAY_VERSION="${XRAY_VERSION:-v1.260327.0}"       # Xray-core v26.3.27
SINGBOX_VERSION="${SINGBOX_VERSION:-v1.14.4}"
DNSPROXY_VERSION="${DNSPROXY_VERSION:-v0.75.5}"   # AdGuard dnsproxy: DoQ / DoH3 server

bin="$PWD/.bin"
mkdir -p "$bin"
export GOBIN="$bin" GOTOOLCHAIN=auto GOFLAGS=-trimpath

if [ ! -x "$bin/xray" ] || [ "$(cat "$bin/xray.version" 2>/dev/null)" != "$XRAY_VERSION" ]; then
  echo "building xray $XRAY_VERSION"
  go install -ldflags "-s -w" "github.com/xtls/xray-core/main@$XRAY_VERSION"
  mv "$bin/main" "$bin/xray"
  echo "$XRAY_VERSION" > "$bin/xray.version"
fi

if [ ! -x "$bin/sing-box" ] || [ "$(cat "$bin/sing-box.version" 2>/dev/null)" != "$SINGBOX_VERSION" ]; then
  echo "building sing-box $SINGBOX_VERSION"
  go install -ldflags "-s -w" -tags "with_quic,with_utls,with_gvisor,with_wireguard,with_clash_api" \
    "github.com/sagernet/sing-box/cmd/sing-box@$SINGBOX_VERSION"
  echo "$SINGBOX_VERSION" > "$bin/sing-box.version"
fi

if [ ! -x "$bin/dnsproxy" ] || [ "$(cat "$bin/dnsproxy.version" 2>/dev/null)" != "$DNSPROXY_VERSION" ]; then
  echo "building dnsproxy $DNSPROXY_VERSION"
  go install -ldflags "-s -w" "github.com/AdguardTeam/dnsproxy@$DNSPROXY_VERSION"
  echo "$DNSPROXY_VERSION" > "$bin/dnsproxy.version"
fi

"$bin/xray" version | head -1
"$bin/sing-box" version | head -1
