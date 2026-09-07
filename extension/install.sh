#!/usr/bin/env bash
# install.sh, Install the GPS native-messaging host for Firefox.
#
# Installs the `gps-host` binary into ~/.local/bin and registers the
# native-messaging manifest so the Firefox extension (id: gps@ist.pt) can
# spawn it. The extension itself is loaded in Firefox via about:debugging
# ("Load Temporary Add-on" -> extension/manifest.json).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../tese-final/extension
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"                     # .../tese-final

BINARY_DST="$HOME/.local/bin/gps-host"
# Prefer the prebuilt v11 binary shipped in the repo; else the build output.
BINARY_SRC="$REPO_DIR/bin/gps-host"
[ -f "$BINARY_SRC" ] || BINARY_SRC="$REPO_DIR/zkvm/target/release/host"

echo "------------------------------------------------"
echo "  GPS: Firefox native-host install"
echo "------------------------------------------------"

# 1. Binary (build if neither the shipped binary nor a build output exists).
if [ ! -f "$BINARY_SRC" ]; then
  echo "  → host binary not found, building (pulls RISC Zero, can take a while)…"
  ( cd "$REPO_DIR/zkvm" && cargo build --release -p host )
  BINARY_SRC="$REPO_DIR/zkvm/target/release/host"
fi
mkdir -p "$HOME/.local/bin"
cp "$BINARY_SRC" "$BINARY_DST"
chmod +x "$BINARY_DST"
echo "  OK Binary installed: $BINARY_DST"

# 2. Native-messaging launcher. The manifest path is run by Firefox WITHOUT a
#    subcommand (and with the manifest path + extension id as args), but gps-host
#    requires the `native-msg` subcommand. A raw-binary path therefore prints help
#    to stdout and exits, so the extension can never connect. This tiny wrapper
#    ignores the browser's args and execs the native-msg loop, and sets the key
#    registry and segment cap (browser-spawned processes do not inherit the shell
#    env, so without GPS_SEGMENT_PO2 the prover would use RISC Zero's default 2^20
#    cap and emit a smaller, single-segment seal than the dissertation's Table 6.3, which
#    pins the cap at 2^19 to bound peak RAM at ~6.9 GB).
LAUNCHER_DST="$HOME/.local/bin/gps-host-wrapper.sh"
cat > "$LAUNCHER_DST" <<EOF
#!/bin/bash
echo "[\$(date)] wrapper invoked, PID=\$\$" >> /tmp/gps-host.log
export GPS_KEY_REGISTRY="\${GPS_KEY_REGISTRY:-$REPO_DIR/nginx/keys/gps-keys.json}"
export GPS_SEGMENT_PO2="\${GPS_SEGMENT_PO2:-19}"
exec "$BINARY_DST" native-msg 2>>/tmp/gps-host.log
EOF
chmod +x "$LAUNCHER_DST"
echo "  OK Native-messaging launcher: $LAUNCHER_DST"

# 3. Native-messaging manifest (Firefox). Path points at the launcher, not the
#    raw binary.
NM_DIR="$HOME/.mozilla/native-messaging-hosts"
mkdir -p "$NM_DIR"
cat > "$NM_DIR/pt.ist.gps_host.json" <<EOF
{
  "name": "pt.ist.gps_host",
  "description": "GPS native host (General Privacy-preserving web proof System)",
  "path": "$LAUNCHER_DST",
  "type": "stdio",
  "allowed_extensions": ["gps@ist.pt"]
}
EOF
echo "  OK Native-messaging manifest: $NM_DIR/pt.ist.gps_host.json"

echo ""
echo "  Next:"
echo "    1. Trust the demo server's TLS cert (accept it on first visit to https://172.18.0.50)."
echo "    2. Load the extension: about:debugging → This Firefox →"
echo "       Load Temporary Add-on → $SCRIPT_DIR/manifest.json"
echo "    3. Start the stack: $REPO_DIR/launch.sh"
echo "------------------------------------------------"
