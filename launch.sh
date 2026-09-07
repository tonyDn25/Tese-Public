#!/usr/bin/env bash
# launch.sh: Bring up the GPS demo stack from this folder.
#
#   1. Builds + starts the GPS signing server (Docker, 172.18.0.50)
#   2. Ensures the gps-host native binary is installed
#   3. Prints the steps to load the extension and run a proof
#
# This folder is self-contained: paths are derived from the script location,
# not hardcoded to ~/tese.

set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo " GPS, starting up (from $REPO_DIR)"
echo "-------------------------------------------"

# 1. Server
echo " Starting GPS signing server (Docker)…"
# Clear any leftover state first: a fixed container_name + the 172.18.0.0/16 subnet
# (in Docker's auto-assign pool) can collide with a previous run or another project.
( cd "$REPO_DIR" && docker compose down --remove-orphans >/dev/null 2>&1 )
docker rm -f gps-server >/dev/null 2>&1 || true
if ! ( cd "$REPO_DIR" && docker compose up -d --build --remove-orphans gps-server ); then
  echo "FAIL docker compose up failed. If it is a network 'Pool overlaps' error, run:"
  echo "     docker network ls   # find the stale *_gps-network on 172.18.0.0/16"
  echo "     docker network rm <that-network> && ./launch.sh"
  exit 1
fi
sleep 3
if curl -skI https://172.18.0.50/account 2>/dev/null | grep -qi 'x-gps-signed: true'; then
  echo "OK Server signing at https://172.18.0.50"
else
  echo "FAIL Server not signing, check: docker compose logs gps-server"
  exit 1
fi

# 2. Native host: use the installed one, else the prebuilt binary shipped here.
GPS_HOST="$HOME/.local/bin/gps-host"
[ -f "$GPS_HOST" ] || GPS_HOST="$REPO_DIR/bin/gps-host"
if [ ! -f "$GPS_HOST" ]; then
  echo " gps-host not found, running extension/install.sh…"
  "$REPO_DIR/extension/install.sh"
  GPS_HOST="$HOME/.local/bin/gps-host"
fi
echo "OK gps-host: $GPS_HOST"

# Make the key registry discoverable to the host (for proving).
export GPS_KEY_REGISTRY="$REPO_DIR/nginx/keys/gps-keys.json"

# 2b. Native-messaging wrapper + manifest so Firefox can reach gps-host.
#     Firefox launches the manifest path with NO subcommand, but gps-host needs
#     `native-msg`; the wrapper supplies it (and logs to /tmp/gps-host.log).
WRAPPER="$HOME/.local/bin/gps-host-wrapper.sh"
cat > "$WRAPPER" <<EOF
#!/bin/bash
echo "[\$(date)] wrapper invoked, PID=\$\$" >> /tmp/gps-host.log
export GPS_KEY_REGISTRY="\${GPS_KEY_REGISTRY:-$REPO_DIR/nginx/keys/gps-keys.json}"
# Firefox hands the wrapper a bare environment. Without GPS_SEGMENT_PO2 the prover
# runs UNSEGMENTED at RISC Zero's default, which needs far more memory than the
# segmented run every measurement in the dissertation uses: on a 16 GB machine also
# running a desktop and the browser, the host reaches ~7.5 GB resident and the kernel
# OOM-kills it mid-proof. The port then drops with no error text anywhere, which looks
# like a messaging fault and is not one. extension/install.sh has always set this;
# launch.sh overwrote that wrapper with one that did not. Keep the two in step.
export GPS_SEGMENT_PO2="\${GPS_SEGMENT_PO2:-19}"
exec "$GPS_HOST" native-msg 2>>/tmp/gps-host.log
EOF
chmod +x "$WRAPPER"
NM_DIR="$HOME/.mozilla/native-messaging-hosts"; mkdir -p "$NM_DIR"
cat > "$NM_DIR/pt.ist.gps_host.json" <<EOF
{
  "name": "pt.ist.gps_host",
  "description": "GPS native host (General Privacy-preserving web proof System)",
  "path": "$WRAPPER",
  "type": "stdio",
  "allowed_extensions": ["gps@ist.pt"]
}
EOF
echo "OK native-messaging host → $WRAPPER"

# 3. Real verifier service (so verifier.html performs genuine STARK verification)
if ! curl -s http://127.0.0.1:8788/ >/dev/null 2>&1; then
  echo " Starting real verifier service on http://127.0.0.1:8788 …"
  nohup "$GPS_HOST" verify-serve > /tmp/gps-verify-serve.log 2>&1 &
  sleep 1
fi
echo "OK verifier service: http://127.0.0.1:8788  (open $REPO_DIR/verifier.html)"

# 4. Optionally launch Firefox with a prepared GPS profile (sideloaded extension +
#    imported CA). Off by default: set GPS_FF_PROFILE=/path/to/profile to use it;
#    otherwise follow the manual extension-load steps printed below (§9 of GUIDE.md).
#    GPS_NO_FIREFOX=1 also skips it.
FF_PROFILE="${GPS_FF_PROFILE:-}"
# Pick the REAL Firefox binary, not a sandbox wrapper. Native messaging (the
# host connection) breaks under firejail/snap/flatpak because the sandbox cannot
# spawn ~/.local/bin/gps-host-wrapper.sh. Prefer the unwrapped ELF; allow override
# with GPS_FF_BIN. If `firefox` resolves to firejail, the real binary is usually
# /usr/lib/firefox/firefox.
FF_BIN="${GPS_FF_BIN:-}"
if [ -z "$FF_BIN" ]; then
  for c in /usr/lib/firefox/firefox /usr/lib/firefox/firefox-bin "$(command -v firefox || true)"; do
    [ -x "$c" ] || continue
    case "$(readlink -f "$c")" in */firejail|*/snap*|*/flatpak*) continue;; esac
    FF_BIN="$c"; break
  done
fi
# Use a dedicated, auto-configured profile by default (override with GPS_FF_PROFILE).
FF_PROFILE="${FF_PROFILE:-$REPO_DIR/.gps-ff-profile}"
if [ -n "${GPS_NO_FIREFOX:-}" ]; then
  echo "Note: GPS_NO_FIREFOX set, not launching Firefox."
elif [ -z "$FF_BIN" ]; then
  echo "[!]  No unsandboxed Firefox found (snap/flatpak/firejail break native messaging)."
  echo "    Install a plain Firefox or set GPS_FF_BIN=/path/to/real/firefox, then re-run."
  echo "    (The headless evaluation needs no browser: ./reproduce.sh build / verify / proofs.)"
else
  # Configure the profile so the unsigned extension auto-loads AND stays enabled
  # (autoDisableScopes=0), with the native-messaging host already installed above.
  mkdir -p "$FF_PROFILE/extensions"
  cat > "$FF_PROFILE/user.js" <<UJS
user_pref("xpinstall.signatures.required", false);
user_pref("extensions.signatures.required", false);
user_pref("extensions.autoDisableScopes", 0);
user_pref("extensions.startupScanScopes", 15);
user_pref("security.enterprise_roots.enabled", true);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.aboutConfig.showWarning", false);
UJS
  echo "$REPO_DIR/extension" > "$FF_PROFILE/extensions/gps@ist.pt"
  rm -f /tmp/gps-host.log
  echo " Launching Firefox ($FF_BIN, profile $FF_PROFILE)…"
  MOZ_WEBRENDER=0 LIBGL_ALWAYS_SOFTWARE=1 \
    "$FF_BIN" --no-remote --profile "$FF_PROFILE" https://172.18.0.50/login \
    >/dev/null 2>&1 &
  echo "   1. First visit: ACCEPT the demo TLS cert (Advanced → Accept the Risk) on https://172.18.0.50."
  echo "   2. The GPS popup dot turns green within ~30 s once the host connects."
  echo "      Watch it: tail -f /tmp/gps-host.log   (look for 'wrapper invoked')."
  echo "   3. If it stays grey: the extension may be disabled, open about:addons, enable"
  echo "      'GPS', and reload; or load it live via about:debugging → Load Temporary Add-on →"
  echo "      $REPO_DIR/extension/manifest.json"
fi

cat <<EOF

-------------------------------------------
  Verify a proof for real (no browser):
    gps-host verify --proof $REPO_DIR/proofs/proof_1field.json
  …or open $REPO_DIR/verifier.html and drop a proof in (uses the service above).

  In Firefox: visit https://172.18.0.50/login, then /account; click a value in the
  GPS popup, set a predicate, Generate ZK Proof.

  Key distribution: the guest pins the GPS ROOT key and trusts any origin leaf key
  the root signed into nginx/keys/gps-keys.json (served at /.well-known/gps-keys).
-------------------------------------------
EOF
