#!/usr/bin/env bash
# Adversarial soundness suite for the v11 GPS guest.
#
# Each case mutates a known-good session or key registry and runs the guest. A
# sound guest must ABORT (panic during execution) and produce NO proof. We run in
# RISC0_DEV_MODE=1: the guest still EXECUTES (so every assert/panic fires), only the
# STARK proving is skipped, so the whole suite runs in seconds rather than minutes.
#
# The baseline case is the control: unmodified inputs must SUCCEED.
# The forged-host-value case needs the attack-sim build (separate binary).
#
# Usage: tests/adversarial_soundness.sh [path-to-gps-host]
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$REPO/bin/gps-host}"
ROOT_PRIV="$REPO/nginx/keys/gps_root_private.pem"
LEAF_PUB="$REPO/nginx/keys/nginx_public.pem"
SESS="$REPO/sessions/session_direct_172_18_0_50_4502b208.json"
REG="$REPO/nginx/keys/gps-keys.json"
BAL='regex:Account Balance.{0,300}?([+-]?[0-9][0-9.,]*)|||balance'
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export RISC0_DEV_MODE=1
pass=0; fail=0

# Re-sign a registry entry with the GPS root (matches gps_core::canonical_bytes:
# "gps-key-registry-v1\nkeyid=..\ndomain=..\nnot_after=0\nleaf=<b64 DER body>", no trailing \n).
sign_entry() { # keyid domain leaf_pem_path -> base64 DER sig
  local b64; b64=$(grep -v '^-----' "$3" | tr -d '[:space:]')
  printf 'gps-key-registry-v1\nkeyid=%s\ndomain=%s\nnot_after=0\nleaf=%s' "$1" "$2" "$b64" > "$TMP/canon"
  openssl dgst -sha256 -sign "$ROOT_PRIV" -out "$TMP/sig.der" "$TMP/canon"
  base64 -w0 "$TMP/sig.der"
}
make_registry() { # keyid domain leaf_pem_path out_path
  local sig leaf; sig=$(sign_entry "$1" "$2" "$3"); leaf=$(cat "$3")
  jq -n --arg k "$1" --arg d "$2" --arg l "$leaf" --arg s "$sig" \
    '[{entry:{keyid:$k,domain:$d,leaf_pubkey_pem:$l,not_after:0},root_sig_b64:$s}]' > "$4"
}
expect_reject() { # name session registry
  local out; out=$(GPS_KEY_REGISTRY="$3" "$BIN" prove --session "$2" --url /account \
      --field "$BAL" --predicate '> 1000' --output "$TMP/p.json" 2>&1)
  if [ -f "$TMP/p.json" ]; then echo "  FAIL  $1, produced a proof (NOT rejected)"; fail=$((fail+1));
  else echo "  PASS  $1, $(echo "$out" | grep -ioE "panic.*|[A-Za-z' ]*violated[A-Za-z' ]*|not signed by the GPS root|not found|mismatch|tampered|unsupported signature base" | head -1)"; pass=$((pass+1)); fi
  rm -f "$TMP/p.json"
}
expect_success() { # name session registry
  GPS_KEY_REGISTRY="$3" "$BIN" prove --session "$2" --url /account \
      --field "$BAL" --predicate '> 1000' --output "$TMP/p.json" >/dev/null 2>&1
  if [ -f "$TMP/p.json" ]; then echo "  PASS  $1, proof produced (control)"; pass=$((pass+1));
  else echo "  FAIL  $1, control did NOT produce a proof"; fail=$((fail+1)); fi
  rm -f "$TMP/p.json"
}

echo "=== GPS adversarial soundness suite (binary: $BIN) ==="

# A0 control: clean inputs must succeed
expect_success "A0 baseline (clean)" "$SESS" "$REG"

# A1 tampered body: change the signed /account body, leave content-digest -> digest mismatch
jq '(.pages[] | select(.request.path=="/account") | .response.body) += "TAMPER"' "$SESS" > "$TMP/s_tamper.json"
expect_reject "A1 tampered body (digest)" "$TMP/s_tamper.json" "$REG"

# A2 forged root signature: corrupt root_sig_b64 -> root verify fails
jq '.[0].root_sig_b64 = (.[0].root_sig_b64[0:40] + "AAAA" + .[0].root_sig_b64[44:])' "$REG" > "$TMP/r_forgedsig.json"
expect_reject "A2 forged root signature" "$SESS" "$TMP/r_forgedsig.json"

# A3 registry keyid mismatch: no entry for the page's keyid
make_registry "evil-key" "172.18.0.50" "$LEAF_PUB" "$TMP/r_keyid.json"
expect_reject "A3 registry keyid mismatch" "$SESS" "$TMP/r_keyid.json"

# A4 registry domain mismatch: root-signed entry, but domain != page authority
make_registry "gps-nginx" "evil.example.com" "$LEAF_PUB" "$TMP/r_domain.json"
expect_reject "A4 registry domain mismatch" "$SESS" "$TMP/r_domain.json"

# A5 root-vouched WRONG leaf key: root signature valid, but response sig doesn't verify under it
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/evil_priv.pem" 2>/dev/null
openssl ec -in "$TMP/evil_priv.pem" -pubout -out "$TMP/evil_pub.pem" 2>/dev/null
make_registry "gps-nginx" "172.18.0.50" "$TMP/evil_pub.pem" "$TMP/r_wrongleaf.json"
expect_reject "A5 root-vouched wrong leaf key" "$SESS" "$TMP/r_wrongleaf.json"

# A6 malformed signature base: strip @method -> guest rejects non-6-component base
jq '(.pages[] | select(.request.path=="/account") | .response.headers["signature-input"]) |= sub("\"@method\" "; "")' "$SESS" > "$TMP/s_nomethod.json"
expect_reject "A6 base missing @method (downgrade)" "$TMP/s_nomethod.json" "$REG"

echo "=== results: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
