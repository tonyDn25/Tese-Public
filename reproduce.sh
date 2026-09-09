#!/usr/bin/env bash
# ============================================================================
#  GPS: full reproduction & verification harness
# ============================================================================
#  One script an evaluator can run on a fresh machine to reproduce EVERY claim
#  in the paper: the guest image identifier, the proofs and their metrics, the
#  verification times, the adversarial soundness suite, the per-operation cycle
#  costs (Table 6.4), the n=10 timing campaign (Table 6.3), and the browser/
#  extension flow (Firefox, with instructions).
#
#  System under test: this folder  (canonical guest image_id 50e385ca…)
#
#  USAGE
#    ./reproduce.sh <command>
#
#  COMMANDS (fast → slow)
#    env        Print tool versions and check prerequisites.
#    build      Build the zkVM host+guest; print the guest image_id and
#               compare it to the expected 50e385ca… (proves source==artifacts).
#    verify     Verify the four shipped proofs (gps-host + risc0-verifier) and
#               time the verification (Table 6.7: 20-170 ms).
#    soundness  Run the 13-case adversarial suite (categories A–I) against the
#               real guest (Table 6.2).
#    cycles     Measure the per-operation cycle costs (Table 6.4) by user-cycle
#               differencing. Builds ~3 guest variants (~10 min). Edits source
#               temporarily and ALWAYS restores it (trap on exit).
#    proofs     Regenerate all four REAL proofs (dev_mode=false) and print each
#               one's time / seal / cycles. ~15–20 min on a 16 GB CPU machine.
#    timing     Full n=10 / n=3 CPU-pinned timing campaign (Table 6.3). ~1-2 h.
#    firefox    Bring up the demo server + native host and print the exact
#               steps to capture a page and prove it from the extension popup.
#    quick      env + build + verify + soundness          (no real proving; ~12 min)
#    all        quick + cycles + proofs                    (the full headless set)
#
#  EXPECTED RESULTS are printed by `./reproduce.sh expected`.
# ============================================================================
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

# -- expected reference values (this machine, 2026-06) ----------------------
EXP_IMAGE_ID="50e385cac9acdd6b9cc3e6c21a19daf33d6d817cad32d5fe7fe17d2728eddcd0"
TR="$REPO/sessions"
export GPS_KEY_REGISTRY="$REPO/nginx/keys/gps-keys.json"
# the dissertation's segment cap; matches Table 6.3 seals and caps proving memory
export GPS_SEGMENT_PO2=19
SESS1="$TR/session_direct_172_18_0_50_4502b208.json"
SESSP="$TR/session_pdf_e0c3c3c9.json"
SESSM="$TR/session_multipage_82a6a7bf.json"
# The numeric convention is part of the pattern, and therefore part of the rule
# the guest commits (2026-09-09). The demo pages write plain decimals.
BAL='regex:Account Balance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)|||balance'
HOLD='regex:Account Holder.{0,300}?(Alice Smith)|||holder'
NIF='regex:Contribuinte sob o n .{0,20}?(500 960 046)|||nif'
MB1='regex:id="balance">.{0,20}?([+-]?[0-9]+(\.[0-9]+)?)|||balance'
MW2='regex:Caixadirecta, .{0,50}?(António Silva)|||welcome_name'

# prefer the freshly built host; fall back to the shipped one, then installed
host_bin() {
  for b in "$REPO/zkvm/target/release/host" "$REPO/bin/gps-host" "$HOME/.local/bin/gps-host"; do
    [ -x "$b" ] && { echo "$b"; return; }
  done
  echo "$REPO/bin/gps-host"
}

# -- pretty printing --------------------------------------------------------
if [ -t 1 ]; then C0=$'\e[0m'; CB=$'\e[1m'; CG=$'\e[32m'; CR=$'\e[31m'; CY=$'\e[33m'; CC=$'\e[36m'
else C0=; CB=; CG=; CR=; CY=; CC=; fi
hr(){ printf '%s\n' "------------------------------------------------------------"; }
hdr(){ echo; hr; echo "${CB}${CC}$*${C0}"; hr; }
ok(){ echo "${CG}OK $*${C0}"; }
bad(){ echo "${CR}FAIL $*${C0}"; }
note(){ echo "${CY}- $*${C0}"; }

# -- prerequisites ----------------------------------------------------------
need(){ command -v "$1" >/dev/null 2>&1; }
cmd_env(){
  hdr "Environment / prerequisites"
  for t in cargo rustc python3 jq curl; do
    if need "$t"; then ok "$t  $($t --version 2>/dev/null | head -1)"; else bad "$t MISSING"; fi
  done
  for t in docker firefox taskset; do
    if need "$t"; then ok "$t  $($t --version 2>/dev/null | head -1)"; else note "$t not found (only needed for: docker=reproducible build + server, firefox=extension, taskset=pinned timing)"; fi
  done
  if need docker; then
    if docker buildx version >/dev/null 2>&1; then ok "docker buildx  $(docker buildx version 2>/dev/null | head -1)"
    else note "docker buildx MISSING, needed for the reproducible guest build (image_id == $EXP_IMAGE_ID). Install buildx, or set RISC0_SKIP_DOCKER=1 for a fast local build with an environment-specific id."; fi
  fi
  note "RISC Zero is pulled by cargo on first build (rzup not required for CPU proving)."
  echo; note "Repo: $REPO"; note "Key registry: $GPS_KEY_REGISTRY"
}

# -- build + image id -------------------------------------------------------
cmd_build(){
  hdr "Build zkVM (host + guest) and check the image identifier"
  ( cd "$REPO/zkvm" && cargo build --release -p host ) || { bad "build failed"; return 1; }
  ok "built $REPO/zkvm/target/release/host"
  note "Deriving guest image_id from a dev proof (fast; image_id is independent of dev/real)…"
  local out img
  RISC0_DEV_MODE=1 "$REPO/zkvm/target/release/host" prove \
        --session "$SESS1" --url /account --field "$BAL" --predicate '> 1000' \
        --output /tmp/gps_idcheck.json >/dev/null 2>&1
  img="$(jq -r .image_id /tmp/gps_idcheck.json 2>/dev/null)"
  echo "  built image_id : $img"
  echo "  expected       : $EXP_IMAGE_ID"
  if [ "$img" = "$EXP_IMAGE_ID" ]; then
    ok "image_id matches - the source in this tree reproduces the artifacts and the dissertation (Appendix A)."
  else
    bad "image_id MISMATCH, source differs from the shipped artifacts."
  fi
}

# -- verify the four shipped proofs + time it -------------------------------
cmd_verify(){
  hdr "Verify the four shipped proofs (Table 6.7: verification 20-170 ms)"
  local BIN; BIN="$(host_bin)"
  note "Using $BIN"
  for f in proof_1field proof_2field proof_pdf_nif proof_multipage; do
    local p="$REPO/proofs/$f.json"
    [ -f "$p" ] || { bad "missing $p"; continue; }
    local dev img; dev="$(jq -r .metadata.dev_mode "$p")"; img="$(jq -r .image_id "$p" | cut -c1-8)"
    local t0 t1 ms res
    t0=$(date +%s%N)
    res="$("$BIN" verify --proof "$p" 2>&1 | grep -oiE "VALID|INVALID|FAILED" | head -1)"
    t1=$(date +%s%N); ms=$(( (t1-t0)/1000000 ))
    if [ "$res" = "VALID" ]; then
      ok "$f  → $res  (${ms} ms incl. process start; img ${img}…, dev_mode=$dev)"
    else
      bad "$f  → ${res:-NO RESULT}"
    fi
  done
  echo; note "risc0-verifier (standalone crate, real STARK):"
  ( cd "$REPO/zkvm" && cargo run --release -q -p risc0-verifier -- "$REPO/proofs/proof_1field.json" 2>/dev/null \
      | grep -iE "valid|verif" | head -2 ) || note "(risc0-verifier crate optional)"
}

# -- adversarial soundness suite (Table 6.2) --------------------------------
cmd_soundness(){
  hdr "Adversarial soundness suite - 13 cases across the 9 attack classes (A-I) against the real guest (Table 6.2)"
  if [ -f "$REPO/tests/adversarial/run_suite.sh" ]; then
    bash "$REPO/tests/adversarial/run_suite.sh"
  else
    bad "tests/adversarial/run_suite.sh not found"
  fi
}

# -- per-operation cycle costs (Table 6.4) by user-cycle differencing -------
cmd_cycles(){
  hdr "Per-operation cycle costs (Table 6.4) - user-cycle differencing in execution mode"
  note "This temporarily instruments the host + guest, builds ~3 variants, measures, and RESTORES."
  local GH="$REPO/zkvm/methods/guest/src/main.rs"
  local HH="$REPO/zkvm/host/src/main.rs"
  local BK; BK="$(mktemp -d)"
  cp "$GH" "$BK/guest.rs"; cp "$HH" "$BK/host.rs"
  restore(){ cp "$BK/guest.rs" "$GH"; cp "$BK/host.rs" "$HH"; echo; note "source restored from backup ($BK)"; }
  trap restore EXIT

  # 1. instrument host to print raw user_cycles
  python3 - "$HH" <<'PY' || { bad "host patch failed"; return 1; }
import sys; f=sys.argv[1]; s=open(f).read()
a='    eprintln!("  zkVM total cycles: {}", total_cycles);'
assert a in s, "host anchor missing"
ins=a+'\n    eprintln!("  MEASURE user_cycles={}", prove_info.stats.user_cycles);'
open(f,'w').write(s.replace(a,ins,1)); print("  host: user_cycles print added")
PY

  build(){ ( cd "$REPO/zkvm" && cargo build --release -p host >/dev/null 2>&1 ); }
  uc(){ RISC0_DEV_MODE=1 "$REPO/zkvm/target/release/host" prove --session "$SESS1" --url /account \
        --field "$BAL" --predicate '> 1000' --output /tmp/uc.json 2>&1 \
        | grep -oE "user_cycles=[0-9]+" | head -1 | cut -d= -f2; }

  note "building baseline (instrumented host, clean guest)…"; build || { bad build; return 1; }
  local BASE; BASE="$(uc)"; echo "  baseline 1-field user_cycles = ${BASE}"

  # 2. guest variant: skip both ECDSA verifies (leaf + root)  → ECDSA cost
  python3 - "$GH" <<'PY' || { bad "ecdsa patch failed"; return 1; }
import sys; f=sys.argv[1]; s=open(f).read()
ro='''            verify_ecdsa_p256(GPS_ROOT_PUBLIC_KEY_PEM, &signed.entry.canonical_bytes(), &root_sig)
                .unwrap_or_else(|e| panic!(
                    "Field '{}': registry entry for '{}' is NOT signed by the GPS root: {}",
                    field_req.field_label, page_keyid, e));'''
le='''            verify_ecdsa_p256(leaf_pem, signature_base.as_bytes(), &sig_bytes)
                .unwrap_or_else(|e| panic!("Field '{}': signature verification failed: {}",
                    field_req.field_label, e));'''
assert ro in s and le in s, "ecdsa anchors missing"
s=s.replace(ro,'            let _=(&signed.entry,&root_sig); // [MEASURE] root verify skipped')
s=s.replace(le,'            let _=(leaf_pem,signature_base.as_bytes(),&sig_bytes); // [MEASURE] leaf verify skipped')
open(f,'w').write(s); print("  guest: both ECDSA verifies skipped")
PY
  note "building no-ECDSA variant…"; build || { bad build; return 1; }
  local NOEC; NOEC="$(uc)"; echo "  no-ECDSA 1-field user_cycles = ${NOEC}"
  cp "$BK/guest.rs" "$GH"   # restore guest for next variant

  # 3. guest variant: software SHA for the content digest  → SHA hw-vs-sw
  python3 - "$GH" <<'PY' || { bad "sha patch failed"; return 1; }
import sys; f=sys.argv[1]; s=open(f).read()
old='''fn sha256(data: &[u8]) -> [u8; 32] {
    // Use RISC Zero's hardware-accelerated SHA-256 syscall for the body digest.
    use risc0_zkvm::sha::{Impl, Sha256};
    Impl::hash_bytes(data).as_bytes().try_into().unwrap()
}'''
new='''fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256}; Sha256::digest(data).into() // [MEASURE] software sha2
}'''
assert old in s, "sha anchor missing"
open(f,'w').write(s.replace(old,new)); print("  guest: sha256 -> software sha2")
PY
  note "building software-SHA variant…"; build || { bad build; return 1; }
  local SWSHA; SWSHA="$(uc)"; echo "  sw-SHA  1-field user_cycles = ${SWSHA}"
  cp "$BK/guest.rs" "$GH"

  # 4. 2-field same page (ECDSA deduped) → per-added-field cost
  note "building clean guest for the 2-field delta…"; build || true
  local TWO; TWO="$(RISC0_DEV_MODE=1 "$REPO/zkvm/target/release/host" prove --session "$SESS1" --url /account \
        --field "$BAL" --predicate '> 1000' --field "$HOLD" --predicate '== "Alice Smith"' \
        --output /tmp/uc2.json 2>&1 | grep -oE "user_cycles=[0-9]+" | head -1 | cut -d= -f2)"

  hdr "Measured per-operation costs (Table 6.4)"
  local ecdsa2=$((BASE-NOEC)); local per_ecdsa=$((ecdsa2/2)); local shadiff=$((SWSHA-BASE)); local addfield=$((TWO-BASE))
  printf "  %-46s %s\n" "Full 1-field execution (raw user_cycles):"      "$BASE"
  printf "  %-46s %s  (~%s per verify)\n" "ECDSA verify, leaf+root per page:"  "$ecdsa2" "$per_ecdsa"
  printf "  %-46s %s%%\n" "  → as share of the proof:"                   "$(( ecdsa2*100/BASE ))"
  printf "  %-46s %s\n" "SHA-256 syscall vs sha2 crate (Δ on body):"     "$shadiff"
  printf "  %-46s %s\n" "Added same-page field (extract+pred+bind+jrnl):" "$addfield"
  echo
  note "Dissertation Table 6.4 reference: ECDSA ~244K/verify, leaf+root ~488K (72%), SHA delta <1K, added field ~106K, total ~675K."
  trap - EXIT; restore
}

# -- regenerate the four real proofs + metrics ------------------------------
cmd_proofs(){
  hdr "Regenerate the four REAL proofs (dev_mode=false) + metrics (Tables VI/VII)"
  note "This runs real STARK proving on CPU. Budget ~15–20 min on a 16 GB machine."
  ( cd "$REPO/zkvm" && cargo build --release -p host >/dev/null 2>&1 )
  local BIN="$REPO/zkvm/target/release/host"
  gen(){ # <name> <outfile> -- <args...>
    local name="$1"; local out="$2"; shift 3
    local log; log="$(unset RISC0_DEV_MODE; "$BIN" prove "$@" --output "$out" 2>&1)"
    local cyc; cyc="$(echo "$log" | grep -oE "zkVM total cycles: [0-9]+" | grep -oE "[0-9]+")"
    local t sz dev img
    t="$(jq -r .metadata.proof_time_seconds "$out")"; sz="$(jq -r .metadata.proof_size_bytes "$out")"
    dev="$(jq -r .metadata.dev_mode "$out")"; img="$(jq -r .image_id "$out" | cut -c1-8)"
    printf "  %-11s time=%6.1fs  seal=%8d B  cycles(padded)=%-9s dev=%s img=%s…\n" \
      "$name" "$t" "$sz" "${cyc:-?}" "$dev" "$img"
  }
  echo "  (dissertation Table 6.3 means: 1f 133s/525KB · 2f 141s/526KB · pdf 214s/788KB · xpage 611s/2.29MB)"
  gen 1field    /tmp/repro_1field.json    -- --session "$SESS1" --url /account --field "$BAL" --predicate '> 1000'
  gen 2field    /tmp/repro_2field.json    -- --session "$SESS1" --url /account --field "$BAL" --predicate '> 1000' --field "$HOLD" --predicate '== "Alice Smith"'
  gen pdf       /tmp/repro_pdf.json       -- --session "$SESSP" --url /comprovativo.pdf --field "$NIF" --predicate '== 500 960 046'
  gen crosspage /tmp/repro_xpage.json     -- --session "$SESSM" --field "$MB1" --predicate '> 1000' --field-session "$SESSM" --field-url /account --field "$MW2" --predicate '== António Silva' --field-session "$SESSM" --field-url /mypage
  ok "regenerated proofs in /tmp/repro_*.json, verify with: $BIN verify --proof /tmp/repro_1field.json"
}

# -- full timing campaign (Table 6.3, n=10) ---------------------------------
cmd_timing(){
  hdr "Full CPU-pinned timing campaign (Table 6.3: n=10 / n=3). ~1-2 hours."
  # Gate on existence, not the executable bit: the bit does not always survive
  # a clone or an archive extract, and the script is invoked through bash anyway.
  if [ -f "$REPO/benchmarks/run_measurements.sh" ]; then
    bash "$REPO/benchmarks/run_measurements.sh"
  else bad "benchmarks/run_measurements.sh not found"; fi
}


# -- Firefox / extension flow (manual, with instructions) -------------------
cmd_firefox(){
  hdr "Browser / extension proof flow (Firefox), interactive"
  note "The popup flow needs a GUI Firefox; this command brings up the backend and prints the steps."
  echo
  echo "${CB}1. Start the signing server + native host${C0}"
  echo "     bash $REPO/launch.sh        # docker server at 172.18.0.50 + installs gps-host"
  echo "     bash $REPO/extension/install.sh   # native-messaging host + wrapper (GPS_SEGMENT_PO2=19)"
  echo
  echo "${CB}2. Trust the demo server's TLS certificate${C0} (one-time, on first visit to"
  echo "     https://172.18.0.50 accept the mkcert-issued cert; the gps-ff2 profile already trusts it)"
  echo
  echo "${CB}3. Load the extension${C0}  (about:debugging → This Firefox → Load Temporary Add-on)"
  echo "     $REPO/extension/manifest.json"
  echo
  echo "${CB}4. Capture + prove from the popup${C0}"
  echo "     - Open  https://172.18.0.50/login → log in (any credentials) → open /account"
  echo "     - Click the GPS toolbar icon; the green dot = native host connected"
  echo "     - Click 'select field', click the balance on the page, type predicate  > 1000 , Enter"
  echo "     - Click 'Generate ZK Proof' (~2 min, real STARK), then 'Download Proof'"
  echo
  echo "${CB}5. Verify the downloaded proof${C0}"
  echo "     GPS_KEY_REGISTRY=$GPS_KEY_REGISTRY $REPO/bin/gps-host verify --proof <downloaded>.json"
  echo "     # or open  $REPO/verifier.html  (drag-drop) while  gps-host verify-serve  runs"
  echo
  echo "${CB}Check the host is alive:${C0}  cat /tmp/gps-host.log   (look for 'wrapper invoked')"
  echo
  note "A browser-captured proof carries the same image_id (50e385ca…), binding (in-circuit),"
  note "field_selected (anchored:\"Account Balance\"->number(w=300)) and dev_mode=false as the CLI proofs."
  echo
  read -rp "Bring up the server + install the host now? [y/N] " a
  if [[ "${a:-N}" =~ ^[Yy]$ ]]; then
    need docker && bash "$REPO/launch.sh" || note "docker not available, start it and re-run launch.sh"
    bash "$REPO/extension/install.sh" 2>/dev/null || note "install.sh needs the built binary (run ./reproduce.sh build first)"
  fi
}

cmd_expected(){
  hdr "Expected results (this machine, v12 guest, 2026-09; CPU, 16 GB)"
  cat <<EOF
  image_id            : ${EXP_IMAGE_ID}
  Proving (Table 6.3) : 1-field 133 s · 2-field 141 s   (n=10 pinned means; ~125/131 s per shipped proof)
                        PDF 214 s · cross-page 611 s     (n=3 means; ~207/585 s per shipped proof)
                        seals: 525 / 526 / 788 KB / 2.29 MB ; peak ~6.9 GB
                        1-/2-field/PDF at tier 2^20/2^20/2^21; cross-page 4,456,448 cycles, past 2^22
                        (all four shipped proofs regenerated at PO2=19 under this guest on 2026-09-05;
                         the old PO2=18 multipage caveat no longer applies)
  Verify (Table 6.7)  : 20-170 ms
  Per-op (Table 6.4)  : ECDSA ~244K/verify · leaf+root ~488K (72% of ~675K proof)
                        SHA syscall vs sha2 delta <1K cyc · added field ~106K · regex 8.4M
                        salted body commitment: +10,767 cyc (1.60%) on the 4.3 KB body,
                        but +6.25% on the 104 KB cross-page body - it hashes the WHOLE body
  Soundness (Tab. 6.2): 13 cases across the 9 attack classes (A-I); forgeries/tampering abort, B/C bind first match, D aborts on predicate
  Cycle counts        : 1-/2-field padded 1,048,576 (2^20) ; raw user ~685,658 (1-field, salted)
EOF
}

cmd_quick(){ cmd_env; cmd_build; cmd_verify; cmd_soundness; hdr "quick done"; }
cmd_all(){ cmd_quick; cmd_cycles; cmd_proofs; hdr "ALL headless checks done, see ./reproduce.sh firefox for the browser flow"; }

case "${1:-}" in
  env) cmd_env;; build) cmd_build;; verify) cmd_verify;; soundness) cmd_soundness;;
  cycles) cmd_cycles;; proofs) cmd_proofs;; timing) cmd_timing;;
  firefox) cmd_firefox;; expected) cmd_expected;; quick) cmd_quick;; all) cmd_all;;
  *) sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; echo; cmd_expected;;
esac
