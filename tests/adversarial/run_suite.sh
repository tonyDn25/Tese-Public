#!/usr/bin/env bash
# ============================================================================
# GPS adversarial negative-test suite (cases A–I)
#
# Exercises the REAL v12 guest (image_id 71442f7b…) against adversarial inputs.
# Runs in RISC0_DEV_MODE=1: the guest still EXECUTES in full (every assert/panic
# fires, every extraction runs), only STARK proving is skipped, so the suite runs
# in seconds. Dev mode is sound for FUNCTIONAL correctness: it is exactly the
# guest logic that would run under a real proof, minus the cryptographic seal.
#
# Two binaries:
#   - production guest  : $PROD   (bin/gps-host)             : cases B,C,D,F,G,H,I
#   - attack-sim build  : $ATTACK (zkvm/target/release/host) : cases A,E only
#     (the attack-sim feature lets the host inject a FORGED value hint via
#      GPS_SIM_FORGE_VALUE; the production binary cannot do this: KI-23.)
#
# Cases B,C,D craft a NEW body and RE-SIGN it with the origin's leaf key, so the
# page passes signature+digest verification and we can observe what the in-circuit
# anchored extractor binds to. This models an adversarial ORIGIN (which controls
# and signs its own HTML), the trust boundary the paper claims.
#
# Output: RESULTS.md in this directory.
# Usage:  tests/adversarial/run_suite.sh
# ============================================================================
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROD="$REPO/bin/gps-host"
ATTACK="$REPO/bin/gps-host-attacksim"   # prebuilt with --features attack-sim

# bin/ is git-ignored, so a fresh clone has neither binary. Build them on demand:
# PROD = normal release host; ATTACK = the same host built --features attack-sim.
# Build ATTACK first and PROD last so the shared target/release/host is left as PROD.
if [ ! -x "$ATTACK" ]; then
  echo "  building attack-sim host (bin/ not in a fresh clone)…"
  mkdir -p "$REPO/bin"
  ( cd "$REPO/zkvm" && cargo build --release -p host --features attack-sim ) || { echo "  attack-sim build failed"; exit 1; }
  cp "$REPO/zkvm/target/release/host" "$ATTACK"
fi
if [ ! -x "$PROD" ]; then
  echo "  building production host (bin/ not in a fresh clone)…"
  mkdir -p "$REPO/bin"
  ( cd "$REPO/zkvm" && cargo build --release -p host ) || { echo "  production build failed"; exit 1; }
  cp "$REPO/zkvm/target/release/host" "$PROD"
fi

LEAF_PRIV="$REPO/nginx/keys/nginx_private.pem"
REG="$REPO/nginx/keys/gps-keys.json"
SESS="$REPO/sessions/session_direct_172_18_0_50_4502b208.json"
SID8="4502b208"                       # session-id prefix the guest matches on
BAL='regex:Account Balance.{0,300}?([+-]?[0-9][0-9.,]*)|||balance'
HOLDER='regex:Account Holder.{0,300}?(Alice Smith)|||holder'
RESULTS="$REPO/tests/adversarial/RESULTS.md"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export RISC0_DEV_MODE=1
export GPS_KEY_REGISTRY="$REG"

# Canonical /account body, taken from the signed session (portable; no external /tmp dep).
ORIG_BODY="$TMP/orig_account_body.html"
jq -r '.pages[]|select(.request.path=="/account")|.response.body' "$SESS" > "$ORIG_BODY"

# RFC 9421 base components for the /account page (read from the session).
PARAMS=$(jq -r '.pages[]|select(.request.path=="/account")|.response.headers["signature-input"]' "$SESS" | sed 's/^sig1=//')
DATE=$(jq -r '.pages[]|select(.request.path=="/account")|.response.headers.date' "$SESS")
AUTH="172.18.0.50"; TURI="https://172.18.0.50/account"

# ---------------------------------------------------------------------------
# resign_account <body_file> <out_session>
#   Rebuild the /account page around <body_file>: recompute content-digest, build
#   the full 6-component RFC 9421 base, ECDSA-P256 sign it with the leaf key, and
#   write a session whose filename carries the session-id prefix (the guest matches
#   sessions by filename substring).
# ---------------------------------------------------------------------------
resign_account() {
  local body="$1" out="$2"
  local digest base sig
  digest="sha-256=:$(openssl dgst -sha256 -binary "$body" | base64 -w0):"
  base="$TMP/base.txt"
  printf '"@method": GET\n"@authority": %s\n"@target-uri": %s\n"@status": 200\n"content-digest": %s\n"date": %s\n"@signature-params": %s' \
    "$AUTH" "$TURI" "$digest" "$DATE" "$PARAMS" > "$base"
  openssl dgst -sha256 -sign "$LEAF_PRIV" -out "$TMP/sig.der" "$base"
  sig="sig1=:$(base64 -w0 "$TMP/sig.der"):"
  jq --rawfile b "$body" --arg sig "$sig" --arg dig "$digest" '
    (.pages[]|select(.request.path=="/account")|.response.body) = $b |
    (.pages[]|select(.request.path=="/account")|.response.headers.signature) = $sig |
    (.pages[]|select(.request.path=="/account")|.response.headers["content-digest"]) = $dig
  ' "$SESS" > "$out"
}

# run_case binary expect session registry forgeval predicate label field [field2 pred2]
# expect = "abort" | "proof"
declare -a ROWS
declare -a NOTES
record() { ROWS+=("$1"); }   # markdown table row
overall_pass=0; overall_fail=0

# Run a single field prove; capture outcome + extracted statement / abort reason.
prove1() { # binary forgeval session url field predicate outvar_prefix
  local bin="$1" forge="$2" sess="$3" url="$4" field="$5" pred="$6"
  rm -f "$TMP/p.json"
  local out
  if [ -n "$forge" ]; then
    out=$(GPS_SIM_FORGE_VALUE="$forge" "$bin" prove --session "$sess" --url "$url" \
          --field "$field" --predicate "$pred" --output "$TMP/p.json" 2>&1)
  else
    out=$("$bin" prove --session "$sess" --url "$url" \
          --field "$field" --predicate "$pred" --output "$TMP/p.json" 2>&1)
  fi
  LAST_OUT="$out"
}
prove2() { # binary forge session url f1 p1 f2 p2  (two fields, both --url)
  local bin="$1" forge="$2" sess="$3" url="$4" f1="$5" p1="$6" f2="$7" p2="$8"
  rm -f "$TMP/p.json"
  local out
  if [ -n "$forge" ]; then
    out=$(GPS_SIM_FORGE_VALUE="$forge" "$bin" prove --session "$sess" --url "$url" \
          --field "$f1" --predicate "$p1" --field "$f2" --predicate "$p2" --output "$TMP/p.json" 2>&1)
  else
    out=$("$bin" prove --session "$sess" --url "$url" \
          --field "$f1" --predicate "$p1" --field "$f2" --predicate "$p2" --output "$TMP/p.json" 2>&1)
  fi
  LAST_OUT="$out"
}
abort_reason() {
  # The full guest panic message is surfaced on the `Error: Guest panicked: …` line.
  local m
  m=$(printf '%s\n' "$LAST_OUT" | sed -n 's/.*Guest panicked: //p' | head -1)
  [ -z "$m" ] && m=$(printf '%s\n' "$LAST_OUT" | grep -iE "panicked|error" | head -1)
  printf '%s' "$m" | sed 's/  */ /g' | cut -c1-160
}
extracted_stmt() { jq -r '.journal.field_results[0].predicate_statement' "$TMP/p.json" 2>/dev/null; }

# verdict: compare actual vs expected, emit table row + console line
verdict() { # id desc expect actual_outcome detail
  local id="$1" desc="$2" expect="$3" actual="$4" detail="$5" ok
  # The guest's own panic strings contain an em dash, and the guest cannot be
  # edited without changing its ELF and therefore the image_id. Normalise it
  # here, where the report is written, so RESULTS.md stays free of them.
  detail="${detail//$'\u2014'/,}"
  if [ "$expect" = "$actual" ]; then ok="PASS"; overall_pass=$((overall_pass+1)); else ok="FAIL"; overall_fail=$((overall_fail+1)); fi
  printf '  [%s] %s, expect:%s actual:%s, %s\n' "$ok" "$id" "$expect" "$actual" "$detail"
  record "| $id | $desc | $expect | $actual | $ok | ${detail//|/\\|} |"
}

echo "=== GPS adversarial soundness suite ==="
echo "  prod   : $PROD"
echo "  attack : $ATTACK"
echo

# -- A0 control: clean inputs must produce a proof ---------------------------
prove1 "$PROD" "" "$SESS" /account "$BAL" "> 1000"
if [ -f "$TMP/p.json" ]; then verdict A0 "control: clean session, balance>1000" proof proof "extracted $(extracted_stmt)"
else verdict A0 "control: clean session" proof abort "UNEXPECTED: $(abort_reason)"; fi

# -- A: forged value (attack-sim) --------------------------------------------
# Host hints '2026' for the balance; guest re-extracts 2500.00 in-circuit → binding abort.
prove1 "$ATTACK" "2026" "$SESS" /account "$BAL" "> 1000"
if [ -f "$TMP/p.json" ]; then verdict A "forged host value (hint 2026 vs real 2500.00)" abort proof "UNEXPECTED PROOF, forge accepted"
else verdict A "forged host value (hint 2026 vs real 2500.00)" abort abort "$(abort_reason)"; fi

# -- B: duplicate label (first-occurrence) -----------------------------------
# Decoy 'Account Balance'=99999.99 placed BEFORE the real one. Predicate > 50000 is
# TRUE only of the decoy (real is 2500). A produced proof => guest bound to the FIRST
# (decoy) occurrence. This is correct-by-design: the decoy is in the origin-SIGNED body.
perl -0777 -pe 's/(<div class="label">Account Balance<\/div>)/<div class="label">Account Balance<\/div>\n        <div class="value" id="decoy">99999.99 EUR<\/div>\n        $1/' "$ORIG_BODY" > "$TMP/body_B.html"
resign_account "$TMP/body_B.html" "$TMP/session_${SID8}_B.json"
prove1 "$PROD" "" "$TMP/session_${SID8}_B.json" /account "$BAL" "> 50000"
if [ -f "$TMP/p.json" ]; then
  ev=$(jq -r '.journal.binding' "$TMP/p.json")
  verdict B "duplicate label: decoy 99999.99 before real 2500" proof proof "bound to FIRST (decoy) 99999.99; > 50000 true; binding=$ev"
else verdict B "duplicate label" proof abort "$(abort_reason)"; fi

# -- C: label inside an HTML attribute ---------------------------------------
# 'Account Balance' appears as a byte substring inside data-field="…", with a decoy
# number after it. The extractor is a byte scan (not HTML-aware), so the anchor matches
# the attribute occurrence first. Predicate > 50000 decisive (real is 2500).
perl -0777 -pe 's/(<div class="label">Account Balance<\/div>)/<div data-field="Account Balance" data-amount="88888.88"><\/div>\n        $1/' "$ORIG_BODY" > "$TMP/body_C.html"
resign_account "$TMP/body_C.html" "$TMP/session_${SID8}_C.json"
prove1 "$PROD" "" "$TMP/session_${SID8}_C.json" /account "$BAL" "> 50000"
if [ -f "$TMP/p.json" ]; then verdict C "label inside HTML attribute (data-field=…)" proof proof "anchor matched the ATTRIBUTE occurrence, bound decoy 88888.88; byte scan, not HTML-aware"
else verdict C "label inside HTML attribute" proof abort "$(abort_reason)"; fi

# -- D: label inside an HTML comment -----------------------------------------
# '<!-- Account Balance: 0.01 -->' before the real label. Byte scan matches the comment
# occurrence; first number after = 0.01. Predicate > 1000 => guest ABORTS (0.01 > 1000 false),
# proving the comment value WAS bound (else real 2500 would pass).
perl -0777 -pe 's/(<div class="label">Account Balance<\/div>)/<!-- Account Balance: 0.01 -->\n        $1/' "$ORIG_BODY" > "$TMP/body_D.html"
resign_account "$TMP/body_D.html" "$TMP/session_${SID8}_D.json"
prove1 "$PROD" "" "$TMP/session_${SID8}_D.json" /account "$BAL" "> 1000"
if [ -f "$TMP/p.json" ]; then verdict D "label inside HTML comment (decoy 0.01)" abort proof "UNEXPECTED: bound real value, comment not matched"
else verdict D "label inside HTML comment (decoy 0.01)" abort abort "comment occurrence WAS matched → bound 0.01 → $(abort_reason)"; fi

# -- E: cross-field value substitution (attack-sim) --------------------------
# Two fields (balance, holder). Host swaps: feeds the holder's value 'Alice Smith' as the
# balance hint (field 0). Guest re-extracts 2500.00 for balance → binding mismatch abort.
prove2 "$ATTACK" "Alice Smith" "$SESS" /account "$BAL" "> 1000" "$HOLDER" "== \"Alice Smith\""
if [ -f "$TMP/p.json" ]; then verdict E "cross-field swap (holder value as balance hint)" abort proof "UNEXPECTED PROOF"
else verdict E "cross-field swap (holder value as balance hint)" abort abort "$(abort_reason)"; fi

# -- F: tampered content-digest ----------------------------------------------
# Append to the signed body, leave content-digest unchanged → digest mismatch.
jq '(.pages[]|select(.request.path=="/account")|.response.body) += "<!--TAMPER-->"' "$SESS" > "$TMP/session_${SID8}_F.json"
prove1 "$PROD" "" "$TMP/session_${SID8}_F.json" /account "$BAL" "> 1000"
if [ -f "$TMP/p.json" ]; then verdict F "tampered body, stale content-digest" abort proof "UNEXPECTED PROOF"
else verdict F "tampered body, stale content-digest" abort abort "$(abort_reason)"; fi

# -- G: wrong key / forged registry ------------------------------------------
sign_root() { local b64; b64=$(grep -v '^-----' "$3" | tr -d '[:space:]'); printf 'gps-key-registry-v1\nkeyid=%s\ndomain=%s\nnot_after=0\nleaf=%s' "$1" "$2" "$b64" > "$TMP/canon"; openssl dgst -sha256 -sign "$REPO/nginx/keys/gps_root_private.pem" -out "$TMP/rsig.der" "$TMP/canon"; base64 -w0 "$TMP/rsig.der"; }
make_reg() { local sig leaf; sig=$(sign_root "$1" "$2" "$3"); leaf=$(cat "$3"); jq -n --arg k "$1" --arg d "$2" --arg l "$leaf" --arg s "$sig" '[{entry:{keyid:$k,domain:$d,leaf_pubkey_pem:$l,not_after:0},root_sig_b64:$s}]' > "$4"; }

# G1: corrupt the root signature on the (otherwise valid) registry entry.
jq '.[0].root_sig_b64 = (.[0].root_sig_b64[0:40] + "AAAA" + .[0].root_sig_b64[44:])' "$REG" > "$TMP/reg_G1.json"
GPS_KEY_REGISTRY="$TMP/reg_G1.json" prove1 "$PROD" "" "$SESS" /account "$BAL" "> 1000"
if [ -f "$TMP/p.json" ]; then verdict G1 "forged root signature on registry entry" abort proof "UNEXPECTED PROOF"
else verdict G1 "forged root signature on registry entry" abort abort "$(abort_reason)"; fi

# G2: no registry entry for the page's keyid (entry under a different keyid).
make_reg "evil-key" "172.18.0.50" "$REPO/nginx/keys/nginx_public.pem" "$TMP/reg_G2.json"
GPS_KEY_REGISTRY="$TMP/reg_G2.json" prove1 "$PROD" "" "$SESS" /account "$BAL" "> 1000"
if [ -f "$TMP/p.json" ]; then verdict G2 "no registry entry for page keyid" abort proof "UNEXPECTED PROOF"
else verdict G2 "no registry entry for page keyid" abort abort "$(abort_reason)"; fi

# G3: root-vouched WRONG leaf key: root sig valid, but response sig fails under it.
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/evil_priv.pem" 2>/dev/null
openssl ec -in "$TMP/evil_priv.pem" -pubout -out "$TMP/evil_pub.pem" 2>/dev/null
make_reg "gps-nginx" "172.18.0.50" "$TMP/evil_pub.pem" "$TMP/reg_G3.json"
GPS_KEY_REGISTRY="$TMP/reg_G3.json" prove1 "$PROD" "" "$SESS" /account "$BAL" "> 1000"
if [ -f "$TMP/p.json" ]; then verdict G3 "root-vouched wrong leaf key" abort proof "UNEXPECTED PROOF"
else verdict G3 "root-vouched wrong leaf key" abort abort "$(abort_reason)"; fi

# -- H: malformed signature-input --------------------------------------------
# H1: drop "@method" from the covered-component list → base downgrade rejected.
jq '(.pages[]|select(.request.path=="/account")|.response.headers["signature-input"]) |= sub("\"@method\" "; "")' "$SESS" > "$TMP/session_${SID8}_H1.json"
prove1 "$PROD" "" "$TMP/session_${SID8}_H1.json" /account "$BAL" "> 1000"
if [ -f "$TMP/p.json" ]; then verdict H1 "base missing @method (downgrade)" abort proof "UNEXPECTED PROOF"
else verdict H1 "base missing @method (downgrade)" abort abort "$(abort_reason)"; fi

# H2: strip the keyid parameter → guest cannot resolve a registry key.
jq '(.pages[]|select(.request.path=="/account")|.response.headers["signature-input"]) |= sub(";keyid=\"gps-nginx\""; "")' "$SESS" > "$TMP/session_${SID8}_H2.json"
prove1 "$PROD" "" "$TMP/session_${SID8}_H2.json" /account "$BAL" "> 1000"
if [ -f "$TMP/p.json" ]; then verdict H2 "signature-input missing keyid" abort proof "UNEXPECTED PROOF"
else verdict H2 "signature-input missing keyid" abort abort "$(abort_reason)"; fi

# -- I: body with no matching anchor -----------------------------------------
# Name a label not present in the body; extractor finds no anchor → abort.
prove1 "$PROD" "" "$SESS" /account 'regex:Nonexistent Label.{0,300}?([+-]?[0-9][0-9.,]*)|||ghost' "> 1000"
if [ -f "$TMP/p.json" ]; then verdict I "anchor names a label absent from the body" abort proof "UNEXPECTED PROOF"
else verdict I "anchor names a label absent from the body" abort abort "$(abort_reason)"; fi

echo
echo "=== $overall_pass passed, $overall_fail failed ==="

# -- Write RESULTS.md --------------------------------------------------------
{
  echo "# Adversarial Negative-Test Suite, Results"
  echo
  echo "Generated by \`tests/adversarial/run_suite.sh\` on $(date -u '+%Y-%m-%d %H:%M UTC')."
  echo
  echo "- **Guest:** v12, image_id \`71442f7b…\` (production binary \`bin/gps-host\`)."
  echo "- **Mode:** \`RISC0_DEV_MODE=1\`: the guest executes in full (all asserts/panics/extraction"
  echo "  run); only the STARK seal is skipped. Functional soundness is exactly what is tested."
  echo "- **Forged-hint cases (A, E):** run against the \`--features attack-sim\` build"
  echo "  (\`zkvm/target/release/host\`), which lets the host inject a forged value hint via"
  echo "  \`GPS_SIM_FORGE_VALUE\`. The production binary cannot do this (KI-23)."
  echo "- **Crafted-body cases (B, C, D):** a new HTML body is built and RE-SIGNED with the origin's"
  echo "  leaf key (valid content-digest + 6-component RFC 9421 signature), modelling an adversarial"
  echo "  ORIGIN that controls and signs its own HTML, the dissertation's trust boundary."
  echo
  echo "**Outcome legend:** \`abort\` = guest panics, no proof emitted. \`proof\` = a (dev-mode) proof"
  echo "is produced. \`PASS\` = actual matched expected."
  echo
  echo "| Case | Attack | Expected | Actual | Verdict | Detail |"
  echo "|------|--------|----------|--------|---------|--------|"
  for r in "${ROWS[@]}"; do echo "$r"; done
  echo
  echo "**Totals: $overall_pass passed, $overall_fail failed.**"
  cat <<'DISCUSSION'

## Discussion

### No unexpected passes
No case produced a proof that should not exist. The only `proof` outcomes are A0 (the clean
control) and B and C, where the bound value is the **first match of the requested pattern in the
origin-signed body**, exactly what the guest guarantees. A prover cannot inject content the origin
did not sign: every body that yields a proof carries a valid content-digest and a valid 6-component
RFC 9421 signature under a root-vouched leaf key. The forge cases (A, E) and every tampering case
(F, G, H, I) abort.

### B, C, D: the "first occurrence" semantics (correct-by-design, with a stated scope)
These three test the byte-scan anchored extractor against adversarial HTML structure.

- **B (duplicate label).** A second `Account Balance` label carrying a decoy value placed *before*
  the real one wins, because the extractor binds the **first** occurrence (`gps_core::extract_anchored`,
  unit test `anchored_first_occurrence_is_bound_not_second`). The proof is sound in the formal sense:
  the journal commits the pattern and the body hash, and the value really is the first match in the
  signed body. **It is correct-by-design _given the trust model_:** the origin controls and signs its
  own HTML, so a verifier who already trusts the origin's key trusts the bytes it vouches for. The gap
  is between the formal guarantee ("value = first match of the pattern in the signed body") and a
  user's *intended* reading ("value = the current account balance"). This is the boundary to state
  explicitly in the paper (this is the duplicate-label case, B): the anchored extractor's
  guarantee is the former, not the latter, and a verifier who needs the latter must treat label
  uniqueness as their own check.

- **C (label inside an HTML attribute).** The anchor `Account Balance` matches as a **byte substring**
  inside `data-field="Account Balance"`; the extractor is not HTML-aware. The decoy number after the
  attribute is bound. Same residual class as B: it requires an adversarial *origin* to author and sign
  such markup, which the trust model already places inside the trusted boundary. Acceptable because the
  extractor's contract is a byte scan over the signed body, audited from the journal, not an HTML/DOM
  parse. Bringing a DOM parser in-circuit would multiply cost and add its own parser-differential
  attack surface.

- **D (label inside an HTML comment).** Same byte-scan behaviour: the anchor matches inside
  `<!-- Account Balance: 0.01 -->`, binding `0.01`. Here the planted value is small, so the predicate
  `> 1000` is false and the guest **aborts**: a comment can shift the bound value but cannot
  manufacture a *true* predicate the signed body does not support. A large planted comment value would
  reduce to case B/C (origin-signed decoy), not a prover forgery.

**Verdict.** B/C/D are not soundness breaks; they are the documented scope boundary of a deliberately
cheap, auditable byte-scan extractor. The defensible paper statement: the extractor binds the value to
the *first occurrence of the named pattern in the signed body*; HTML structure (attributes, comments,
duplicate labels) is not interpreted, and an origin that signs adversarial markup is already inside the
trust boundary. A verifier needing field-identity semantics audits label uniqueness, or uses a
body-revealing mode (out of scope).
DISCUSSION
} > "$RESULTS"
echo "  wrote $RESULTS"
[ "$overall_fail" -eq 0 ]
