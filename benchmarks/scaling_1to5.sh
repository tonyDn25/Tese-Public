#!/usr/bin/env bash
# Real-proof scaling campaign: same-page field counts 1..5 on /account.
# Config matches the measured key-registry guest (50e385ca):
#   real proofs (dev_mode off), GPS_SEGMENT_PO2=19 (≈6.9 GB peak, ~525 KB seal),
#   CPU-pinned. Logs one CSV row per run: fields,run,time_s,seal_bytes,total_cycles.
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GPS_KEY_REGISTRY="$REPO/nginx/keys/gps-keys.json"
export GPS_SEGMENT_PO2=19
unset RISC0_DEV_MODE
TR="$REPO/sessions"; SESS1="$TR/session_direct_172_18_0_50_4502b208.json"
BIN="$REPO/bin/gps-host"
PIN="taskset -c 0-7"
OUT="$REPO/benchmarks/scaling_1to5.csv"
LOG="$REPO/benchmarks/scaling_1to5.log"
RUNS="${RUNS:-3}"

F1='regex:Account Balance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)|||balance';      P1='> 1000'
F2='regex:Account Holder.{0,300}?(Alice Smith)|||holder';              P2='== "Alice Smith"'
F3='regex:NIF.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)|||nif';                          P3='> 100000000'
F4='regex:Account Type.{0,300}?(Premium Current Account)|||acct_type'; P4='== Premium Current Account'
F5='regex:Verified.{0,300}?(true)|||verified';                         P5='== true'

args_for(){ # echo --field/--predicate args for N fields
  local n="$1"
  [ "$n" -ge 1 ] && printf -- '--field\n%s\n--predicate\n%s\n' "$F1" "$P1"
  [ "$n" -ge 2 ] && printf -- '--field\n%s\n--predicate\n%s\n' "$F2" "$P2"
  [ "$n" -ge 3 ] && printf -- '--field\n%s\n--predicate\n%s\n' "$F3" "$P3"
  [ "$n" -ge 4 ] && printf -- '--field\n%s\n--predicate\n%s\n' "$F4" "$P4"
  [ "$n" -ge 5 ] && printf -- '--field\n%s\n--predicate\n%s\n' "$F5" "$P5"
}

echo "fields,run,time_s,seal_bytes,total_cycles" > "$OUT"
: > "$LOG"
echo "[start] $(date -Is)  RUNS=$RUNS  bin=$BIN  po2=$GPS_SEGMENT_PO2" | tee -a "$LOG"
for n in 1 2 3 4 5; do
  mapfile -t A < <(args_for "$n")
  for r in $(seq 1 "$RUNS"); do
    out="/tmp/scal_${n}f_${r}.json"
    echo "[run] fields=$n run=$r $(date -Is)" | tee -a "$LOG"
    cyc="$($PIN "$BIN" prove --session "$SESS1" --url /account "${A[@]}" --output "$out" 2>>"$LOG" \
           | grep -oE "total cycles: [0-9]+" | grep -oE "[0-9]+" | tail -1)"
    t="$(jq -r '.metadata.proof_time_seconds' "$out" 2>/dev/null)"
    sz="$(jq -r '.metadata.proof_size_bytes' "$out" 2>/dev/null)"
    dev="$(jq -r '.metadata.dev_mode' "$out" 2>/dev/null)"
    echo "$n,$r,$t,$sz,${cyc:-NA}" | tee -a "$OUT"
    echo "    -> time=${t}s seal=${sz}B cycles=${cyc} dev_mode=${dev}" | tee -a "$LOG"
  done
done
echo "[done] $(date -Is)" | tee -a "$LOG"
