#!/usr/bin/env bash
# ============================================================================
# n>=5 CPU-pinned real-STARK measurements for the current guest.
#
# Two key configs at n=N_KEY: 1-field and 2-field (Key Registry guest).
# Two aux  configs at n=N_AUX: PDF (1 field) and cross-page (2 fields).
#
# All runs: real STARK (dev_mode=false), taskset -c $CORES for consistent
# scheduling, GPS_SEGMENT_PO2=19 (matches the canonical proofs, bounds RAM ~6.9 GB).
# Each run's proof_time_seconds (the prover's measured elapsed, same field Table 6.3
# uses) is appended to a per-config log; stats computed at the end.
#
# Usage: benchmarks/run_measurements.sh
# Output: benchmarks/raw/*.log  and  benchmarks/n10_measurements.md
# ============================================================================
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/bin/gps-host"
TR="$REPO/sessions"
export GPS_KEY_REGISTRY="$REPO/nginx/keys/gps-keys.json"
export GPS_SEGMENT_PO2=19
unset RISC0_DEV_MODE          # REAL proofs
# Pin to all 16 cores: fixes affinity to the canonical 16-core environment Table 6.3
# was measured on, so times are directly comparable (~120 s, not the ~272 s a 4-core
# pin produces). Override with CORES env to isolate a subset.
CORES="${CORES:-0-15}"
N_KEY="${N_KEY:-10}"
N_AUX="${N_AUX:-3}"
RAW="$REPO/benchmarks/raw"; mkdir -p "$RAW"
PROG="$REPO/benchmarks/progress.log"; : > "$PROG"

SESS1="$TR/session_direct_172_18_0_50_4502b208.json"
SESSP="$TR/session_pdf_e0c3c3c9.json"
SESSM="$TR/session_multipage_82a6a7bf.json"
BAL='regex:Account Balance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)|||balance'
HOLD='regex:Account Holder.{0,300}?(Alice Smith)|||holder'
NIF='regex:Contribuinte sob o n .{0,20}?(500 960 046)|||nif'
MB1='regex:id="balance">.{0,20}?([+-]?[0-9]+(\.[0-9]+)?)|||balance'
MW2='regex:Caixadirecta, .{0,50}?(António Silva)|||welcome_name'

# run_config <logname> <n> -- <prove args...>
run_config() {
  local name="$1" n="$2"; shift 3   # drop name n --
  local log="$RAW/$name.log"; : > "$log"
  local out="$REPO/benchmarks/_tmp_${name}.json"
  echo "[$(date +%H:%M:%S)] config $name : n=$n" | tee -a "$PROG"
  for i in $(seq 1 "$n"); do
    rm -f "$out" "$out.salt"
    taskset -c "$CORES" "$BIN" prove "$@" --output "$out" >/dev/null 2>&1
    if [ -f "$out" ]; then
      local t dm; t=$(jq -r '.metadata.proof_time_seconds' "$out"); dm=$(jq -r '.metadata.dev_mode' "$out")
      echo "$t" >> "$log"
      echo "[$(date +%H:%M:%S)]   $name run $i/$n : ${t}s (dev_mode=$dm)" | tee -a "$PROG"
    else
      echo "[$(date +%H:%M:%S)]   $name run $i/$n : FAILED (no proof)" | tee -a "$PROG"
    fi
    rm -f "$out" "$out.salt"
  done
}

echo "START $(date)" | tee -a "$PROG"
run_config 1field  "$N_KEY" -- --session "$SESS1" --url /account \
  --field "$BAL"  --predicate '> 1000'
run_config 2field  "$N_KEY" -- --session "$SESS1" --url /account \
  --field "$BAL"  --predicate '> 1000' --field "$HOLD" --predicate '== "Alice Smith"'
run_config pdf     "$N_AUX" -- --session "$SESSP" --url /comprovativo.pdf \
  --field "$NIF"  --predicate '== 500 960 046'
run_config crosspage "$N_AUX" -- --session "$SESSM" \
  --field "$MB1" --predicate '> 1000'        --field-session "$SESSM" --field-url /account \
  --field "$MW2" --predicate '== António Silva' --field-session "$SESSM" --field-url /mypage
echo "DONE $(date)" | tee -a "$PROG"

# -- Stats + markdown --------------------------------------------------------
python3 - "$REPO" "$N_KEY" "$N_AUX" <<'PY'
import sys, statistics, datetime, os
repo, nkey, naux = sys.argv[1], sys.argv[2], sys.argv[3]
raw = os.path.join(repo, "benchmarks", "raw")
cfgs = [("1field","1-field (balance), Key Registry"),
        ("2field","2-field (balance+holder), Key Registry"),
        ("pdf","PDF NIF (1 field, FlateDecode)"),
        ("crosspage","Cross-page (balance + welcome, 2 pages)")]
def stats(vals):
    if not vals: return None
    m=statistics.mean(vals)
    sd=statistics.stdev(vals) if len(vals)>1 else 0.0
    return m,sd,min(vals),max(vals),len(vals)
rows=[]; detail=[]
for key,desc in cfgs:
    p=os.path.join(raw,f"{key}.log")
    vals=[float(x) for x in open(p).read().split()] if os.path.exists(p) else []
    s=stats(vals)
    if s:
        m,sd,lo,hi,n=s
        rows.append(f"| {desc} | {n} | {m:.1f} | {sd:.1f} | {lo:.1f} | {hi:.1f} |")
        detail.append(f"- **{desc}** (n={n}): "+", ".join(f"{v:.1f}" for v in vals))
    else:
        rows.append(f"| {desc} | 0 |, |, |, |, |")
out=os.path.join(repo,"benchmarks","n10_measurements.md")
with open(out,"w") as f:
    f.write("# CPU-pinned real-STARK measurements (v13 guest, image_id 50e385ca...)\n\n")
    f.write(f"Generated {datetime.datetime.utcnow():%Y-%m-%d %H:%M UTC} by `benchmarks/run_measurements.sh`.\n\n")
    f.write("- **Guest:** v13, image_id `50e385ca…` (`bin/gps-host`).\n")
    f.write(f"- **Real STARK proofs** (`dev_mode=false`), each pinned with `taskset -c {os.environ.get('CORES','0-15')}`,\n")
    f.write("  `GPS_SEGMENT_PO2=19` (matches the canonical proofs; bounds peak RAM ~6.9 GB).\n")
    f.write(f"- Machine: 16-core CPU, 16 GB, shared with the live desktop session. Key configs n={nkey}; PDF/cross-page n={naux}.\n")
    f.write("- Times are `metadata.proof_time_seconds` (the prover's measured elapsed, the same\n")
    f.write("  figure dissertation Table 6.3 reports).\n\n")
    f.write("| Configuration | n | Mean (s) | Std dev (s) | Min (s) | Max (s) |\n")
    f.write("|---------------|---|----------|-------------|---------|---------|\n")
    f.write("\n".join(rows)+"\n\n")
    f.write("## Raw times\n\n"+"\n".join(detail)+"\n")
print(open(out).read())
PY
