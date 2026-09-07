# ARCHIVED: v11 measurements (guest `97f01cdf…`)

> **This file is the historical record and is not the current measurement.**
> It holds the 2026-06-14 CPU-pinned campaign against the **v11** guest, kept verbatim because
> the dissertation's Table 6.3 means (138.3 s, 145.5 s) come from it. The current campaign, run
> against the **v12** guest `71442f7b…`, is in `n10_measurements.md`.
>
> Its cross-page row (459.7 s / 3,145,728 cycles) was measured before the 2026-06-25 session
> redaction changed those inputs and is superseded; see the correction note below.

# CPU-pinned real-STARK measurements (v11 key-registry guest)

> **CORRECTION, 2026-09-05.** Two rows below were measured before the 2026-06-25 session
> redaction changed the cross-page inputs, and were never re-measured, so this file has been
> contradicting `GUIDE.md` and `reproduce.sh` ever since. The cross-page figures of
> **459.7 s / 3,145,728 cycles** are for the pre-redaction session and are superseded.
> Nothing is deleted: the original rows stand as the record of what was run on 2026-06-14.
>
> The guest has also moved on. Everything below is the **v11** guest, `97f01cdf…`. The current
> guest is **v12**, `71442f7b…`, adding anchored dates and salted commitments. Freshly measured
> on 2026-09-05, single real proof each, same machine:
>
> | Configuration | Time | Seal | Padded cycles |
> |---|---|---|---|
> | 1-field | 124.8 s | 537,684 B | 1,048,576 |
> | 2-field | 130.9 s | 538,668 B | 1,048,576 |
> | PDF NIF | 206.7 s | 806,542 B | 1,572,864 |
> | cross-page | 584.8 s | 2,402,898 B | 4,456,448 |
>
> The first three are within 500 bytes of v11. **The cross-page seal grew 253 KB and its cycles
> 6.25 %**, because the salted commitment hashes each body a second time and that workload
> carries a 104 KB page. The cost of the commitment is proportional to body size, which the
> 4.3 KB figures understate.


Generated 2026-06-14 by `benchmarks/run_measurements.sh`.

- **Guest:** v11, image_id `97f01cdf…` (`bin/gps-host`).
- **Real STARK proofs** (`dev_mode=false`), each pinned with `taskset -c 0-15`,
  `GPS_SEGMENT_PO2=19` (matches the canonical proofs; bounds peak RAM ~6.9 GB).
- Machine: 16-core CPU, 16 GB, **shared with the live desktop session** (this work ran on the
  same machine). Key configs n=10; PDF/cross-page n=3.
- Times are `metadata.proof_time_seconds` (the prover's measured elapsed, the same figure
  Table V reports).

| Configuration | n | Mean (s) | Std dev (s) | Min (s) | Max (s) |
|---------------|---|----------|-------------|---------|---------|
| 1-field (balance), Key Registry | 10 | 138.3 | 6.4 | 128.5 | 144.2 |
| 2-field (balance+holder), Key Registry | 10 | 145.5 | 0.6 | 144.8 | 146.3 |
| PDF NIF (1 field, FlateDecode) | 3 | 219.9 | 0.5 | 219.4 | 220.4 |
| Cross-page (balance + welcome, 2 pages) | 3 | 459.7 | 0.3 | 459.5 | 460.1 | *(pre-redaction inputs; superseded)* |

## Raw times

- **1-field (balance), Key Registry** (n=10): 128.5, 128.5, 131.7, 137.3, 141.3, 141.7, 142.6, 143.3, 143.7, 144.2
- **2-field (balance+holder), Key Registry** (n=10): 144.9, 144.9, 144.8, 144.9, 145.8, 145.9, 146.0, 145.9, 145.5, 146.3
- **PDF NIF (1 field, FlateDecode)** (n=3): 219.4, 219.8, 220.4
- **Cross-page (balance + welcome, 2 pages)** (n=3): 459.5, 459.6, 460.1

## Analysis

**Warm-up, not intrinsic variance.** The 1-field run has the only wide spread (σ=6.4), and its raw
times climb monotonically (128.5 → 144.2). This is the machine warming up at the start of the batch:
the first proofs ran cold and the rest settled near 144 s. The 2-field run, which started after
~23 min of continuous proving, is essentially flat (σ=0.6), as are PDF (σ=0.5) and cross-page (σ=0.3).
The honest read is that pinned, steady-state proving on this machine is very stable (σ < 1 s once
warm); the 1-field σ overstates run-to-run noise because it spans the cold-start ramp.

**Reconciliation with Table V and the proof artifacts.** Three sources of the absolute proving time
exist and they differ:

| Config | proof JSON (1 sample) | Table V (paper) | this run (n, pinned, loaded) |
|--------|----------------------|-----------------|------------------------------|
| 1-field | 120.48 s | 133.3 s | 138.3 ± 6.4 (n=10) |
| 2-field | 126.71 s | 137.8 s | 145.5 ± 0.6 (n=10) |
| PDF     | 193.41 s | 193 s   | 219.9 ± 0.5 (n=3) |
| cross-page | 412.56 s | 413 s | 459.7 ± 0.3 (n=3) *(pre-redaction inputs; superseded, see the correction at the top)* |

The pinned means run ~10–15 % above the single canonical proof artifacts. The proof JSONs were each a
single sample on a quieter machine; this batch ran 26 back-to-back real proofs on a machine also
running the desktop session, so concurrent load and sustained-load CPU behaviour push the absolute
times up. Cycle counts are unaffected (identical to the artifacts: 1,048,576 for 1- and 2-field,
1,572,864 PDF, and 3,145,728 cross-page for the pre-redaction inputs) and remain the
hardware-independent transfer metric.

**Implication for the paper.** Absolute proving time on this machine is load-dependent and spans
~120 s (idle, single sample) to ~145 s (loaded, n=10 steady state). Table V's 133.3 s / 137.8 s sit
between these, which is defensible, but the single proof artifacts (120.48 s / 126.71 s) are the
fastest samples, not the typical case. The most honest figure for Table V is a mean ± σ with the
measurement conditions stated, e.g. "1-field 138 ± 6 s, 2-field 146 ± 1 s (n=10, real STARK,
`taskset` 16 cores, machine shared with the desktop session)", or the lighter "about two minutes" the
abstract already uses, leaning on cycle counts as the transfer metric (the paper's own stated stance).
This supersedes the §VI.H "n=3, no CPU pinning" caveat.

**Method note.** `taskset -c 0-15` pins affinity to all 16 cores (the canonical environment), giving
times comparable to Table V. A tighter isolation (pinning the prover to a 4-core subset, `CORES=0-3`)
was tried first and produced ~272 s/proof: it isolates scheduling but the smaller core budget more
than doubles proving time and is not comparable to the full-machine numbers in the paper.
