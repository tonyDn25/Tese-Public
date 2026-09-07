# CPU-pinned real-STARK measurements (v12 guest, image_id 71442f7b...)

Generated 2026-09-06 02:23 UTC by `benchmarks/run_measurements.sh`.

- **Guest:** v12, image_id `71442f7b…` (`bin/gps-host`).
- **Real STARK proofs** (`dev_mode=false`), each pinned with `taskset -c 0-15`,
  `GPS_SEGMENT_PO2=19` (matches the canonical proofs; bounds peak RAM ~6.9 GB).
- Machine: 16-core CPU, 16 GB, shared with the live desktop session. Key configs n=10; PDF/cross-page n=3.
- Times are `metadata.proof_time_seconds` (the prover's measured elapsed, the same
  figure dissertation Table 6.3 reports).

| Configuration | n | Mean (s) | Std dev (s) | Min (s) | Max (s) |
|---------------|---|----------|-------------|---------|---------|
| 1-field (balance), Key Registry | 10 | 133.2 | 5.4 | 122.5 | 138.5 |
| 2-field (balance+holder), Key Registry | 10 | 140.7 | 1.1 | 138.9 | 142.3 |
| PDF NIF (1 field, FlateDecode) | 3 | 214.1 | 0.1 | 214.0 | 214.1 |
| Cross-page (balance + welcome, 2 pages) | 3 | 610.6 | 1.8 | 608.7 | 612.4 |

## Raw times

- **1-field (balance), Key Registry** (n=10): 122.5, 127.7, 128.0, 132.6, 134.5, 135.7, 136.4, 137.7, 138.2, 138.5
- **2-field (balance+holder), Key Registry** (n=10): 138.9, 139.3, 140.0, 140.6, 140.8, 141.2, 141.1, 141.4, 141.9, 142.3
- **PDF NIF (1 field, FlateDecode)** (n=3): 214.0, 214.0, 214.1
- **Cross-page (balance + welcome, 2 pages)** (n=3): 608.7, 610.6, 612.4
