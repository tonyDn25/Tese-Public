# GPS: Full Guide (project, running, testing, validating)

**GPS** = *General Privacy-preserving web proof System*. It produces non-interactive, publicly
verifiable **zero-knowledge proofs** about a single field of an **RFC 9421-signed** web response,
revealing nothing else about the page. No trusted hardware, no online third party, and no server
change beyond signing.

- **Source tree:** this folder (the code needed to build, run, and verify GPS end to end).
- **Guest image identifier:** `50e385cac9acdd6b9cc3e6c21a19daf33d6d817cad32d5fe7fe17d2728eddcd0`
  (the SHA-256 of the compiled zkVM guest; trusting a proof means trusting this exact program).
- **One-shot reproduction:** [`./reproduce.sh`](#7-running-testing-validating), see §7.

---

## Contents
1. [What problem GPS solves](#1-what-problem-gps-solves)
2. [How it works (the pipeline)](#2-how-it-works-the-pipeline)
3. [Glossary, the meaning of every term](#3-glossary)
4. [Components, what each piece does](#4-components)
5. [What is proven / not proven (trust model)](#5-trust-model)
6. [What is done (status + measured results)](#6-status--measured-results)
7. [Running, testing, validating](#7-running-testing-validating)
8. [Using the REAL verifier](#8-using-the-real-verifier)
9. [The browser/extension flow (Firefox)](#9-the-browserextension-flow-firefox)
10. [Reproducing on another PC](#10-reproducing-on-another-pc)
11. [Where every paper number comes from](#11-where-every-paper-number-comes-from)
12. [File map](#12-file-map)

---

## 1. What problem GPS solves
A user often needs to prove **one fact** from a logged-in web page to a third party, "my balance is
over €1000", "this statement names me", without handing over their password, a forgeable screenshot,
or the whole page. TLS secures the *connection* but leaves **no artefact a third party can check**
afterwards (both endpoints share the keys, so a saved transcript could have been typed up by the
client). GPS closes that gap: the origin signs responses at the application layer (RFC 9421), and a
zkVM proves a predicate over a chosen field of a signed response in zero knowledge. The proof is
**transferable** (anyone can check it offline) and **selective** (only the predicate's truth leaks).

## 2. How it works (the pipeline)
```
 Firefox + extension --> direct capture --> GPS origin (RFC 9421 signing)
        |                                                        |
        |                       signed response(s) recorded into a Session (JSON)
        v                                                        v
   gps-host (orchestrator) -writes-> RISC Zero guest (zkVM): re-hash body, verify
        |                            registry+signature, extract field, check predicate
        v                                                        |
   proof.json  (seal + journal)  <-------- commit journal + STARK seal
        v
   Verifier (anyone, offline): receipt.verify(image_id) + read journal
```
Inside the zkVM the **guest** (1) re-derives the SHA-256 content digest and checks it matches the
signed `Content-Digest`; (2) resolves the origin's **leaf** key through a **root-signed registry**
and verifies the RFC 9421 signature under it; (3) runs the field's **selection pattern** on the
verified body and binds the proven value to it; (4) evaluates the **predicate** and commits a
**journal** entry; the prover emits a **STARK seal**. A false check => panic => **no proof**.

## 3. Glossary
| Term | Meaning |
|------|---------|
| **RFC 9421** | IETF *HTTP Message Signatures* (Feb 2024). The origin signs selected components (here: `@method`, `@authority`, `@target-uri`, `@status`, `content-digest`, `date`) with ECDSA P-256. Survives TLS termination; checkable long after the connection closes. |
| **Content-Digest** (RFC 9530) | `sha-256=:<base64>:` header binding the body to the signature without putting the body in the signed base. |
| **zkVM / guest** | RISC Zero zero-knowledge virtual machine running RISC-V RV32IM. The **guest** is the Rust program executed inside it; it performs every security check. |
| **host** | The Rust program on the user's machine (`gps-host`) that assembles the proof request and drives the prover. **Not** trusted for soundness. |
| **origin** | The web server that signs responses (RFC 9421). |
| **image identifier (`image_id`)** | SHA-256 of the compiled guest ELF. Accepting a proof for an `image_id` means accepting *that exact program and its constants* (including the pinned root key). Ours: `50e385ca…`. |
| **journal** | The public output the guest commits; a verifier learns only this (predicates, results, patterns, body hash, source URL, session, trust anchor, **not** the body, and for inequalities not the value). |
| **seal** | The STARK proof a verifier checks against the `image_id`. ~525 KB here. |
| **predicate** | The claim checked over the extracted value: `> 1000`, `== "Alice Smith"`, `contains(...)`, `age >= N`, etc. A false predicate aborts the proof. |
| **anchored extractor** | The cheap, sound in-circuit field selector: find the first occurrence of an **anchor** (label), then take the first number / a named literal within a **window** of `w` bytes. Lowered on the host from a `LABEL.{0,300}?(value)` regex. The window (`w=300`) is committed to the journal. |
| **binding** (`"in-circuit"`) | The guest re-runs the extractor on the *verified* body and asserts the host's hint equals it, so the prover cannot substitute a value. The journal carries `binding:"in-circuit"`. |
| **root / leaf key, registry** | The guest pins a long-lived **root** public key (compile-time → part of `image_id`). Origin **leaf** keys are data: the root signs a registry entry `keyid→domain→leaf`, verified in-circuit. Rotating a leaf re-signs the registry; the `image_id` is unchanged. |
| **cycles / tier** | RISC Zero measures work in cycles and pads each proof to the next power of two (a **tier**: 2¹⁹, 2²⁰, …). Cost is flat within a tier, doubles at each boundary. |
| **user_cycles vs total_cycles** | `user_cycles` = the raw executed count; `total_cycles` = padded to the tier (e.g. 1-field: ~675K raw → 1,048,576 = 2²⁰). Per-operation costs are measured by differencing `user_cycles`. |
| **dev mode** (`RISC0_DEV_MODE=1`) | Runs the full guest logic (every assert, signature check, extraction) but **skips** the STARK seal, fast. A dev receipt is marked `dev_mode:true` and **cannot pass** the real verifier. |

## 4. Components
| Path | Role |
|------|------|
| `gps-server/` | OpenResty (Nginx + Lua) **origin** that signs HTML and PDF responses (RFC 9421) and serves the registry at `/.well-known/gps-keys`. |
| `nginx/keys/` | Signing material (mounted, not baked in): leaf keypair, **GPS root keypair**, `gps-keys.json` registry. |
| `sessions/` | Sample sessions (signed responses) captured by the extension. |
| `extension/` | Firefox **extension** (capture by click, direct browser-side capture) + native-messaging host manifest + `install.sh`. |
| `zkvm/methods/guest/` | The **guest** (security-critical; the only component trusted for soundness). |
| `zkvm/gps-core/` | Shared types (`Session`, `Extractor::Anchored`, `ProofReceipt`, key registry) + the anchored extractor. |
| `zkvm/host/` | `gps-host`: `prove`, `verify`, `native-msg`, `verify-serve`. |
| `zkvm/risc0-verifier/` | Standalone reference verifier crate. |
| `verifier.html` | Browser proof **inspector**; does *real* STARK verification when `verify-serve` is running, else a clearly-labelled journal-only view. |
| `proofs/` | The four real proofs (`dev_mode:false`, `50e385ca…`). |
| `reproduce.sh` | The reproduction harness (this guide's companion). |
| `launch.sh`, `generate_keys.sh` | Bring up the demo stack / regenerate the leaf key. |
| `nginx/keys/` | **Throwaway demo keys, committed on purpose.** The root's public half is compiled into the guest, so it is part of `image_id 50e385ca…` and cannot be rotated without invalidating every shipped proof. Because its private half is public, anyone can mint a registry entry under this identifier: fine for a demo, never for a deployment. See README. |

## 5. Trust model
**Proven** (a verifier accepting a proof for `image_id` 50e385ca is assured of):
1. the response was served under a leaf key the pinned **root** vouched for in a registry entry whose authority matches the page;
2. the body was not altered after signing (digest re-checked in-circuit);
3. each field's value is the **first match of its named pattern** in that signed body (bound in-circuit);
4. each predicate holds (a false predicate aborts);
5. exactly the program named by `image_id` did all of the above.

**Not proven:** that the page reflects real-world truth (an honest-but-wrong origin signs a false value
into a valid proof, GPS proves *provenance + integrity*, not *correctness*); anything about the TLS
channel; that the matched label is the *intended* field rather than a same-labelled value the origin
also signed (**the verifier audits label uniqueness**: see dissertation §6.3, Cases B/C/D). Trust bottoms
out at the single pinned root; there is an expiry but **no revocation yet**. The user's machine is trusted.

## 6. Status & measured results
Everything below is **measured** on a 16 GB CPU machine (no GPU); reproduce with `./reproduce.sh`.

**Proving (dissertation Table 6.3, n=10 / n=3 CPU-pinned means on the v12 guest):**

| Config | Time | Seal | Cycles |
|--------|------|------|--------|
| 1-field `/account` | 133 s (≈125 s idle) | 525 KB | 1,048,576 (2²⁰) |
| 2-field same page | 141 s (≈131 s idle) | 526 KB | 1,048,576 (2²⁰) |
| PDF (NIF, FlateDecode) | 214 s (≈207 s idle) | 788 KB | 1,572,864 (2²¹) |
| cross-page (104 KB page) | 611 s (≈585 s idle) | 2.29 MB | 4,456,448 (past 2²²) |

The bracketed figure is the single shipped proof's own `proof_time_seconds`; the headline is the
CPU-pinned campaign mean. Peak RAM ≈ 6.9 GB (`GPS_SEGMENT_PO2=19`; the default 2²⁰ cap yields a
smaller ~276 KB single-segment seal).

> The cross-page row moved with the v12 guest. Under v11 it was 583 s / 2.05 MB / 4,194,304 cycles.
> The salted body commitment is a second hash of the **whole** body, so on this 104 KB page it costs
> **6.25 % in cycles**, against a figure not visible at all on the 4.3 KB bodies above. A deployment
> proving over megabyte-scale bodies should measure it rather than assume the headline.

> All four shipped proofs were regenerated at `GPS_SEGMENT_PO2=19` under the v12 guest on
> 2026-09-05, so `proof_multipage.json` is now the 2.29 MB PO2=19 seal and the old PO2=18 caveat
> no longer applies.

**Verification (dissertation Table 6.7):** 20–170 ms.

**Per-operation cost model (dissertation Table 6.4, measured by user-cycle differencing):**

| Operation | Cycles |
|-----------|--------|
| ECDSA P-256 verify, per signature | ~244 K |
| Signature verification per single-origin page (leaf + root) | ~488 K = **72 %** of the proof |
| SHA-256 syscall vs `sha2` crate (Δ on the body hash) | <1 K (negligible, both accelerated) |
| Anchored extract + predicate, per added field | ~106 K |
| In-circuit regex, per field (the cost the anchored form avoids) | 8.4 M |
| One-field execution, total | ~675 K raw user cycles |

**Soundness (dissertation Table 6.2):** a 13-case adversarial suite (9 attack classes A–I) runs the real guest; forgeries and tampering
abort, the produced proofs bind the first pattern match, Case D aborts on the predicate.

## 7. Running, testing, validating
Everything is driven by **`./reproduce.sh <command>`** (run `./reproduce.sh` with no args for help,
`./reproduce.sh expected` for the reference numbers):

| Command | What it does / validates | Time |
|---------|--------------------------|------|
| `env` | Check prerequisites and print tool versions. | secs |
| `build` | Build the zkVM (guest built reproducibly in Docker, see §10); print the guest `image_id` and assert it equals `50e385ca…` (proves the source in this tree reproduces the shipped artifacts and the dissertation, Appendix A). | ~3 min |
| `verify` | Verify the four shipped proofs with `gps-host verify` + `risc0-verifier`, timed (Table 6.7). | secs |
| `soundness` | Run the 13-case adversarial suite (9 attack classes A–I) against the real guest (Table 6.2). | ~3 min |
| `cycles` | Reproduce Table 6.4 by user-cycle differencing. Temporarily instruments host+guest, builds variants, measures, and **restores the source** (exit trap). | ~10 min |
| `proofs` | Regenerate all four **real** proofs and print each one's time / seal / cycles (Table 6.3). | ~15–20 min |
| `timing` | Full CPU-pinned n=10 / n=3 campaign (Table 6.3). | ~1–2 h |
| `firefox` | Bring up the server + native host and print the exact extension capture-and-prove steps (§9). | interactive |
| `quick` | `env + build + verify + soundness` (no real proving). | ~12 min |
| `all` | `quick + cycles + proofs`. | ~40 min |

**Recommended first run on a new machine:** `./reproduce.sh quick`, then `./reproduce.sh cycles`.

## 8. Using the REAL verifier
A GPS proof is a JSON file with a `seal` (the STARK proof) and a `journal` (the public claims). "Real"
verification means cryptographically checking the seal against the guest `image_id`: **not** merely
reading the journal. Three equivalent ways:

**(a) Command line, `gps-host verify`** (recommended; no daemon):
```bash
cd <this folder>
GPS_KEY_REGISTRY=$PWD/nginx/keys/gps-keys.json \
  bin/gps-host verify --proof proofs/proof_1field.json
# → "Verifying STARK seal against GPS image_id... VALID"
```
This calls `receipt.verify(GPS_GUEST_ID)`: the genuine RISC Zero STARK check.
- **VALID** = the seal is a real proof produced by *exactly* the guest whose id the verifier was built with, and the journal is authentic.
- **`gps-host verify` is image-id-specific.** It checks against the *currently compiled* guest. A proof from a different guest fails with "claim digest does not match", that is correct. To verify a proof from another build, use `risc0-verifier` with the proof's own id.
- A **dev-mode** proof (`dev_mode:true`) is **rejected** here, dev receipts can never pass as real.

**(b) Standalone reference, `risc0-verifier`** (no `--prove` overhead; can target any id):
```bash
cd zkvm    # from this folder
cargo run --release -p risc0-verifier -- ../proofs/proof_1field.json
# verify a foreign proof against its own id:
cargo run --release -p risc0-verifier -- some_proof.json --image-id <that proof's image_id>
```

**(c) Browser, `verify-serve` + `verifier.html`** (what the extension uses):
```bash
gps-host verify-serve &                 # real verifier service on 127.0.0.1:8788
firefox verifier.html                   # from this folder; drag-and-drop a proof JSON
```
The page POSTs the proof to the service, which runs the genuine `receipt.verify`, and shows
**STARK proof VERIFIED (real)** / **Invalid** / **DEV MODE**, plus the per-field predicates and
provenance. **If the service is not running**, the page degrades to an explicitly-labelled
**journal-only inspection** that makes *no* cryptographic claim (so it can never present an unchecked
proof as verified). The command-line path (a) is the recommended method for anyone not using the browser.

**What a verifier needs to trust a proof:** only the guest `image_id` (and, implicitly, the pinned
root inside it). The body and the server's per-request keys are never needed.

## 9. The browser/extension flow (Firefox): generating a proof live
This is the interactive demo: capture a real signed page in the browser and prove a field from it.
The headless evaluation in §7 needs none of this; the extension only shows live capture.

**Start the stack (one command):**
```bash
./extension/install.sh    # once: installs gps-host + the native-messaging host
./launch.sh               # starts the server + verifier AND opens Firefox on /login
```
`launch.sh` opens a real (unsandboxed) Firefox with a pre-configured profile, the GPS extension
is already side-loaded and enabled. (Snap/Flatpak/firejail Firefox can't talk to the native host;
launch.sh avoids them, see the §9 note below.)

**One-time on first launch:**
1. **Accept the demo TLS cert.** The pages are served over HTTPS by a self-signed cert for
   `172.18.0.50`: on the first visit click *Advanced → Accept the Risk and Continue*.
2. **Check the host is connected.** Click the GPS toolbar icon: a **green dot** means the native
   host is connected. (`tail -f /tmp/gps-host.log` shows `wrapper invoked` when it connects.)

**Prove a field (the part you demo):**
3. Browse to a signed page, e.g. `https://172.18.0.50/account` (or `/balancepage`). The extension
   captures the RFC 9421-signed response automatically.
4. Open the GPS popup → **Select a value on the page**. Then **click the label first** (e.g.
   "Account Balance"), then **click the value** (e.g. `2500.00`). This builds the anchored
   selector `anchored:"Account Balance"->number(w=300)`: the label anchors the extraction and the
   guest re-runs it in-circuit, so the host cannot substitute a value.
5. Enter a **predicate** and press Enter / **Generate ZK Proof**:
   - numeric: `> 1000`, `>= 500`, `== 2500.00`
   - text: `== "Alice Smith"`, `contains "Caixa"`
   - the proof reveals only whether the predicate holds (for `>`/`>=` it does **not** reveal the value).
6. Proving runs locally (~2 min on CPU). When it finishes, **Download Proof** (a `proof.json`).

**Verify what you captured** (real STARK check):
```bash
GPS_KEY_REGISTRY=$PWD/nginx/keys/gps-keys.json bin/gps-host verify --proof ~/Downloads/proof.json
```
or open `verifier.html` and drop the file in. A browser-captured proof carries the same
`image_id` (`50e385ca`), `binding:"in-circuit"`, `dev_mode:false`, and the `field_selected` rule.

**Other fields/pages to try** (the demo index is `https://172.18.0.50/`):
| Page | Field to click | Example predicate | Proves |
|------|----------------|-------------------|--------|
| `/account` | "Account Balance" → number | `> 1000` | balance over a threshold (value hidden) |
| `/balancepage` | "Saldo" → number | `> 1000` | the same, in European number formatting |
| `/mypage` | "Titular" → name | `== "Antonio Silva"` | the account holder's name |
| `/account` | "Account Holder" → name | `== "Alice Smith"` | a second field in one proof |
| `/comprovativo.pdf` | "Contribuinte sob o nº" → number | `== 500 960 046` | a field extracted from a signed **PDF** |

> The `/mypage` and `/balancepage` demo pages were rewritten on 2026-09-07. They previously served
> verbatim saved copies of a real bank's site, which were removed before publication. The labels
> above are the ones the current pages carry, so a **fresh capture** uses them. The **shipped**
> `session_multipage` still holds the older signed body and its committed rule reads
> `anchored:"Caixadirecta, "`, because a signed body cannot be edited without destroying the
> signature the cross-page proof rests on. `reproduce.sh` therefore keeps the original pattern.

A two-field proof: select one field, add a predicate, then **+ Add field**, select another, add its
predicate, and Generate, both are bound and proven in a single receipt.

Health check: `cat /tmp/gps-host.log` (look for "wrapper invoked"). Native messaging uses stdout as the
protocol pipe, so the host writes diagnostics only to stderr (a stray stdout line drops the connection).

**Sandboxed Firefox (the host won't connect).** Native messaging fails under a sandboxed
Firefox, **firejail, Snap (Ubuntu's default), or Flatpak**: because the sandbox cannot spawn
`~/.local/bin/gps-host-wrapper.sh` (and Snap/Flatpak also look for the host manifest under a
different directory). Symptoms: the GPS popup dot stays grey and `/tmp/gps-host.log` shows no
"wrapper invoked". Fixes: run the **unsandboxed** binary (e.g. `/usr/lib/firefox/firefox`, or set
`GPS_FF_BIN` for `launch.sh`); or use a non-Snap Firefox (`apt install` the `.tar.bz2` build, or the
Flatpak with `flatpak override --filesystem=home --talk-name=...`). **None of this is needed for the
headless evaluation**, `reproduce.sh build/verify/proofs/timing` produce and check proofs without the
browser; the extension flow only demonstrates live in-browser capture.

## 10. Reproducing on another PC
Prerequisites: **Rust/cargo**, **python3**, **jq**, **curl** (always); **Docker with BuildKit/
buildx** (the reproducible guest build, see below, also runs the demo server); **firefox**
(extension), **taskset** (pinned timing).
```bash
cd gps   # this folder
./reproduce.sh env        # check tools
./reproduce.sh quick      # build+image_id, verify, soundness            (~12 min)
./reproduce.sh cycles     # per-operation cycle table                    (~10 min)
./reproduce.sh proofs     # regenerate the 4 real proofs                 (~15–20 min)
./reproduce.sh expected   # reference numbers to compare against
```
**Reproducible image_id (Docker).** The guest is built inside the pinned
`risczero/risc0-guest-builder` image, so `reproduce.sh build` yields the **same** `image_id`
(`50e385ca…`) on any machine. This needs Docker with **BuildKit**. If `docker buildx version`
fails, install the buildx plugin (e.g. `pacman -S docker-buildx`, or drop the release binary in
`~/.docker/cli-plugins/docker-buildx`) and the build runs with `DOCKER_BUILDKIT=1`. To skip Docker
and build locally instead, set `RISC0_SKIP_DOCKER=1`: the build still works but its `image_id`
is environment-specific and will **not** equal `50e385ca…` (so the shipped proofs are then verified
with the prebuilt `bin/gps-host`, and proofs you generate are verified with your own build).

The first `cargo build` pulls RISC Zero and takes longer (it compiles memory-heavy C++ prover
kernels, on a machine with little RAM and no swap, build with `cargo build -j2` to avoid the OOM
killer). Real proving needs ≈7 GB free RAM (2-field/PDF) and is CPU-only; a 4 GB GPU is not usable
for RISC Zero 3.x.

## 11. Where every paper number comes from
The paper itself is not part of this code bundle, but every measured number in it is
reproduced here, table by table:

- **Table 6.2, soundness suite:** `./reproduce.sh soundness` (§7).
- **Table 6.4, per-operation costs:** `./reproduce.sh cycles` (§7), by user-cycle differencing.
- **Table 6.3, proving cost:** `./reproduce.sh proofs` / `timing` (§7).
- **Table 6.7, verification:** `./reproduce.sh verify` (§7).

The artifact `image_id` (`50e385ca…`, dissertation Appendix A) is asserted by `./reproduce.sh build`,
which proves the source in this tree reproduces the shipped artifacts.

## 12. File map
```
reproduce.sh            ← run/test/validate everything (start here)
GUIDE.md                ← this file
launch.sh               ← bring up demo server + install native host
generate_keys.sh        ← regenerate the leaf signing key
docker-compose.yml      ← gps-server service
proofs/                 ← proof_1field/2field/pdf_nif/multipage.json (real, 50e385ca)
benchmarks/             ← run_measurements.sh (n=10 campaign) + measurement notes
tests/adversarial/      ← run_suite.sh (13-case soundness) + RESULTS.md
bin/                    ← prebuilt gps-host (+ attack-sim build used by the suite)
zkvm/                   ← gps-core, methods/guest (security core), host, risc0-verifier
gps-server/             ← OpenResty RFC 9421 signer (HTML + PDF) + mock pages
nginx/keys/             ← leaf + GPS root keypairs + gps-keys.json registry
sessions/               ← sample sessions (signed responses) captured by the extension
extension/              ← Firefox extension + native-host install.sh + manifest
verifier.html           ← browser proof inspector (real verify via verify-serve)
```

---
*Authoritative state: this tree. Guest `image_id`: `50e385ca…`.*
