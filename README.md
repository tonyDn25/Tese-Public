# GPS: General Privacy-preserving web proof System

Prove to a third party that a browser observed a specific field value on a
signed HTTPS page, without revealing the rest of the page, using a
zero-knowledge (STARK) proof. No trusted hardware, no online third party, and no
server change beyond RFC 9421 response signing.

This folder is the code needed to **build, run, and verify** GPS end to end. The
full walkthrough (problem, pipeline, glossary, trust model, measured results,
how to run/test/validate) is in **[`GUIDE.md`](GUIDE.md)**; everything is driven
by **[`reproduce.sh`](reproduce.sh)**.

## Current version

| | |
|---|---|
| Guest image_id | `50e385cac9acdd6b9cc3e6c21a19daf33d6d817cad32d5fe7fe17d2728eddcd0` (sound in-circuit anchored binding + distributed trust) |
| Trust anchor | pinned **GPS root** key → root-signed leaf-key registry, all verified in-circuit |
| Field binding | **in-circuit**: the host's value is re-extracted inside the zkVM and asserted equal; a forged value or registry entry aborts (no proof) |
| 1-field proof | 133 s CPU (n=10 pinned mean), seal ~525 KB, tier 2²⁰, peak ~6.9 GB RAM (`GPS_SEGMENT_PO2=19`) |
| 2-field proof | 141 s CPU (n=10 pinned mean), seal ~526 KB, tier 2²⁰ (1→2 fields is nearly free) |
| Verification | real STARK via `gps-host verify` / `risc0-verifier` / `verify-serve` (browser); 20–170 ms |

## Keys in this repository, and why they are here

**Every key in this repository is a throwaway demo key. None of them protects anything.**
They are committed deliberately, because the artifact would not be reproducible without them:

| File | What it is |
|---|---|
| `nginx/keys/gps_root_private.pem` | The **GPS root** signing key. Signs registry entries. |
| `nginx/keys/nginx_private.pem` | The demo origin's **leaf** key. Signs each HTTP response. |
| `gps-server/certs/*-key.pem` | TLS key for the local demo host `172.18.0.50`. |

The root is not rotatable. Its **public** half is a compile-time constant in the guest
(`zkvm/methods/guest/src/main.rs`), so it is part of the image identifier
`50e385ca…` that every shipped proof verifies against. Changing the root changes the guest,
changes the image identifier, and invalidates those proofs. Shipping the private half is what
lets anyone re-sign the registry, add an origin, and regenerate the proofs from source.

**The consequence, stated plainly: because the root private key is public, anyone can mint a
registry entry that verifies under this image identifier.** That is fine for a demonstration and
fatal for a deployment. A real deployment generates its own root, keeps the private half offline
(the dissertation's §4.6 treats root custody as load-bearing), and compiles its own guest, which
gives it a different image identifier that verifiers trust instead of this one.

## Key properties
- **Distributed trust**: the guest pins a long-lived **GPS root** key and trusts any
  origin leaf key the root signed into a registry (`/.well-known/gps-keys`), all
  verified in-circuit. Rotating or adding an origin leaf key keeps the same image_id;
  a forged registry entry is rejected and no proof is produced.
- **Real verifier**: `gps-host verify-serve` runs genuine `receipt.verify()`; the
  browser `verifier.html` calls it and reports the true STARK result (and falls
  back to an explicitly-labelled journal-only inspection when offline).
- **Sound by construction**: a missing session or page aborts (no silent fallback),
  age is calendar-correct, and the attack-simulation hook is compiled out of the
  default binary.

## Layout

```
reproduce.sh          run/test/validate everything (start here)
GUIDE.md              full guide (project, run, test, validate, glossary)
launch.sh             bring up the demo server + install the native host
generate_keys.sh      regenerate the leaf signing key
docker-compose.yml    gps-server service (172.18.0.50)
verifier.html         browser proof inspector (real verify via verify-serve)
zkvm/                 RISC Zero workspace: gps-core, methods/guest (security core),
                      host (gps-host CLI), risc0-verifier
bin/                  prebuilt gps-host (+ attack-sim build used by the soundness suite)
proofs/               four real proofs (dev_mode:false, 50e385ca)
sessions/             sample signed-response sessions captured by the extension
gps-server/           OpenResty (Nginx + Lua) RFC 9421 signer (HTML + PDF) + mock pages
nginx/keys/           leaf + GPS root keypairs + gps-keys.json registry
extension/            Firefox MV3 extension + native-host install.sh + manifest
tests/adversarial/    13-case soundness suite (run_suite.sh) + RESULTS.md
benchmarks/           n=10 timing campaign + measurement notes
```

## Quick start

```bash
./reproduce.sh             # list commands + expected reference numbers
./reproduce.sh quick       # build + image_id check, verify proofs, soundness (~12 min)
```

> **Cloning from GitHub?** The `bin/` prebuilt binaries and `zkvm/target/` are
> **not** in the repo (git-ignored to keep it lightweight). Run `./reproduce.sh build`
> **first**: it compiles the zkVM host, asserts the guest `image_id` equals
> `50e385ca…`, and produces `zkvm/target/release/host`, which every other command
> falls back to. (In the `.tar.gz` bundle, `bin/gps-host` ships prebuilt so `verify`
> works without a rebuild.)

`reproduce.sh build` recompiles the zkVM and asserts the guest `image_id` equals
`50e385ca…`, proving the source in this tree reproduces the shipped artifacts.

```bash
# Verify a shipped proof (real STARK check, no daemon):
GPS_KEY_REGISTRY=$PWD/nginx/keys/gps-keys.json \
  bin/gps-host verify --proof proofs/proof_1field.json

# Guest soundness logic, fast (no RISC Zero proving needed):
cd zkvm/gps-core && cargo test

# Bring up the signing server + browser flow:
./extension/install.sh     # installs gps-host + native-messaging manifest
./launch.sh                # starts server + verify-serve, prints the rest
```

## What is proven (and what is not)

**Proven, in zero knowledge:** the page was served under a key the **GPS root
vouches for** (root signature over the registry entry + leaf signature, both
verified in-circuit); the body was not altered after signing (content-digest
checked in-circuit); the proven field equals an in-circuit re-extraction of the
audited selection rule; and the predicate holds, all under the specific
`image_id`. The page body itself is never revealed.

**Not proven (prototype scope):**
- **Real-world truth.** GPS proves provenance + integrity, not correctness: an
  honest-but-wrong origin can sign a false value into a valid proof.
- **Registry scope.** One root, an offline + HTTP registry; expiry is carried but
  revocation / transparency-log are future work.
- **TLS channel.** Integrity rests on the RFC 9421 application-layer signature over
  the response, not on the transport.
- **Field identity.** The value is the **first match** of the named pattern in the
  signed body; the verifier audits label uniqueness (see `GUIDE.md` §5 and the
  soundness suite cases B/C/D).
- **Offline `verifier.html`** is a journal-only inspector unless `verify-serve` is
  running (a browser-native WASM verifier is future work).

## Licence

Apache License 2.0, see [`LICENSE`](LICENSE). **In this tree the licence covers the code only.**
The dissertation (`theses-skilled/`, `thesis/`), the extended abstract and the paper drafts are
academic work, not offered for redistribution.

The licence covers the code, scripts and documentation here. It does **not**
relicense two pieces of third-party material that are published so the measured
results stay verifiable:

- `gps-server/html/realwebsite/comprovativo.pdf`, a redacted operations receipt
  whose layout and corporate footer originate with Caixa Geral de Depositos, S.A.
  It carries no personal data; the account, date and identifier fields are empty.
- `sessions/*.json`, which embed the signed response bodies the proofs were
  generated over. **A signed body cannot be edited without destroying the content
  digest its signature covers**, and with it the proof, so they are published as
  captured.

Both are here because without them the proofs in `proofs/` cannot be reproduced,
which is what this repository is for.
