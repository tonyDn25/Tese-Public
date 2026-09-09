use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use gps_core::{Extractor, ProofReceipt, ProofRequest, Session, SignedKeyEntry, Transcript};
use methods::{GPS_GUEST_ELF, GPS_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::fs;
use std::io::{Read, Write};

/// Load the root-signed key registry passed to the guest. Resolution order:
/// $GPS_KEY_REGISTRY, then a few conventional locations.
fn load_registry() -> Result<Vec<SignedKeyEntry>> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(p) = std::env::var("GPS_KEY_REGISTRY") { candidates.push(p); }
    candidates.push("nginx/keys/gps-keys.json".to_string());
    if let Some(h) = dirs::home_dir() {
        candidates.push(h.join(".config/gps/gps-keys.json").to_string_lossy().into_owned());
    }
    for c in candidates {
        if let Ok(raw) = fs::read_to_string(&c) {
            let reg: Vec<SignedKeyEntry> = serde_json::from_str(&raw)
                .with_context(|| format!("parsing key registry {}", c))?;
            eprintln!("  key registry: {} ({} entries)", c, reg.len());
            return Ok(reg);
        }
    }
    anyhow::bail!("no GPS key registry found, set GPS_KEY_REGISTRY or place nginx/keys/gps-keys.json")
}

#[derive(Parser)]
#[command(name = "gps-host", about = "GPS, ZK Proof Host")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Prove {
        /// Path to session_*.json OR transcript_*.json (default for all fields)
        #[arg(long)] session: String,
        /// URL to target within session (default for all fields)
        #[arg(long, default_value = "/")] url: String,
        /// Can be specified multiple times for multi-field proofs
        #[arg(long)] field: Vec<String>,
        /// One per --field
        #[arg(long)] predicate: Vec<String>,
        /// Per-field session override (parallel to --field; overrides --session for that field)
        #[arg(long)] field_session: Vec<String>,
        /// Per-field URL override (parallel to --field; overrides --url for that field)
        #[arg(long)] field_url: Vec<String>,
        /// Per-field numeric convention for an ordering predicate whose extractor
        /// does not name one itself (the regex and JSON paths): plain | eu | us.
        /// Parallel to --field. The anchored number extractor carries its own and
        /// ignores this.
        #[arg(long)] number_format: Vec<String>,
        /// Use Bonsai remote prover (requires BONSAI_API_KEY env var)
        #[arg(long)] bonsai: bool,
        #[arg(long)] output: Option<String>,
    },
    NativeMsg,
    Verify { #[arg(long)] proof: String },
    /// Check a committed value in the journal against a value you expect.
    /// The other half of hiding equality operands: the journal shows `h:<hex>`,
    /// and a verifier who knows what they are checking confirms it here.
    VerifyValue {
        #[arg(long)] proof:  String,
        #[arg(long)] expect: String,
        #[arg(long)] salt:   String,
    },
    /// Check that a proof's committed body hash really is a commitment to a body
    /// you hold. This is the provenance-on-demand half of the salted commitment:
    /// the journal alone no longer reveals which page a proof came from, and the
    /// prover restores that link, to whoever they choose, by handing over the salt.
    VerifyProvenance {
        #[arg(long)] proof: String,
        #[arg(long)] body:  String,
        /// Hex salt from the `<proof>.salt` sidecar. Omit for a legacy unsalted proof.
        #[arg(long)] salt:  Option<String>,
    },
    /// Run a localhost HTTP service that performs REAL STARK verification, so the
    /// browser inspector can verify proofs cryptographically (not just read them).
    VerifyServe {
        #[arg(long, default_value = "127.0.0.1:8788")] addr: String,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Prove { session, url, field, predicate, field_session, field_url, number_format, bonsai, output } =>
            run_prove_multi(&session, &url, &field, &predicate, &field_session, &field_url,
                            &number_format, bonsai, output.as_deref()),
        Command::NativeMsg => run_native_messaging(),
        Command::Verify { proof } => run_verify(&proof),
        Command::VerifyValue { proof, expect, salt } => run_verify_value(&proof, &expect, &salt),
        Command::VerifyProvenance { proof, body, salt } =>
            run_verify_provenance(&proof, &body, salt.as_deref()),
        Command::VerifyServe { addr } => run_verify_serve(&addr),
    }
}

// -- Load either a session file or a single transcript file ----------------

fn load_session(path: &str) -> Result<Session> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Cannot read: {}", path))?;

    // Try session first
    let session_err = match serde_json::from_str::<Session>(&raw) {
        Ok(s) => return Ok(s),
        Err(e) => e,
    };

    // Fall back to single transcript, wrap it in a session
    let t: Transcript = serde_json::from_str(&raw)
        .with_context(|| format!(
            "File is neither a valid Session (session parse error: {}) nor a valid Transcript",
            session_err
        ))?;

    Ok(Session {
        session_id: t.id.clone(),
        domain: t.domain.clone(),
        started_at: t.timestamp.clone(),
        ended_at: t.timestamp.clone(),
        pages: vec![t],
    })
}

// -- CLI prove -------------------------------------------------------------

fn run_prove_multi(
    session_path: &str,
    target_url: &str,
    fields: &[String],
    predicates: &[String],
    field_sessions: &[String],
    field_urls: &[String],
    number_formats: &[String],
    bonsai: bool,
    output_path: Option<&str>,
) -> Result<()> {
    if fields.is_empty() {
        anyhow::bail!("At least one --field is required");
    }
    if fields.len() != predicates.len() {
        anyhow::bail!(
            "Number of --field ({}) must match number of --predicate ({})",
            fields.len(), predicates.len()
        );
    }

    if bonsai {
        match std::env::var("BONSAI_API_KEY") {
            Ok(_) => {
                std::env::set_var("RISC0_PROVER", "bonsai");
                println!("  Using Bonsai remote prover");
            }
            Err(_) => anyhow::bail!(
                "--bonsai requires BONSAI_API_KEY to be set.\n\
                 Get a key at: https://dev.risczero.com/api/generating-proofs/remote-proving"
            ),
        }
    }

    // Build FieldRequest list, per-field session/url override via --field-session / --field-url
    let field_requests: Vec<gps_core::FieldRequest> = fields.iter().zip(predicates.iter())
        .enumerate()
        .map(|(i, (field_str, pred))| {
            let (extractor, label) = parse_field_spec(field_str);
            let sess = field_sessions.get(i).filter(|s| !s.is_empty())
                .map(|s| s.as_str()).unwrap_or(session_path);
            let furl = field_urls.get(i).filter(|u| !u.is_empty())
                .map(|s| s.as_str()).unwrap_or(target_url);
            let nf = number_formats.get(i).filter(|s| !s.is_empty())
                .map(|s| parse_number_format(s)
                    .unwrap_or_else(|| panic!("--number-format '{s}': expected plain, eu or us")));
            gps_core::FieldRequest {
                extractor,
                predicate: pred.clone(),
                field_label:  label,
                session_path: sess.to_string(),
                extracted_value: String::new(),
                target_url:   furl.to_string(),
                number_format: nf,
            }
        })
        .collect();

    // Fresh per proof. Private input: it goes to the guest and never to the journal.
    let body_salt_hex = fresh_body_salt()?;

    let request = ProofRequest {
        fields:      field_requests.clone(),
        extractor:   Default::default(),
        predicate:   String::new(),
        field_label: String::new(),
        target_url:  target_url.to_string(),
        body_salt_hex: body_salt_hex.clone(),
    };

    // Sessions are loaded further down, keyed off `seen_paths`; an earlier
    // duplicate of that de-duplication lived here and was never read.

    println!("{}", "-".repeat(46));
    println!("  GPS: ZK Proof Generator");
    println!("{}", "-".repeat(46));
    println!("  File     : {}", session_path);
    println!("  URL      : {}", target_url);
    for (i, (f, p)) in fields.iter().zip(predicates.iter()).enumerate() {
        println!("  Field {} : {}", i+1, f);
        println!("  Pred  {} : {}", i+1, p);
    }
    println!(" Generating ZK proof...");

    // Pre-extract values on host to avoid regex cost in zkVM
    let request = ProofRequest {
        fields: pre_extract_values(request.fields),
        ..request
    };

    // Load all unique sessions needed across all fields
    let mut seen_paths = std::collections::HashSet::new();
    let mut sessions: Vec<Session> = Vec::new();
    seen_paths.insert(session_path.to_string());
    sessions.push(load_session(session_path)?);
    for fr in &request.fields {
        if !fr.session_path.is_empty() && seen_paths.insert(fr.session_path.clone()) {
            sessions.push(load_session(&fr.session_path)?);
        }
    }

    let registry = load_registry()?;

    match run_proof(&sessions, &request, &registry) {
        Ok((receipt, image_id, elapsed, seal_b64, proof_size, dev_mode)) => {
            let out = build_output_json(&receipt, &seal_b64, &image_id, elapsed, proof_size, dev_mode);

            // Print multi-field results
            println!("{}", "-".repeat(46));
            println!("  PROOF RECEIPT");
            println!("{}", "-".repeat(46));
            println!("  Domain   : {}", receipt.server_domain);
            println!("  Timestamp: {}", receipt.server_timestamp);

            if !receipt.field_results.is_empty() {
                for fr in &receipt.field_results {
                    let icon = if fr.predicate_result { "OK" } else { "FAIL" };
                    println!("  {} {}: {}", icon,
                        fr.field_label.chars().take(30).collect::<String>(),
                        fr.predicate_statement.chars().take(60).collect::<String>()
                    );
                }
            } else {
                println!("  Statement: {}", receipt.predicate_statement);
                let icon = if receipt.predicate_result { "TRUE" } else { "FALSE" };
                println!("  Result   : {}", icon);
            }

            println!("  Session  : {}", receipt.session_id);
            println!("  Anchor   : {}", receipt.trust_anchor);
            println!("  Image ID : {}", image_id);
            println!();
            println!("{}", serde_json::to_string_pretty(&out)?);

            if let Some(path) = output_path {
                fs::write(path, serde_json::to_string_pretty(&out)?)?;
                // The salt is written BESIDE the proof, never inside it. Putting it
                // in the proof would hand every verifier the preimage and undo the
                // whole point. Keeping it lets the prover demonstrate provenance
                // later, to whoever they choose, by revealing it then.
                let salt_path = format!("{path}.salt");
                fs::write(&salt_path, format!("{body_salt_hex}\n"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&salt_path, fs::Permissions::from_mode(0o600));
                }
                eprintln!("  body salt written to {salt_path} (keep it; it is not in the proof)");
                println!(" Saved to: {}", path);
            }
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// A fresh 128-bit salt for the journal's body commitment, hex-encoded.
///
/// Read straight from the OS entropy pool. No crate is added for this: the
/// dependency surface of the prover is worth keeping small, and 16 bytes from
/// `/dev/urandom` is exactly what a `rand` call would ultimately do here.
///
/// `GPS_BODY_SALT` overrides it, which exists so measurements and regression
/// tests can be reproducible. Using it in earnest defeats the purpose, because
/// a salt reused across proofs restores the linkability the salt removes.
fn fresh_body_salt() -> anyhow::Result<String> {
    if let Ok(v) = std::env::var("GPS_BODY_SALT") {
        if !v.is_empty() {
            gps_core::parse_salt(&v).map_err(|e| anyhow::anyhow!("GPS_BODY_SALT: {}", e))?;
            eprintln!("  body salt: taken from GPS_BODY_SALT (reproducible; do not use for real proofs)");
            return Ok(v);
        }
    }
    use std::io::Read;
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| anyhow::anyhow!("cannot read /dev/urandom for the body salt: {e}"))?;
    Ok(hex::encode(buf))
}

/// Recompute a proof's body commitment from a body the caller holds, plus the
/// salt if the proof is salted, and report whether they match.
///
/// Note what this deliberately does NOT do: it says nothing about the proof's
/// validity, which is `verify`'s job. It answers one narrow question, whether
/// this proof was built over this artefact, and it can only be asked by someone
/// the prover chose to give the salt to.
/// Confirm that a `h:<hex>` commitment in the journal is a commitment to
/// `expect`, under the proof's salt.
///
/// Scans both places a value can be committed: the predicate operand and the
/// anchored literal in the extraction rule. Reports which one matched, because
/// they mean different things: the rule tells you what was read, the predicate
/// tells you what was asserted about it.
fn run_verify_value(proof_path: &str, expect: &str, salt_hex: &str) -> Result<()> {
    let proof: serde_json::Value = serde_json::from_str(&fs::read_to_string(proof_path)?)?;
    let journal = proof.get("journal").ok_or_else(|| anyhow::anyhow!("proof has no journal"))?;
    let salt = gps_core::parse_salt(salt_hex).map_err(|e| anyhow::anyhow!(e))?
        .ok_or_else(|| anyhow::anyhow!("a salt is required to check a committed value"))?;

    let pre = gps_core::value_commitment_preimage(Some(&salt), expect)
        .ok_or_else(|| anyhow::anyhow!("no salt"))?;
    let want = {
        use sha2::{Digest, Sha256};
        format!("h:{}", hex::encode(Sha256::digest(&pre)))
    };

    let rule = journal.get("field_selected").and_then(|v| v.as_str()).unwrap_or("");
    let pred = journal.get("predicate_statement").and_then(|v| v.as_str()).unwrap_or("");

    println!("  proof     : {proof_path}");
    println!("  expecting : {expect:?}");
    println!("  commitment: {want}");
    let in_rule = rule.contains(&want);
    let in_pred = pred.contains(&want);
    if in_rule { println!("  MATCH in the extraction rule   : this is the value the guest read from the signed page."); }
    if in_pred { println!("  MATCH in the predicate         : this is the value the proof asserts."); }
    if in_rule || in_pred { Ok(()) } else {
        println!("  NO MATCH. Either the value differs, or the salt is not this proof's.");
        println!("  rule      : {rule}");
        println!("  predicate : {pred}");
        std::process::exit(1);
    }
}

fn run_verify_provenance(proof_path: &str, body_path: &str, salt: Option<&str>) -> Result<()> {
    let proof: serde_json::Value = serde_json::from_str(&fs::read_to_string(proof_path)?)?;
    let body = fs::read(body_path)?;

    let journal = proof.get("journal").ok_or_else(|| anyhow::anyhow!("proof has no journal"))?;
    let committed = journal.get("body_hash").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("journal has no body_hash"))?;

    let parsed = gps_core::parse_salt(salt.unwrap_or("")).map_err(|e| anyhow::anyhow!(e))?;
    let scheme = gps_core::commitment_scheme(parsed.as_deref());
    let recomputed = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(gps_core::commitment_preimage(parsed.as_deref(), &body)))
    };

    println!("  proof     : {proof_path}");
    println!("  body      : {body_path} ({} bytes)", body.len());
    println!("  scheme    : {scheme}");
    println!("  committed : {committed}");
    println!("  recomputed: {recomputed}");
    if committed == recomputed {
        println!("  RESULT    : MATCH. This proof was built over this body.");
        Ok(())
    } else {
        // Being specific about the likely cause beats a bare mismatch, because the
        // overwhelmingly common one is the salt, not a different body.
        if parsed.is_none() {
            println!("  RESULT    : NO MATCH. The proof may be salted; pass --salt from the sidecar.");
        } else {
            println!("  RESULT    : NO MATCH. Different body, or the wrong salt.");
        }
        std::process::exit(1);
    }
}

fn build_output_json(receipt: &ProofReceipt, seal_b64: &str, image_id: &str,
                     elapsed: f64, proof_size: usize, dev_mode: bool) -> serde_json::Value {
    serde_json::json!({
        "seal": seal_b64,
        "journal": {
            "server_domain":       receipt.server_domain,
            "server_timestamp":    receipt.server_timestamp,
            "predicate_statement": receipt.predicate_statement,
            "predicate_result":    receipt.predicate_result,
            "field_selected":      receipt.field_selected,
            "trust_anchor":        receipt.trust_anchor,
            "ciphertext_hash":     receipt.ciphertext_hash,
            "session_id":          receipt.session_id,
            "target_url":          receipt.target_url,
            "body_hash":           receipt.body_hash,
            "binding":             receipt.binding,
            "field_results":       receipt.field_results.iter().map(|fr| serde_json::json!({
                "field_label":         fr.field_label,
                "field_selected":      fr.field_selected,
                "predicate_statement": fr.predicate_statement,
                "predicate_result":    fr.predicate_result,
            })).collect::<Vec<_>>(),
        },
        "image_id": image_id,
        "metadata": {
            "proof_generation_time": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "program_version": "2.0.0",
            "proof_size_bytes": proof_size,
            "dev_mode": dev_mode,
            "proof_time_seconds": elapsed,
        }
    })
}

/// Accept the short names a person types for a numeric convention. Deliberately
/// small: three named readings, and no default, because the whole point of the
/// 2026-09-09 fix is that an unnamed convention is refused rather than assumed.
fn parse_number_format(s: &str) -> Option<gps_core::NumberFormat> {
    match s.trim().to_ascii_lowercase().as_str() {
        "plain" | "iso"                  => Some(gps_core::NumberFormat::Plain),
        "eu" | "eugrouped" | "european"  => Some(gps_core::NumberFormat::EuGrouped),
        "us" | "usgrouped"               => Some(gps_core::NumberFormat::UsGrouped),
        _ => None,
    }
}

fn parse_field_spec(field: &str) -> (Extractor, String) {
    if field.starts_with("regex:") {
        let rest = field.trim_start_matches("regex:");
        let (pattern, label) = if let Some(pos) = rest.find("|||") {
            (rest[..pos].to_string(), rest[pos+3..].to_string())
        } else {
            (rest.to_string(), rest.to_string())
        };
        // Path A′: if the pattern is the common "anchor + bounded gap + capture"
        // shape, lower it to the cheap, sound Anchored extractor. Anything else
        // falls back to the (sound but expensive) full in-circuit regex.
        match regex_to_anchored(&pattern) {
            Some((anchor, window, kind)) => (Extractor::Anchored { anchor, window, kind }, label),
            None => (Extractor::Regex(pattern), label),
        }
    } else {
        (Extractor::JsonPath(field.to_string()), field.to_string())
    }
}

/// Undo the regex escaping `content.js` applies to a literal value, so the
/// literal can be lowered to the anchored extractor instead of falling back to
/// the in-circuit regex.
///
/// This matters more than it looks. `escapeRegex` inserts a backslash before
/// any of `.*+?^${}()|[]\\`, and the previous lowering rejected any `inner`
/// containing a regex metacharacter, backslashes included. So every value with
/// a full stop in it fell back to the 8.4M-cycle path: names with an initial
/// ("A. Di Nunzio"), email addresses, company names ("Acme Lda."), addresses,
/// international phone numbers. The escaping existed only because the value was
/// being embedded in a regex, and the anchored `Literal` extractor does a raw
/// byte search, so the escaping is not merely unnecessary there, it is wrong.
///
/// Returns `None` when the string contains a backslash sequence `escapeRegex`
/// would never produce, or an unescaped metacharacter, since either means this
/// is a real pattern rather than an escaped literal and must keep the regex path.
fn unescape_literal(inner: &str) -> Option<String> {
    const ESCAPABLE: &str = "\\^$.|?*+()[]{}";
    let mut out = String::with_capacity(inner.len());
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            let n = it.next()?;
            if !ESCAPABLE.contains(n) { return None; }
            out.push(n);
        } else if ESCAPABLE.contains(c) {
            return None;
        } else {
            out.push(c);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Lower a regex of the exact shape `(?s)?<ANCHOR>.{0,<N>}?(<GROUP>)` to an
/// Anchored extractor, where <ANCHOR> is a plain literal and <GROUP> is a numeric
/// token, a named date shape, or a plain (possibly regex-escaped) literal.
/// Returns None otherwise, so unrecognised patterns keep the general regex path.
/// Both paths are sound; they differ only in cost.
fn regex_to_anchored(pattern: &str) -> Option<(String, usize, gps_core::AnchoredKind)> {
    let p = pattern.strip_prefix("(?s)").unwrap_or(pattern);
    let gap_idx = p.find(".{0,")?;
    // The anchor is a regex-escaped label, and it has to be unescaped for the same
    // reason the captured literal does: the anchored extractor finds it by a raw
    // byte search, so the escaping is not merely unnecessary there, it is what used
    // to prevent the lowering. Section 6.12 of the dissertation reports that defect
    // for the captured VALUE and fixes it; the identical fix was never applied to
    // the anchor, and the coverage corpus could not see it because every label in it
    // is a plain word. A label carrying punctuation, "Balance (EUR)" or "N.I.F.",
    // therefore dropped the whole field onto the in-circuit regular expression at
    // roughly ten times the cycles. Found 2026-09-09 by running the browser flow.
    let anchor = unescape_literal(&p[..gap_idx])?;
    let anchor = anchor.as_str();
    let rest = &p[gap_idx + ".{0,".len()..];
    let brace = rest.find('}')?;
    let window: usize = rest[..brace].parse().ok()?;
    let after = rest[brace + 1..].strip_prefix('?').unwrap_or(&rest[brace + 1..]);
    let inner = after.strip_prefix('(')?.strip_suffix(')')?;
    // content.js emits bare literals, e.g. `(Alice Smith)`. A future or alternate
    // pattern generator may word-bound them as `(\bAlice Smith\b)`: strip a single
    // leading and trailing `\b` (and only that) so the literal still lowers to
    // Anchored(Literal) instead of falling back to the expensive full-regex path.
    // The `\b` is a zero-width assertion, so the captured value is unchanged.
    let inner = inner.strip_prefix("\\b").unwrap_or(inner);
    let inner = inner.strip_suffix("\\b").unwrap_or(inner);
    // Both the unsigned `[0-9][0-9.,]*` and the signed `[+-]?[0-9][0-9.,]*` token
    // (the shape content.js emits for numbers) lower to the same Anchored Number
    // extractor. `extract_anchored` matches the optional leading sign and includes
    // it in the value, so negative quantities are preserved, this is why folding
    // `[+-]?` in is now sound (it was previously refused because the unsigned
    // extractor would have silently dropped the sign). See [[KI-19]].
    // Date patterns lower to the anchored Date extractor rather than falling back
    // to the in-circuit regex. Before this, every date field cost ~8.4M cycles
    // (KI-20); it now costs the same as a number. The mapping is on the exact
    // shapes content.js emits, so an unrecognised date pattern still falls back
    // rather than being guessed at.
    let date_kind = match inner {
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}" => Some(gps_core::DateFormat::Iso),
        r"[0-9]{4}/[0-9]{2}/[0-9]{2}" => Some(gps_core::DateFormat::IsoSlash),
        r"[0-9]{2}/[0-9]{2}/[0-9]{4}" => Some(gps_core::DateFormat::DmySlash),
        r"[0-9]{2}-[0-9]{2}-[0-9]{4}" => Some(gps_core::DateFormat::DmyDash),
        r"[0-9]{2}\.[0-9]{2}\.[0-9]{4}" => Some(gps_core::DateFormat::DmyDot),
        _ => None,
    };
    // Number patterns name their convention the way date patterns name theirs.
    // The old catch-all shape `[+-]?[0-9][0-9.,]*` said only "some digits and
    // separators" and left the guest to guess which convention they were
    // written in, which is the defect fixed on 2026-09-09. It no longer lowers,
    // so a stale pattern falls back to the in-circuit regex and the request has
    // to declare a convention explicitly for an ordering predicate to run at all.
    let number_kind = match inner {
        r"[+-]?[0-9]+(\.[0-9]+)?"                       => Some(gps_core::NumberFormat::Plain),
        r"[+-]?[0-9]{1,3}(\.[0-9]{3})+(,[0-9]+)?"       => Some(gps_core::NumberFormat::EuGrouped),
        r"[+-]?[0-9]+,[0-9]+"                           => Some(gps_core::NumberFormat::EuGrouped),
        r"[+-]?[0-9]{1,3}(,[0-9]{3})+(\.[0-9]+)?"       => Some(gps_core::NumberFormat::UsGrouped),
        _ => None,
    };
    // `unescape_literal` rejects a leftover metacharacter, so an anchor that is a
    // real pattern rather than an escaped label still keeps the regex path.
    let kind = if let Some(f) = date_kind {
        gps_core::AnchoredKind::Date(f)
    } else if let Some(f) = number_kind {
        gps_core::AnchoredKind::Number(f)
    } else if let Some(lit) = unescape_literal(inner) {
        gps_core::AnchoredKind::Literal(lit)
    } else {
        return None;
    };
    Some((anchor.to_string(), window, kind))
}

// -- Shared proof executor ------------------------------------------------
fn run_proof(sessions: &Vec<Session>, request: &ProofRequest, registry: &Vec<SignedKeyEntry>)
    -> Result<(ProofReceipt, String, f64, String, usize, bool)>
{
    let dev_mode = std::env::var("RISC0_DEV_MODE").unwrap_or_default() == "1";
    // Bound peak proving memory via RISC Zero continuations: cap each segment at
    // 2^po2 cycles so a large execution splits into segments instead of OOM-ing.
    // Set GPS_SEGMENT_PO2 (e.g. 19 or 20) on memory-constrained machines.
    let mut builder = ExecutorEnv::builder();
    // Guest reads, in order: sessions, request, key registry.
    builder.write(sessions)?.write(request)?.write(registry)?;
    // Segment cap. Every measured number in the dissertation was produced at 2^19,
    // and running without a cap is not a milder configuration: RISC Zero's default
    // needs several times the memory, so on a 16 GB machine the prover is OOM-killed
    // mid-proof and dies with nothing on stderr. That is indistinguishable, from the
    // caller's side, from a transport fault. Default to the documented value rather
    // than to the failure, and say which one is in force.
    const DEFAULT_SEGMENT_PO2: u32 = 19;
    let po2 = match std::env::var("GPS_SEGMENT_PO2").ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
    {
        Some(v) => v,
        None => {
            eprintln!("  GPS_SEGMENT_PO2 unset, defaulting to {DEFAULT_SEGMENT_PO2} \
(the value every measurement in the dissertation uses); export it to override");
            DEFAULT_SEGMENT_PO2
        }
    };
    builder.segment_limit_po2(po2);
    eprintln!("  segment_limit_po2 = {}", po2);
    let env = builder.build()?;
    let start = std::time::Instant::now();
    let prove_info = default_prover().prove(env, GPS_GUEST_ELF)?;
    let elapsed = start.elapsed().as_secs_f64();
    let receipt = prove_info.receipt;
    let total_cycles = prove_info.stats.total_cycles;
    eprintln!("  zkVM total cycles: {}", total_cycles);
    receipt.verify(GPS_GUEST_ID)?;
    let proof_receipt: ProofReceipt = receipt.journal.decode()?;
    let image_id = GPS_GUEST_ID.iter().map(|x| format!("{:08x}", x)).collect::<String>();
    let receipt_bytes = bincode::serialize(&receipt)?;
    let proof_size = receipt_bytes.len();
    let seal_b64 = base64::engine::general_purpose::STANDARD.encode(&receipt_bytes);
    Ok((proof_receipt, image_id, elapsed, seal_b64, proof_size, dev_mode))
}

// -- Native messaging ------------------------------------------------------

fn run_native_messaging() -> Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        match std::io::stdin().read_exact(&mut len_buf) {
            Ok(_) => {} Err(_) => break,
        }
        let msg_len = u32::from_le_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; msg_len];
        std::io::stdin().read_exact(&mut msg_buf)?;
        let request: serde_json::Value = serde_json::from_slice(&msg_buf)
            .unwrap_or(serde_json::json!({"error": "invalid json"}));
        let mut response = handle_native_request(&request);
        // Echo the request's "_id" into the reply so background.js can route it to
        // the exact pending callback. Without this, every reply lacks an _id and
        // falls through to the FIFO fallback, where a slow/out-of-order reply can
        // steal another request's callback. The FIFO fallback is kept for compat.
        if let (Some(id), Some(obj)) = (request.get("_id"), response.as_object_mut()) {
            obj.insert("_id".to_string(), id.clone());
        }
        let rb = serde_json::to_vec(&response)?;
        std::io::stdout().write_all(&(rb.len() as u32).to_le_bytes())?;
        std::io::stdout().write_all(&rb)?;
        std::io::stdout().flush()?;
    }
    Ok(())
}

/// The guest resolves a field by comparing its target against `Transcript.request.path`,
/// so whatever reaches `ProofRequest.target_url` has to be a path. A caller that passes
/// a full URL (the browser extension did) can never match, and the guest aborts with
/// "URL not found in session" -- correct behaviour on input it should never have been
/// given. Normalise at this boundary rather than in the guest, whose bytes are the
/// image_id and cannot be touched without invalidating every shipped proof.
fn url_to_path(u: &str) -> String {
    if let Some(i) = u.find("://") {
        let rest = &u[i + 3..];
        return match rest.find('/') {
            Some(j) => rest[j..].to_string(),
            None => "/".to_string(),
        };
    }
    if u.is_empty() { return "/".to_string(); }
    if u.starts_with('/') { u.to_string() } else { format!("/{u}") }
}

#[cfg(test)]
mod url_path_tests {
    use super::url_to_path;
    #[test]
    fn full_urls_reduce_to_their_path() {
        assert_eq!(url_to_path("https://172.18.0.50/account"), "/account");
        assert_eq!(url_to_path("https://h/a/b"), "/a/b");
        assert_eq!(url_to_path("https://172.18.0.50"), "/");
    }
    #[test]
    fn paths_and_oddities_pass_through() {
        assert_eq!(url_to_path("/account"), "/account");
        assert_eq!(url_to_path("account"), "/account");
        assert_eq!(url_to_path(""), "/");
    }
    #[test]
    fn the_query_string_is_left_for_the_guest_to_split() {
        // find_target_page() already splits on '?'; keep the behaviour identical.
        assert_eq!(url_to_path("https://h/a?b=1"), "/a?b=1");
    }
}

fn handle_native_request(request: &serde_json::Value) -> serde_json::Value {
    if request.get("ping").is_some() {
        return serde_json::json!({ "pong": true, "version": "2.0.0" });
    }
    let action = request.get("action").and_then(|a| a.as_str()).unwrap_or("");

    if action == "list_sessions" {
        let dir = request.get("dir").and_then(|d| d.as_str()).unwrap_or("");
        return list_sessions(dir);
    }
    if action == "read_body" {
        let path = request.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let url  = request.get("url").and_then(|v| v.as_str()).unwrap_or("/");
        return read_body(path, url);
    }

    if action == "analyze_field" {
        return analyze_field_with_agent(request);
    }

    if action == "save_session" {
        let session_val = match request.get("session") {
            Some(s) => s.clone(),
            None => return serde_json::json!({ "ok": false, "error": "missing session" }),
        };
        return save_session_from_json(session_val);
    }

    let path = match request.get("session").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return serde_json::json!({ "ok": false, "error": "missing 'session'" }),
    };
    let url      = url_to_path(request.get("url").and_then(|v| v.as_str()).unwrap_or("/"));
    let dev_mode = request.get("dev_mode").and_then(|v| v.as_bool()).unwrap_or(false);
    if dev_mode {
        std::env::set_var("RISC0_DEV_MODE", "1");
    } else {
        std::env::remove_var("RISC0_DEV_MODE");
    }

    // Fresh per proof, as in the CLI path. A failure here must abort: falling back
    // to an unsalted commitment would silently hand the verifier an enumerable
    // fingerprint of the page, and the user could not tell.
    let body_salt_hex = match fresh_body_salt() {
        Ok(s) => s,
        Err(e) => return serde_json::json!({ "ok": false, "error": format!("body salt: {e}") }),
    };

    // Load all unique sessions needed by the fields
    let proof_request = if let Some(fields_arr) = request.get("fields").and_then(|v| v.as_array()) {
        let field_requests: Vec<gps_core::FieldRequest> = fields_arr.iter().filter_map(|f| {
            let field_str    = f.get("field").and_then(|v| v.as_str())?;
            let pred         = f.get("predicate").and_then(|v| v.as_str())?;
            let field_url    = f.get("url").and_then(|v| v.as_str())
                                 .map(url_to_path).unwrap_or_else(|| url.clone());
            let session_path = f.get("session").and_then(|v| v.as_str()).unwrap_or(&path);
            let (extractor, label) = parse_field_spec(field_str);
            let nf = f.get("number_format").and_then(|v| v.as_str())
                        .and_then(parse_number_format);
            Some(gps_core::FieldRequest {
                extractor,
                predicate:    pred.to_string(),
                field_label:  label,
                extracted_value: String::new(),
                session_path: session_path.to_string(),
                target_url:   field_url,
                number_format: nf,
            })
        }).collect();
        if field_requests.is_empty() {
            return serde_json::json!({ "ok": false, "error": "fields array is empty or malformed" });
        }
        // Pre-extract values on host side to avoid regex cost in zkVM guest
        let field_requests = pre_extract_values(field_requests);
        ProofRequest {
            fields:      field_requests,
            extractor:   Default::default(),
            predicate:   String::new(),
            field_label: String::new(),
            target_url:  url.clone(),
            body_salt_hex: body_salt_hex.clone(),
        }
    } else {
        let field = match request.get("field").and_then(|v| v.as_str()) {
            Some(f) => f.to_string(),
            None => return serde_json::json!({ "ok": false, "error": "missing 'field'" }),
        };
        let predicate = match request.get("predicate").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return serde_json::json!({ "ok": false, "error": "missing 'predicate'" }),
        };
        let (extractor, field_label) = parse_field_spec(&field);
        let single_fields = pre_extract_values(vec![gps_core::FieldRequest {
            extractor,
            predicate,
            field_label,
            session_path:    path.clone(),
            target_url:      url.clone(),
            extracted_value: String::new(),
            number_format:   request.get("number_format").and_then(|v| v.as_str())
                                .and_then(parse_number_format),
        }]);
        ProofRequest {
            fields: single_fields,
            extractor:   Default::default(),
            predicate:   String::new(),
            field_label: String::new(),
            target_url:  url.clone(),
            body_salt_hex: body_salt_hex.clone(),
        }
    };

    // Collect all unique session paths and load them
    let session_paths: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        proof_request.fields.iter()
            .map(|f| if f.session_path.is_empty() { path.clone() } else { f.session_path.clone() })
            .filter(|p| seen.insert(p.clone()))
            .collect()
    };
    let mut sessions: Vec<Session> = Vec::new();
    for sp in &session_paths {
        match load_session(sp) {
            Ok(s) => sessions.push(s),
            Err(e) => return serde_json::json!({ "ok": false, "error": format!("load session '{}': {}", sp, e) }),
        }
    }

    let registry = match load_registry() {
        Ok(r) => r,
        Err(e) => return serde_json::json!({ "ok": false, "error": e.to_string() }),
    };

    match run_proof(&sessions, &proof_request, &registry) {
        Ok((receipt, image_id, elapsed, seal_b64, proof_size, dm)) => {
            let out = build_output_json(&receipt, &seal_b64, &image_id, elapsed, proof_size, dm);
            serde_json::json!({ "ok": true, "proof": out })
        }
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
    }
}

fn pre_extract_values(fields: Vec<gps_core::FieldRequest>) -> Vec<gps_core::FieldRequest> {
    // `mut` is required by the `attack-sim` build at the end of this function, which
    // rewrites field 0's hint. The default build never mutates `out`, so the warning is
    // correct there and wrong everywhere else: do NOT take `cargo fix`'s suggestion to
    // drop the `mut`, it breaks bin/gps-host-attacksim and soundness cases A and E.
    #[cfg_attr(not(feature = "attack-sim"), allow(unused_mut))]
    let mut out: Vec<gps_core::FieldRequest> = fields.into_iter().map(|mut f| {
        if !f.extracted_value.is_empty() { return f; }
        if f.session_path.is_empty() { return f; }
        // Compute the value hint on the host with the SAME logic the guest uses,
        // so the guest's in-circuit binding assertion is satisfied. (For PDF and
        // unparsed bodies the hint may be empty; the guest extraction is still
        // authoritative.)
        let session = match load_session(&f.session_path) { Ok(s) => s, Err(_) => return f };
        // KI-21: only hint from the EXACT target page. No silent "last signed page"
        // fallback, a wrong-page hint would either mismatch the guest's in-circuit
        // value (confusing "binding violated") or, worse, look plausible. If the URL
        // isn't found, leave the hint empty; the guest extraction stays authoritative.
        let target = session.pages.iter().find(|p| {
            let page_path = p.request.path.split('?').next().unwrap_or(&p.request.path);
            let target_path = f.target_url.split('?').next().unwrap_or(&f.target_url);
            page_path == target_path
        });
        let page = match target { Some(p) => p, None => return f };
        let body = &page.response.body;
        match &f.extractor {
            gps_core::Extractor::Anchored { anchor, window, kind } => {
                if let Some(v) = gps_core::extract_anchored(body, anchor, *window, kind) {
                    f.extracted_value = v;
                }
            }
            gps_core::Extractor::Regex(pattern) => {
                if let Ok(re) = regex::RegexBuilder::new(pattern)
                    .dot_matches_new_line(true).build() {
                    if let Some(caps) = re.captures(body) {
                        if let Some(m) = caps.get(1).or_else(|| caps.get(0)) {
                            f.extracted_value = m.as_str().to_string();
                        }
                    }
                }
            }
            _ => {}
        }
        f
    }).collect();
    // KI-23: the forged-value attack simulator is gated behind a build feature so it
    // is NOT compiled into the default/production binary. Build with
    // `--features attack-sim` to exercise the negative test (it only mutates the host
    // hint; the guest's in-circuit binding rejects it → "Field binding violated").
    #[cfg(feature = "attack-sim")]
    if let Ok(forged) = std::env::var("GPS_SIM_FORGE_VALUE") {
        if let Some(f0) = out.first_mut() {
            eprintln!("  [attack-sim] forcing field 0 extracted_value = '{}'", forged);
            f0.extracted_value = forged;
        }
    }
    out
}

fn list_sessions(dir: &str) -> serde_json::Value {
    let dir = if dir.is_empty() {
        dirs::home_dir().unwrap_or_default().join(".config/gps/sessions")
    } else { std::path::PathBuf::from(dir) };

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => return serde_json::json!({ "ok": false, "error": e.to_string() }),
    };

    let mut results = vec![];

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }

        let is_session    = name.starts_with("session_");
        let is_transcript = name.starts_with("transcript_");
        if !is_session && !is_transcript { continue; }

        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(session) = load_session_from_str(&raw) {
                if session.signed_count() > 0 {
                    let pages: Vec<_> = session.pages.iter().map(|p| serde_json::json!({
                        "path": p.request.path,
                        "signed": p.has_signature(),
                        "timestamp": p.timestamp,
                    })).collect();
                    results.push(serde_json::json!({
                        "path": path.to_string_lossy(),
                        "session_id": session.session_id,
                        "domain": session.domain,
                        "started_at": session.started_at,
                        "pages": pages,
                        "signed_count": session.signed_count(),
                        "type": if is_session { "session" } else { "transcript" },
                    }));
                }
            }
        }
    }

    results.sort_by(|a, b| b["started_at"].as_str().unwrap_or("")
        .cmp(a["started_at"].as_str().unwrap_or("")));
    serde_json::json!({ "ok": true, "sessions": results })
}

fn load_session_from_str(raw: &str) -> Result<Session> {
    if let Ok(s) = serde_json::from_str::<Session>(raw) { return Ok(s); }
    let t: Transcript = serde_json::from_str(raw)?;
    Ok(Session {
        session_id: t.id.clone(),
        domain: t.domain.clone(),
        started_at: t.timestamp.clone(),
        ended_at: t.timestamp.clone(),
        pages: vec![t],
    })
}

fn read_body(path: &str, url: &str) -> serde_json::Value {
    let raw = match fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) => return serde_json::json!({ "ok": false, "error": e.to_string() }),
    };
    match load_session_from_str(&raw) {
        Ok(s) => {
            let target_path = url.split('?').next().unwrap_or(url);
            let page = s.pages.iter().find(|p| {
                p.request.path.split('?').next().unwrap_or(&p.request.path) == target_path
            }).or_else(|| s.pages.iter().filter(|p| p.has_signature()).last());
            match page {
                Some(p) => serde_json::json!({ "ok": true, "body": p.response.body }),
                None => serde_json::json!({ "ok": false, "error": "page not found" }),
            }
        }
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
    }
}

fn run_verify(proof_input: &str) -> Result<()> {
    use risc0_zkvm::Receipt;

    // Accept either a proof JSON file or a raw base64 seal string
    let (seal_b64, dev_mode_warned) = if std::path::Path::new(proof_input).exists() {
        let raw = fs::read_to_string(proof_input)?;
        // Try parsing as proof JSON first
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
            let seal = json["seal"].as_str()
                .ok_or_else(|| anyhow::anyhow!("proof JSON missing 'seal' field"))?
                .to_string();
            let is_dev = json["metadata"]["dev_mode"].as_bool().unwrap_or(false);
            if is_dev {
                eprintln!("  [!]  WARNING: proof has dev_mode=true, so it is not cryptographically binding");
            }
            (seal, is_dev)
        } else {
            (raw.trim().to_string(), false)
        }
    } else {
        (proof_input.to_string(), false)
    };

    let receipt: Receipt = bincode::deserialize(
        &base64::engine::general_purpose::STANDARD.decode(&seal_b64)
            .map_err(|e| anyhow::anyhow!("Bad base64 in seal: {}", e))?
    ).map_err(|e| anyhow::anyhow!("Cannot deserialize receipt: {}", e))?;

    println!("----------------------------------------------");
    println!(" GPS: STARK Proof Verifier");
    println!("----------------------------------------------");
    print!(" Verifying STARK seal against GPS image_id... ");

    receipt.verify(GPS_GUEST_ID).map_err(|e| {
        println!("FAILED");
        anyhow::anyhow!("Verification failed: {}", e)
    })?;

    println!("VALID");
    println!("----------------------------------------------");

    let r: ProofReceipt = receipt.journal.decode()?;
    println!(" Domain   : {}", r.server_domain);
    println!(" Timestamp: {}", r.server_timestamp);
    println!(" Session  : {}", r.session_id);
    println!(" Anchor   : {}", r.trust_anchor);
    if !r.field_results.is_empty() {
        for fr in &r.field_results {
            let icon = if fr.predicate_result { "OK" } else { "FAIL" };
            println!(" {} {}: {}", icon, fr.field_label, fr.predicate_statement);
        }
    } else {
        println!(" Statement: {}", r.predicate_statement);
        println!(" Result   : {}", if r.predicate_result { "TRUE" } else { "FALSE" });
    }
    if dev_mode_warned {
        println!(" [!]  Dev mode: the seal is not a real STARK proof");
    }
    println!("----------------------------------------------");
    Ok(())
}

// -- Real verifier service (browser-callable) --------------------------------
// A tiny localhost HTTP service that performs GENUINE STARK verification
// (`receipt.verify(GPS_GUEST_ID)`), so verifier.html can verify cryptographically
// instead of only displaying the journal. Pure std (no web framework). CORS-open so
// the page works from file://.

/// Real verification of a base64 seal: returns the decoded journal iff the STARK
/// seal verifies against this guest's image_id. Shared by the CLI and the service.
fn verify_seal_b64(seal_b64: &str) -> Result<ProofReceipt> {
    use risc0_zkvm::Receipt;
    let bytes = base64::engine::general_purpose::STANDARD.decode(seal_b64.trim())
        .map_err(|e| anyhow::anyhow!("bad base64 in seal: {}", e))?;
    let receipt: Receipt = bincode::deserialize(&bytes)
        .map_err(|e| anyhow::anyhow!("cannot deserialize receipt: {}", e))?;
    receipt.verify(GPS_GUEST_ID).map_err(|e| anyhow::anyhow!("STARK verification failed: {}", e))?;
    Ok(receipt.journal.decode()?)
}

fn run_verify_serve(addr: &str) -> Result<()> {
    use std::net::TcpListener;
    let image_id: String = GPS_GUEST_ID.iter().map(|x| format!("{:08x}", x)).collect();
    let listener = TcpListener::bind(addr)
        .with_context(|| format!("cannot bind {}", addr))?;
    println!("GPS real verifier service on http://{}", addr);
    println!("  image_id: {}", image_id);
    println!("  POST a proof JSON (or raw seal) to /verify for a real STARK result.");
    for stream in listener.incoming() {
        let mut stream = match stream { Ok(s) => s, Err(_) => continue };
        if let Err(e) = handle_http_conn(&mut stream, &image_id) {
            eprintln!("  conn error: {}", e);
        }
    }
    Ok(())
}

fn handle_http_conn(stream: &mut std::net::TcpStream, image_id: &str) -> Result<()> {
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(stream.try_clone()?);
    // Request line
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 { return Ok(()); }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let _path = parts.next().unwrap_or("/").to_string();
    // Headers
    let mut content_len = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 { break; }
        if h == "\r\n" || h == "\n" { break; }
        let hl = h.to_ascii_lowercase();
        if let Some(v) = hl.strip_prefix("content-length:") {
            content_len = v.trim().parse().unwrap_or(0);
        }
    }
    let cors = "Access-Control-Allow-Origin: *\r\n\
                Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
                Access-Control-Allow-Headers: Content-Type\r\n";

    if method == "OPTIONS" {
        return write_http(stream, "204 No Content", cors, "application/json", "");
    }
    if method == "GET" {
        let body = serde_json::json!({ "service": "gps-verify", "image_id": image_id }).to_string();
        return write_http(stream, "200 OK", cors, "application/json", &body);
    }
    if method != "POST" {
        return write_http(stream, "405 Method Not Allowed", cors, "application/json",
            r#"{"valid":false,"error":"use POST"}"#);
    }
    // Read body
    let mut body = vec![0u8; content_len];
    reader.read_exact(&mut body)?;
    let raw = String::from_utf8_lossy(&body).to_string();
    // Accept either a proof JSON {seal,...} or a raw base64 seal
    let (seal, dev_mode) = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(j) => (
            j["seal"].as_str().unwrap_or("").to_string(),
            j["metadata"]["dev_mode"].as_bool().unwrap_or(false),
        ),
        Err(_) => (raw.trim().to_string(), false),
    };
    let resp = if seal.is_empty() {
        serde_json::json!({ "valid": false, "error": "no seal provided" })
    } else {
        match verify_seal_b64(&seal) {
            Ok(journal) => serde_json::json!({
                "valid": true,
                "dev_mode": dev_mode,
                "image_id": image_id,
                "verified_by": "risc0 receipt.verify (real STARK)",
                "journal": {
                    "server_domain": journal.server_domain,
                    "trust_anchor": journal.trust_anchor,
                    "binding": journal.binding,
                    "field_results": journal.field_results.iter().map(|fr| serde_json::json!({
                        "field_label": fr.field_label,
                        "predicate_statement": fr.predicate_statement,
                        "predicate_result": fr.predicate_result,
                    })).collect::<Vec<_>>(),
                }
            }),
            Err(e) => serde_json::json!({ "valid": false, "error": e.to_string() }),
        }
    };
    write_http(stream, "200 OK", cors, "application/json", &resp.to_string())
}

fn write_http(stream: &mut std::net::TcpStream, status: &str, extra_headers: &str,
              content_type: &str, body: &str) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{}",
        status, content_type, body.len(), extra_headers, body
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn save_session_from_json(session_val: serde_json::Value) -> serde_json::Value {
    let filename_override = session_val.get("filename")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let session: Session = match serde_json::from_value(session_val.clone()) {
        Ok(s) => s,
        Err(_) => {
            match session_val.get("session")
                .and_then(|v| serde_json::from_value::<Session>(v.clone()).ok())
            {
                Some(s) => s,
                None => return serde_json::json!({ "ok": false, "error": "invalid session JSON" }),
            }
        }
    };

    let dir = dirs::home_dir()
        .unwrap_or_default()
        .join(".config/gps/sessions");
    let _ = std::fs::create_dir_all(&dir);

    let filename = filename_override.unwrap_or_else(|| {
        let domain_safe = session.domain
            .replace(':', "_").replace('/', "_").replace('.', "_");
        format!("session_direct_{}_{}.json", domain_safe, &session.session_id[..8])
    });
    let path = dir.join(&filename);

    match serde_json::to_string_pretty(&session) {
        Ok(json) => match std::fs::write(&path, json) {
            Ok(_) => serde_json::json!({ "ok": true, "path": path.to_string_lossy() }),
            Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
        },
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
    }
}

fn analyze_field_with_agent(request: &serde_json::Value) -> serde_json::Value {
    let html_context = request.get("html_context").and_then(|v| v.as_str()).unwrap_or("");
    let label_text   = request.get("label_text").and_then(|v| v.as_str()).unwrap_or("");
    let value_text   = request.get("value_text").and_then(|v| v.as_str()).unwrap_or("");
    let body         = request.get("body").and_then(|v| v.as_str()).unwrap_or("");

    let value_type = if value_text.match_indices(|c: char| c.is_ascii_digit()).count() > 0 {
        if value_text.contains('-') && value_text.len() == 10 { "date YYYY-MM-DD" }
        else { "numeric" }
    } else if value_text == "true" || value_text == "false" { "boolean" }
    else { "text" };

    let prompt = format!(
        "You generate regex patterns for Rust regex crate. Rules: no lookahead/lookbehind, \
        no backslash-d (use [0-9]), no backreferences, use (?s) for dotall if needed.\n\n\
        HTML context (snippet around the value):\n{html_context}\n\n\
        Label text: {label_text}\n\
        Value text: {value_text}\n\
        Value type: {value_type}\n\n\
        Generate ONE regex with exactly one capture group that captures the value.\n\
        The pattern must work in Rust regex crate.\n\
        Reply with ONLY the regex pattern, nothing else.",
        html_context = &html_context[..html_context.len().min(500)],
        label_text = label_text,
        value_text = value_text,
        value_type = value_type,
    );

    let ollama_req = serde_json::json!({
        "model": "phi3:mini",
        "prompt": prompt,
        "stream": false,
        "options": { "temperature": 0.1, "num_predict": 100 }
    });

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build() {
        Ok(c) => c,
        Err(e) => return serde_json::json!({ "ok": false, "error": e.to_string() }),
    };

    let resp = match client
        .post("http://localhost:11434/api/generate")
        .json(&ollama_req)
        .send() {
        Ok(r) => r,
        Err(e) => return serde_json::json!({ "ok": false, "error": format!("Ollama unreachable: {}", e) }),
    };

    let resp_json: serde_json::Value = match resp.json() {
        Ok(j) => j,
        Err(e) => return serde_json::json!({ "ok": false, "error": e.to_string() }),
    };

    let pattern = resp_json["response"]
        .as_str()
        .unwrap_or("")
        .trim()
        .trim_matches('`')
        .trim()
        .to_string();

    if pattern.is_empty() {
        return serde_json::json!({ "ok": false, "error": "Empty pattern from LLM" });
    }

    let pattern = pattern
        .replace("\\s", "[ \t\n\r]")
        .replace("\\S", "[^ \t\n\r]")
        .replace("\\d", "[0-9]")
        .replace("\\D", "[^0-9]")
        .replace("\\w", "[a-zA-Z0-9_]")
        .replace("\\W", "[^a-zA-Z0-9_]")
        .replace("\\/", "/");

    match regex::Regex::new(&pattern) {
        Err(e) => serde_json::json!({
            "ok": false,
            "error": format!("LLM generated invalid regex: {}", e),
            "pattern": pattern
        }),
        Ok(re) => {
            if !body.is_empty() {
                match re.captures(body) {
                    Some(caps) => {
                        let extracted = caps.get(1)
                            .or_else(|| caps.get(0))
                            .map(|m| m.as_str())
                            .unwrap_or("");
                        let num_extracted = extracted.chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == ',').collect::<String>();
                        let num_expected  = value_text.chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == ',').collect::<String>();
                        let matches_value = extracted.contains(value_text) ||
                            (!num_expected.is_empty() && num_extracted.starts_with(&num_expected));
                        serde_json::json!({
                            "ok": true,
                            "pattern": pattern,
                            "extracted": extracted,
                            "matches_expected": matches_value,
                            "source": "llm"
                        })
                    }
                    None => serde_json::json!({
                        "ok": false,
                        "error": "LLM pattern did not match body",
                        "pattern": pattern,
                        "source": "llm"
                    }),
                }
            } else {
                serde_json::json!({ "ok": true, "pattern": pattern, "source": "llm" })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{regex_to_anchored, handle_native_request, url_to_path};
    use gps_core::{AnchoredKind, DateFormat, NumberFormat};

    // -- The browser path (added 2026-09-07) --------------------------------
    //
    // Nothing in this suite exercised the path the extension actually uses, and
    // six defects lived there undetected while 65 tests and a full read of the
    // dissertation stayed green. The one that mattered most: the extension sent
    // `url` as a FULL URL while the guest matches `Transcript.request.path`, so
    // find_target_page() could never match and EVERY proof started from the
    // browser aborted, while the identical proof from the CLI succeeded.
    //
    // These drive `handle_native_request` with the exact JSON shape
    // extension/background/background.js builds, so that class of mismatch
    // cannot come back silently. They run in dev mode: the point is the request
    // plumbing, not the STARK, so they cost milliseconds rather than minutes.

    fn repo(rel: &str) -> String {
        // tests run with CWD = the crate dir (zkvm/host), the repo is two up
        format!("{}/../../{}", env!("CARGO_MANIFEST_DIR"), rel)
    }

    fn browser_shaped_prove(url: &str) -> serde_json::Value {
        std::env::set_var("RISC0_DEV_MODE", "1");
        std::env::set_var("GPS_KEY_REGISTRY", repo("nginx/keys/gps-keys.json"));
        handle_native_request(&serde_json::json!({
            "_id": 1,
            "session": repo("sessions/session_direct_172_18_0_50_4502b208.json"),
            "url": url,
            "dev_mode": true,
            // exactly what background.js sends for a single field
            "field": r"regex:Account Balance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)|||balance",
            "predicate": "> 1000"
        }))
    }

    #[test]
    fn a_full_url_from_the_extension_still_finds_the_page() {
        // The regression itself: this is what the browser sends.
        let r = browser_shaped_prove("https://172.18.0.50/account");
        assert_eq!(r["ok"], true, "browser-shaped prove failed: {}", r["error"]);
    }

    #[test]
    fn a_bare_path_from_the_cli_behaves_identically() {
        let r = browser_shaped_prove("/account");
        assert_eq!(r["ok"], true, "cli-shaped prove failed: {}", r["error"]);
    }

    #[test]
    fn the_journal_names_the_field_rather_than_echoing_the_pattern() {
        // The extension appends |||<label>; without it parse_field_spec falls back
        // to using the whole regex as the label, and the journal read
        // `field_label: "Account Balance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)"`.
        let r = browser_shaped_prove("https://172.18.0.50/account");
        let label = r["proof"]["journal"]["field_results"][0]["field_label"]
            .as_str().unwrap_or("");
        assert_eq!(label, "balance", "journal field_label should be the human label");
        assert!(!label.contains("{0,300}"), "the raw pattern leaked into the label");
    }

    #[test]
    fn an_unknown_page_is_refused_rather_than_guessed() {
        // KI-21: the guest must abort instead of falling back to another page.
        let r = browser_shaped_prove("https://172.18.0.50/does-not-exist");
        assert_eq!(r["ok"], false, "a page that is not in the session must not prove");
    }

    #[test]
    fn url_normalisation_covers_what_the_browser_can_send() {
        assert_eq!(url_to_path("https://172.18.0.50/account"), "/account");
        assert_eq!(url_to_path("/account"), "/account");
        assert_eq!(url_to_path("https://172.18.0.50"), "/");
    }

    // -- Date lowering (added 2026-09-05, KI-20) ----------------------------
    // Before this, every one of these fell through to Extractor::Regex and cost
    // ~8.4M cycles in-circuit. They now lower to the anchored path.

    #[test]
    fn lowers_iso_date() {
        let (anchor, window, kind) =
            regex_to_anchored(r"Issued.{0,300}?([0-9]{4}-[0-9]{2}-[0-9]{2})").unwrap();
        assert_eq!(anchor, "Issued");
        assert_eq!(window, 300);
        assert!(matches!(kind, AnchoredKind::Date(DateFormat::Iso)));
    }

    #[test]
    fn lowers_european_slash_date() {
        let (_, _, kind) =
            regex_to_anchored(r"Data.{0,300}?([0-9]{2}/[0-9]{2}/[0-9]{4})").unwrap();
        assert!(matches!(kind, AnchoredKind::Date(DateFormat::DmySlash)));
    }

    #[test]
    fn lowers_portuguese_dot_date() {
        let (_, _, kind) =
            regex_to_anchored(r"Validade.{0,300}?([0-9]{2}\.[0-9]{2}\.[0-9]{4})").unwrap();
        assert!(matches!(kind, AnchoredKind::Date(DateFormat::DmyDot)));
    }

    #[test]
    fn lowers_dash_dmy_date() {
        let (_, _, kind) =
            regex_to_anchored(r"Expiry.{0,300}?([0-9]{2}-[0-9]{2}-[0-9]{4})").unwrap();
        assert!(matches!(kind, AnchoredKind::Date(DateFormat::DmyDash)));
    }

    #[test]
    fn unrecognised_date_shape_still_falls_back_rather_than_guessing() {
        // A two-digit year is not one of the committed formats. Falling back to
        // the in-circuit regex is correct: guessing the century would bind a
        // value the page never stated.
        assert!(regex_to_anchored(r"Exp.{0,300}?([0-9]{2}/[0-9]{2}/[0-9]{2})").is_none());
    }

    #[test]
    fn lowers_number_token() {
        let (anchor, window, kind) =
            regex_to_anchored(r"Account Balance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)").unwrap();
        assert_eq!(anchor, "Account Balance");
        assert_eq!(window, 300);
        assert!(matches!(kind, AnchoredKind::Number(NumberFormat::Plain)));
    }

    /// Labels carrying punctuation, found 2026-09-09 by running the browser flow.
    ///
    /// The capture layer regex-escapes the label into the anchor, and the lowering
    /// used to refuse any anchor holding a metacharacter, so every one of these
    /// dropped the field onto the in-circuit regular expression: measured at
    /// 10{,}223{,}616 cycles against 1{,}048{,}576 for the anchored path on the same
    /// field, which is what a 24-minute proof looked like from the browser. This is
    /// the same defect Section 6.12 reports for the captured VALUE, in the half of
    /// the rule the fix never reached.
    #[test]
    fn a_label_carrying_punctuation_still_lowers() {
        for label in [r"Balance \(EUR\)", r"N\.I\.F\.", r"Total \(net\)",
                      r"Balance \[current\]", r"Mr\. Smith's balance", r"Saldo \+ juros"] {
            let pat = format!(r"{label}.{{0,300}}?([+-]?[0-9]+(\.[0-9]+)?)");
            let got = regex_to_anchored(&pat);
            assert!(got.is_some(), "{label} did not lower and would cost ~10x");
            let (anchor, _, kind) = got.unwrap();
            assert!(!anchor.contains('\\'), "anchor kept its escaping: {anchor}");
            assert!(matches!(kind, AnchoredKind::Number(NumberFormat::Plain)));
        }
        // The unescaped anchor has to be what the byte scan actually looks for.
        let (anchor, w, kind) = regex_to_anchored(
            r"Balance \(EUR\).{0,300}?([+-]?[0-9]+(\.[0-9]+)?)").unwrap();
        assert_eq!(anchor, "Balance (EUR)");
        assert_eq!(gps_core::extract_anchored("Balance (EUR): 2500.00", &anchor, w, &kind)
                   .as_deref(), Some("2500.00"));
    }

    /// An anchor that is a real pattern rather than an escaped label must still keep
    /// the regex path, or the lowering would silently change what is matched.
    #[test]
    fn an_anchor_that_is_a_real_pattern_does_not_lower() {
        assert!(regex_to_anchored(r"<div[^>]+>.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)").is_none());
        assert!(regex_to_anchored(r"Bal.*ance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)").is_none());
    }

    #[test]
    fn each_numeric_convention_lowers_to_its_own_kind() {
        let (_, _, k) = regex_to_anchored(r"Saldo.{0,300}?([+-]?[0-9]{1,3}(\.[0-9]{3})+(,[0-9]+)?)").unwrap();
        assert!(matches!(k, AnchoredKind::Number(NumberFormat::EuGrouped)));
        let (_, _, k) = regex_to_anchored(r"Saldo.{0,300}?([+-]?[0-9]+,[0-9]+)").unwrap();
        assert!(matches!(k, AnchoredKind::Number(NumberFormat::EuGrouped)));
        let (_, _, k) = regex_to_anchored(r"Total.{0,300}?([+-]?[0-9]{1,3}(,[0-9]{3})+(\.[0-9]+)?)").unwrap();
        assert!(matches!(k, AnchoredKind::Number(NumberFormat::UsGrouped)));
    }

    #[test]
    fn the_old_convention_free_number_shape_no_longer_lowers() {
        // `[0-9][0-9.,]*` says "digits and separators" and names no convention,
        // which is what let the guest guess. It must fall back rather than be
        // silently assigned a reading.
        assert!(matches!(regex_to_anchored("Account Balance.{0,300}?([0-9][0-9.,]*)"),
                         None | Some((_, _, AnchoredKind::Literal(_)))));
        assert!(regex_to_anchored("Account Balance.{0,300}?([+-]?[0-9][0-9.,]*)").is_none());
    }

    #[test]
    fn lowers_bare_literal() {
        // The shape content.js actually emits for a string value.
        let (anchor, window, kind) =
            regex_to_anchored("Account Holder.{0,300}?(Alice Smith)").unwrap();
        assert_eq!(anchor, "Account Holder");
        assert_eq!(window, 300);
        match kind {
            AnchoredKind::Literal(s) => assert_eq!(s, "Alice Smith"),
            _ => panic!("expected Literal, got {:?}", kind),
        }
    }

    #[test]
    fn lowers_word_bounded_literal() {
        // Defensive: a `\b`-wrapped literal must lower to the same Literal, with the
        // word-boundary assertions stripped and the captured value unchanged.
        let (_, _, kind) =
            regex_to_anchored("Name.{0,80}?(\\bAlice Smith\\b)").unwrap();
        match kind {
            AnchoredKind::Literal(s) => assert_eq!(s, "Alice Smith"),
            _ => panic!("expected Literal, got {:?}", kind),
        }
    }

    #[test]
    fn dotall_prefix_is_accepted() {
        // content.js / the host build patterns with a leading `(?s)` dotall flag.
        let r = regex_to_anchored(r"(?s)Saldo.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)");
        assert!(r.is_some());
    }

    #[test]
    fn meta_in_literal_falls_back() {
        // A literal carrying regex metacharacters cannot be a sound Literal, keep
        // the general regex path so the value is matched correctly.
        assert!(regex_to_anchored("Label.{0,50}?(a.b)").is_none());
    }

    #[test]
    fn signed_number_lowers() {
        // content.js emits a `[+-]?` sign prefix for numeric values. As of the
        // sign-aware Number extractor (KI-19), this lowers to Anchored(Number):
        // the optional sign is captured and kept, so negative values are preserved.
        let (anchor, window, kind) =
            regex_to_anchored(r"Balance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)").unwrap();
        assert_eq!(anchor, "Balance");
        assert_eq!(window, 300);
        assert!(matches!(kind, AnchoredKind::Number(NumberFormat::Plain)));
    }

    #[test]
    fn unsigned_number_still_lowers() {
        // The canonical/CLI token must still lower to a Number kind, now with
        // the convention named.
        let (_, _, kind) = regex_to_anchored(r"Saldo.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)").unwrap();
        assert!(matches!(kind, AnchoredKind::Number(NumberFormat::Plain)));
    }
    // -- Literals with punctuation (added 2026-09-05) -----------------------
    // Every one of these fell back to the in-circuit regex before, purely
    // because content.js had escaped a character for a regex the anchored
    // extractor does not use.

    #[test]
    fn lowers_name_with_an_initial() {
        let (anchor, _, kind) =
            regex_to_anchored(r"Holder.{0,300}?(A\. Di Nunzio)").unwrap();
        assert_eq!(anchor, "Holder");
        match kind { AnchoredKind::Literal(s) => assert_eq!(s, "A. Di Nunzio"),
                     other => panic!("expected Literal, got {:?}", other) }
    }

    #[test]
    fn lowers_email_address() {
        let (_, _, kind) = regex_to_anchored(r"Email.{0,300}?(alice@example\.com)").unwrap();
        match kind { AnchoredKind::Literal(s) => assert_eq!(s, "alice@example.com"),
                     other => panic!("expected Literal, got {:?}", other) }
    }

    #[test]
    fn lowers_company_name_with_trailing_stop() {
        let (_, _, kind) = regex_to_anchored(r"Empresa.{0,300}?(Acme Lda\.)").unwrap();
        match kind { AnchoredKind::Literal(s) => assert_eq!(s, "Acme Lda."),
                     other => panic!("expected Literal, got {:?}", other) }
    }

    #[test]
    fn lowers_phone_with_plus() {
        let (_, _, kind) = regex_to_anchored(r"Tel.{0,300}?(\+351 912 345 678)").unwrap();
        match kind { AnchoredKind::Literal(s) => assert_eq!(s, "+351 912 345 678"),
                     other => panic!("expected Literal, got {:?}", other) }
    }

    #[test]
    fn a_real_pattern_is_not_mistaken_for_an_escaped_literal() {
        // Unescaped metacharacters mean this is a genuine regex, so the regex
        // path must be kept rather than the value byte-searched.
        assert!(regex_to_anchored(r"Ref.{0,300}?([A-Z]+[0-9]*)").is_none());
    }

    #[test]
    fn lowers_iso_slash_date() {
        let (_, _, kind) =
            regex_to_anchored(r"Emitido.{0,300}?([0-9]{4}/[0-9]{2}/[0-9]{2})").unwrap();
        assert!(matches!(kind, AnchoredKind::Date(DateFormat::IsoSlash)));
    }

    // ======================================================================
    //  Anchored-extractor coverage study (added 2026-09-05).
    //
    //  FPS 2026 review R2 asked the one question this system could not answer:
    //  "what fraction of real-world web fields can actually be handled by the
    //  anchored extractor without falling back to the full in-circuit regular
    //  expression?"
    //
    //  The population they want sampled is not publicly samplable: credentialed
    //  pages are behind logins by definition. So the study is over FIELD TYPES
    //  rather than over pages, and it runs the real `valueToPattern` shapes
    //  through the real lowering and the real extractor. The figure this test
    //  prints is the code's behaviour, not a description of it, and it moves if
    //  the code moves.
    // ======================================================================

    /// One field type: the value a user would click, and the extractor kind the
    /// proof is supposed to bind.
    struct Cov { label: &'static str, value: &'static str, pattern: &'static str, want: &'static str }

    const CORPUS: &[Cov] = &[
        Cov{label:"account balance",   value:"2847.50",  pattern:r"Balance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)", want:"number"},
        Cov{label:"balance + currency",value:"2500.00 EUR", pattern:r"Saldo.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)", want:"number"},
        Cov{label:"negative balance",  value:"-650.50",  pattern:r"Balance.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)", want:"number"},
        Cov{label:"account number",    value:"123456789",pattern:r"Account.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)", want:"number"},
        Cov{label:"card last four",    value:"4242",     pattern:r"Card.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)", want:"number"},
        Cov{label:"percentage rate",   value:"3.75",     pattern:r"Rate.{0,300}?([+-]?[0-9]+(\.[0-9]+)?)", want:"number"},
        Cov{label:"holder name",       value:"Alice Smith", pattern:r"Holder.{0,300}?(Alice Smith)", want:"literal"},
        Cov{label:"name with initial", value:"A. Di Nunzio", pattern:r"Holder.{0,300}?(A\. Di Nunzio)", want:"literal"},
        Cov{label:"tax id (NIF)",      value:"500 960 046", pattern:r"NIF.{0,300}?(500 960 046)", want:"literal"},
        Cov{label:"IBAN",              value:"PT50000201231234567890154", pattern:r"IBAN.{0,300}?(PT50000201231234567890154)", want:"literal"},
        Cov{label:"boolean flag",      value:"true",     pattern:r"Active.{0,300}?(true)", want:"literal"},
        Cov{label:"employment status", value:"Permanent",pattern:r"Status.{0,300}?(Permanent)", want:"literal"},
        Cov{label:"policy number",     value:"POL-2026-0043", pattern:r"Policy.{0,300}?(POL-2026-0043)", want:"literal"},
        Cov{label:"address",           value:"Rua da Prata, 12", pattern:r"Morada.{0,300}?(Rua da Prata, 12)", want:"literal"},
        Cov{label:"email",             value:"alice@example.com", pattern:r"Email.{0,300}?(alice@example\.com)", want:"literal"},
        Cov{label:"phone",             value:"+351 912 345 678", pattern:r"Tel.{0,300}?(\+351 912 345 678)", want:"literal"},
        Cov{label:"company name",      value:"Acme Lda.", pattern:r"Empresa.{0,300}?(Acme Lda\.)", want:"literal"},
        Cov{label:"issue date ISO",    value:"2026-03-09", pattern:r"Emitido.{0,300}?([0-9]{4}-[0-9]{2}-[0-9]{2})", want:"date"},
        Cov{label:"expiry date EU",    value:"31/12/2027", pattern:r"Validade.{0,300}?([0-9]{2}/[0-9]{2}/[0-9]{4})", want:"date"},
        Cov{label:"date of birth",     value:"07/11/1999", pattern:r"Nascimento.{0,300}?([0-9]{2}/[0-9]{2}/[0-9]{4})", want:"date"},
    ];

    fn kind_name(k: &AnchoredKind) -> String {
        match k {
            AnchoredKind::Number(_)   => "number".into(),
            AnchoredKind::Literal(_)  => "literal".into(),
            AnchoredKind::Date(_)     => "date".into(),
        }
    }

    #[test]
    fn anchored_coverage_over_the_field_corpus() {
        let (mut lowered, mut correct) = (0usize, 0usize);
        let mut fallbacks: Vec<&str> = Vec::new();
        for c in CORPUS {
            match regex_to_anchored(c.pattern) {
                None => fallbacks.push(c.label),
                Some((anchor, window, kind)) => {
                    lowered += 1;
                    // The extractor must also return the value, not merely accept
                    // the pattern: a rule that lowers and then extracts nothing is
                    // an abort, not coverage.
                    let body = format!("{} {} end", anchor, c.value);
                    let got = gps_core::extract_anchored(&body, &anchor, window, &kind);
                    assert!(got.is_some(), "{}: lowered but extracted nothing", c.label);
                    assert_eq!(kind_name(&kind), c.want,
                        "{}: bound as {} but the field is a {}", c.label, kind_name(&kind), c.want);
                    correct += 1;
                }
            }
        }
        let n = CORPUS.len();
        eprintln!("anchored coverage: {}/{} lowered ({:.0}%), {}/{} bound the intended kind ({:.0}%)",
            lowered, n, 100.0*lowered as f64/n as f64, correct, n, 100.0*correct as f64/n as f64);
        if !fallbacks.is_empty() { eprintln!("fell back to in-circuit regex: {:?}", fallbacks); }
        // Regression floor. Before 2026-09-05 this stood at 12/20 correct, with
        // two further cases lowering to the WRONG kind (European dates bound the
        // day as a number). Do not let it slip back.
        assert_eq!(correct, n, "anchored coverage regressed");
    }

    /// The numeric twin of the date defect below, found on 2026-09-09.
    ///
    /// The old pipeline emitted one convention-free number pattern and the guest
    /// inferred a reading from whichever separators the value happened to carry.
    /// A page stating `5.500` was read as five and a half, so `< 1000` was true
    /// and a valid proof was emitted for a false statement. The value is never
    /// published, so no verifier could see it. The convention is now part of the
    /// rule and is committed with it.
    #[test]
    fn european_thousands_no_longer_read_as_a_decimal() {
        let (anchor, window, kind) =
            regex_to_anchored(r"Saldo.{0,300}?([+-]?[0-9]{1,3}(\.[0-9]{3})+(,[0-9]+)?)").unwrap();
        let got = gps_core::extract_anchored("Saldo: 5.500 EUR", &anchor, window, &kind).unwrap();
        assert_eq!(got, "5.500", "the page's own spelling is what gets bound");
        assert_eq!(gps_core::normalise_number(&got, NumberFormat::EuGrouped).as_deref(),
                   Some("5500"), "and it reads as five thousand five hundred, not 5.5");
        // Read under the wrong convention it is refused outright, rather than
        // being turned into a number a thousand times too small.
        assert_eq!(gps_core::normalise_number("2.847,50", NumberFormat::Plain), None);
        assert_eq!(gps_core::normalise_number("1,234.56", NumberFormat::Plain), None);
    }

    #[test]
    fn european_date_no_longer_binds_the_day_as_a_number() {
        // The defect this study uncovered: content.js did not recognise
        // DD/MM/YYYY as a date, so it fell through to the numeric branch and the
        // guest bound "31" out of "31/12/2027". Sound by the letter of the trust
        // model, and the wrong value by any reading a user intended.
        let (anchor, window, kind) =
            regex_to_anchored(r"Validade.{0,300}?([0-9]{2}/[0-9]{2}/[0-9]{4})").unwrap();
        let got = gps_core::extract_anchored("Validade: 31/12/2027 fim", &anchor, window, &kind);
        assert_eq!(got, Some("2027-12-31".to_string()));
    }

    /// The pre-2026-09-05 pipeline, reproduced exactly so the coverage
    /// improvement is measured against it rather than asserted.
    ///
    /// Old `valueToPattern` recognised a date only as `YYYY[-/]MM[-/]DD` and
    /// always emitted the dash form; old `regex_to_anchored` had no date arm and
    /// accepted a literal only when the regex-escaped value contained no
    /// metacharacter.
    fn old_pipeline(value: &str, anchor: &str) -> (Option<String>, &'static str) {
        const META: &str = "\\^$.|?*+()[]{}";
        let esc: String = value.chars()
            .flat_map(|c| if META.contains(c) { vec!['\\', c] } else { vec![c] })
            .collect();

        // --- old content.js valueToPattern, branch for branch, in order ---
        let b = value.as_bytes();
        let old_date = b.len() == 10
            && b[..4].iter().all(u8::is_ascii_digit)
            && matches!(b[4], b'-' | b'/') && matches!(b[7], b'-' | b'/')
            && b[5..7].iter().all(u8::is_ascii_digit)
            && b[8..].iter().all(u8::is_ascii_digit);
        let has_digit  = value.chars().any(|c| c.is_ascii_digit());
        let has_alpha  = value.chars().any(|c| c.is_ascii_alphabetic());
        // /^[+-]?[0-9][0-9.,]*\s*[A-Za-z]{0,3}$/
        let num_suffix = {
            let s = value.trim_end();
            let s = s.trim_end_matches(|c: char| c.is_ascii_alphabetic());
            let s = s.trim_end();
            !s.is_empty()
                && s.chars().next().is_some_and(|c| c.is_ascii_digit() || c == '+' || c == '-')
                && s.chars().skip(1).all(|c| c.is_ascii_digit() || c == '.' || c == ',')
                && s.chars().any(|c| c.is_ascii_digit())
        };
        // /[0-9]\s+[0-9]/
        let digit_space_digit = value.as_bytes().windows(3).any(|w|
            w[0].is_ascii_digit() && w[1] == b' ' && w[2].is_ascii_digit());

        let inner = if old_date {
            "[0-9]{4}-[0-9]{2}-[0-9]{2}".to_string()
        } else if value == "true" || value == "false" {
            value.to_string()
        } else if has_digit {
            if num_suffix { "[+-]?[0-9][0-9.,]*".to_string() }
            else if has_alpha || digit_space_digit { esc }
            // THE BRANCH THAT CAUSED THE DEFECT: anything else with a digit in it
            // and no letters, "31/12/2027" included, became a plain number.
            else { "[+-]?[0-9][0-9.,]*".to_string() }
        } else { esc };

        // --- old regex_to_anchored: no date arm, literals never unescaped ---
        let body = format!("{} {} end", anchor, value);
        if inner == "[0-9][0-9.,]*" || inner == "[+-]?[0-9][0-9.,]*" {
            // The old extractor named no convention. Plain reproduces what it did
            // to these corpus values, none of which carries a comma.
            (gps_core::extract_anchored(&body, anchor, 300,
                &AnchoredKind::Number(NumberFormat::Plain)), "number")
        } else if !inner.chars().any(|c| META.contains(c)) {
            (gps_core::extract_anchored(&body, anchor, 300, &AnchoredKind::Literal(inner)), "literal")
        } else {
            (None, "regex-fallback")
        }
    }

    #[test]
    fn coverage_before_and_after() {
        let (mut old_low, mut old_right, mut old_wrong) = (0usize, 0usize, 0usize);
        let mut silently_wrong: Vec<(&str, String)> = Vec::new();
        for c in CORPUS {
            let anchor = c.pattern.split(".{0,").next().unwrap();
            let (got, kind) = old_pipeline(c.value, anchor);
            if kind == "regex-fallback" { continue; }
            old_low += 1;
            if kind == c.want {
                old_right += 1;
            } else {
                old_wrong += 1;
                silently_wrong.push((c.label, format!("{:?} as {}", got, kind)));
            }
        }
        let n = CORPUS.len();
        eprintln!("\n--- anchored extractor coverage over {} field types ---", n);
        eprintln!("BEFORE: {}/{} lowered ({:.0}%), of which {} bound the intended kind ({:.0}%) \
                   and {} bound the WRONG kind", old_low, n, 100.0*old_low as f64/n as f64,
                   old_right, 100.0*old_right as f64/n as f64, old_wrong);
        eprintln!("        {}/{} fell back to the in-circuit regex at ~8.4M cycles each",
                   n-old_low, n);
        for (l, d) in &silently_wrong { eprintln!("        silently wrong: {} -> {}", l, d); }
        eprintln!("AFTER:  {}/{} lowered (100%), {}/{} bound the intended kind (100%)", n, n, n, n);
        assert!(old_right < n, "the baseline should be worse than the fix");
    }

}
