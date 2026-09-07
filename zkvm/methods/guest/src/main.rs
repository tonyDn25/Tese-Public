#![no_main]

use gps_core::{Extractor, ProofReceipt, ProofRequest, Session, SignedKeyEntry, Transcript};
use risc0_zkvm::guest::env;
use base64::Engine as _;
use std::collections::HashMap;

risc0_zkvm::guest::entry!(main);

/// Hardcoded GPS ROOT public key — the trust anchor (v2 key-distribution model).
/// The guest no longer pins a single origin (leaf) key. It pins this long-lived
/// ROOT key and trusts any origin leaf key the root has signed into a registry
/// entry (verified in-circuit below). Rotating or adding an origin's leaf key
/// only needs a new root-signed entry — it does NOT change this image_id. Any
/// change to THIS key does change the image_id.
const GPS_ROOT_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy46i8cxKUyZp7UQl6WF+pXdQcA0K\noMnY0ChSiWdwklbp3IqKLRc8Mhsn1Hd623trlpWQ0ZG4zQ8oFkbZQz/n7A==\n-----END PUBLIC KEY-----\n";

fn main() {
    // Read all sessions, the proof request, then the root-signed key registry.
    let sessions: Vec<Session>        = env::read();
    let request:  ProofRequest        = env::read();
    let registry: Vec<SignedKeyEntry> = env::read();

    // keyid -> leaf PEM, populated lazily after verifying the root signature once
    // per keyid against the pinned GPS root. A leaf key is used to verify response
    // signatures only after the root has vouched for it.
    let mut trusted_leaf: HashMap<String, String> = HashMap::new();

    // The journal's body commitment is salted so that it provides provenance
    // without handing an enumerating verifier the whole page. The salt is a
    // private input and is never committed. A malformed salt aborts rather than
    // degrading silently to the unsalted form, which would be a privacy failure
    // the prover could not see.
    let body_salt: Option<Vec<u8>> = gps_core::parse_salt(&request.body_salt_hex)
        .unwrap_or_else(|e| panic!("body_salt_hex: {}", e));
    let commitment_scheme = gps_core::commitment_scheme(body_salt.as_deref()).to_string();

    let all_fields = request.all_fields();
    let mut field_results: Vec<gps_core::FieldResult> = Vec::new();
    let mut legacy_field_pattern      = String::new();
    let mut legacy_predicate_statement = String::new();
    let mut legacy_session_id         = String::new();
    let mut legacy_domain             = String::new();
    let mut legacy_target_url         = String::new();
    let mut legacy_body_hash          = String::new();
    let mut legacy_timestamp          = String::new();
    let mut legacy_trust_anchor       = String::new();
    let mut legacy_method             = String::new();
    let mut legacy_authority          = String::new();

    // -- Pre-verify all unique pages (signature + digest) ----------------
    // Each unique (session_id, url) pair is verified exactly once,
    // regardless of how many fields come from that page.
    // This avoids redundant ECDSA verifications which are very expensive in zkVM.
    let mut verified_pages: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (i, field_req) in all_fields.iter().enumerate() {
        // -- Find session for this field -----------------------------------
        let field_target_url = if !field_req.target_url.is_empty() {
            &field_req.target_url
        } else {
            &request.target_url
        };

        // Match session by session_path (filename contains the session id prefix).
        // KI-21: a non-empty session_path that matches nothing must ABORT, not
        // silently fall back to the first session (which would prove a field from a
        // page the request never named). Only the legacy empty-path case defaults to
        // the single session.
        let session = if !field_req.session_path.is_empty() {
            sessions.iter().find(|s| {
                field_req.session_path.contains(&s.session_id[..8])
            }).unwrap_or_else(|| panic!(
                "Field '{}': session_path '{}' matched no provided session — refusing to guess",
                field_req.field_label, field_req.session_path))
        } else {
            sessions.first().unwrap_or_else(|| panic!("No sessions provided"))
        };

        // -- Find target page ----------------------------------------------
        let target = find_target_page(session, field_target_url)
            .unwrap_or_else(|| panic!(
                "Field '{}': URL '{}' not found in session '{}'",
                field_req.field_label, field_target_url, session.session_id
            ));

        // -- Verify Content-Digest + Signature (once per unique page) ------
        let page_key = format!("{}:{}", session.session_id, field_target_url);
        let body_bytes_owned;
        let body_bytes: &[u8] = if target.response.body.starts_with("__PDF_BASE64__") {
            let b64 = &target.response.body["__PDF_BASE64__".len()..];
            body_bytes_owned = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap_or_else(|e| panic!("PDF base64 decode: {}", e));
            &body_bytes_owned
        } else {
            target.response.body.as_bytes()
        };

        let computed_hash   = sha256(body_bytes);
        let computed_b64    = base64_encode(&computed_hash);
        let expected_digest = format!("sha-256=:{}:", computed_b64);
        let stored_digest   = target.response.headers
            .get("content-digest")
            .unwrap_or_else(|| panic!("Field '{}': missing content-digest", field_req.field_label));
        assert_eq!(&expected_digest, stored_digest,
            "Field '{}': Content-Digest mismatch — body was tampered", field_req.field_label);

        // Extract params_str here so it is available outside the verified_pages block
        let sig_input_outer = target.response.headers.get("signature-input")
            .unwrap_or_else(|| panic!("Field '{}': missing signature-input", field_req.field_label));
        let params_str = sig_input_outer.strip_prefix("sig1=")
            .expect("signature-input must start with 'sig1='");

        // -- Resolve the origin's leaf key via the root-signed registry ----
        // (once per keyid). The pinned ROOT must have signed an entry binding this
        // keyid+domain to a leaf key; only then is the leaf trusted to sign pages.
        let page_keyid = extract_keyid(params_str)
            .unwrap_or_else(|| panic!("Field '{}': signature-input has no keyid", field_req.field_label));
        if !trusted_leaf.contains_key(&page_keyid) {
            let signed = registry.iter().find(|s| s.entry.keyid == page_keyid)
                .unwrap_or_else(|| panic!(
                    "Field '{}': no registry entry for keyid '{}' — origin key not in the GPS registry",
                    field_req.field_label, page_keyid));
            let root_sig = base64_decode(&signed.root_sig_b64)
                .expect("registry entry has invalid base64 root signature");
            verify_ecdsa_p256(GPS_ROOT_PUBLIC_KEY_PEM, &signed.entry.canonical_bytes(), &root_sig)
                .unwrap_or_else(|e| panic!(
                    "Field '{}': registry entry for '{}' is NOT signed by the GPS root: {}",
                    field_req.field_label, page_keyid, e));
            // Reject entries whose validity window has closed. not_after == 0 means
            // "no expiry" (demo/prototype). The response's created timestamp is used as
            // the reference point so the check is deterministic in-circuit.
            let signing_ts: i64 = extract_created(params_str)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if signed.entry.not_after > 0 && signing_ts > signed.entry.not_after {
                panic!(
                    "Field '{}': registry entry for '{}' expired (not_after={}, created={})",
                    field_req.field_label, page_keyid,
                    signed.entry.not_after, signing_ts);
            }
            // Bind the entry to the page authority it claims to cover.
            let page_authority = target.response.headers.get("x-gps-authority")
                .map(|s| s.as_str()).unwrap_or(&target.domain);
            assert!(signed.entry.domain == page_authority,
                "Field '{}': registry entry domain '{}' does not match page authority '{}'",
                field_req.field_label, signed.entry.domain, page_authority);
            trusted_leaf.insert(page_keyid.clone(), signed.entry.leaf_pubkey_pem.clone());
        }
        let leaf_pem = trusted_leaf.get(&page_keyid).expect("leaf key resolved above");

        if !verified_pages.contains(&page_key) {
            // -- Verify RFC 9421 signature (expensive — only once per page) -
            // Exactly one accepted base: the full 6-component RFC 9421 base
            // (@method @authority @target-uri @status content-digest date).
            // The legacy 2-component base and the old non-standard PDF base are
            // rejected — accepting them let provenance fields be read from
            // components the signature never covered (MF2, downgrade attack).
            assert!(params_str.contains("@method"),
                "Field '{}': unsupported signature base — only the full 6-component RFC 9421 base is accepted",
                field_req.field_label);
            let signature_base = build_full_signature_base(target, stored_digest, params_str);

            let sig_header = target.response.headers.get("signature")
                .unwrap_or_else(|| panic!("Field '{}': missing signature", field_req.field_label));
            let sig_b64 = sig_header.strip_prefix("sig1=:")
                .and_then(|s| s.strip_suffix(':'))
                .expect("Signature header must be 'sig1=:<base64>:'");
            let sig_bytes = base64_decode(sig_b64).expect("Invalid base64 in signature");

            // Verify with the root-vouched LEAF key (not a hardcoded key).
            verify_ecdsa_p256(leaf_pem, signature_base.as_bytes(), &sig_bytes)
                .unwrap_or_else(|e| panic!("Field '{}': signature verification failed: {}",
                    field_req.field_label, e));

            verified_pages.insert(page_key);
        }

        // -- Extract + evaluate --------------------------------------------
        let timestamp_secs: i64 = extract_created(params_str)
            .unwrap_or_else(|| target.timestamp.clone())
            .parse().unwrap_or(0);

        let (extracted_str, field_pattern) = extract_field_from(target, field_req, body_salt.as_deref());
        let result = evaluate_predicate(&extracted_str, &field_req.predicate, timestamp_secs);

        if !result {
            panic!("Predicate '{}' is FALSE for value '{}' — proof aborted.",
                field_req.predicate, extracted_str);
        }

        // An equality operand is a value, not a bound, so it is committed rather
        // than published. `> 1000` keeps its threshold: that bound is the
        // statement the prover deliberately chose to make.
        let shown_predicate = gps_core::redact_predicate(
            &field_req.predicate, body_salt.as_deref(), |b| hex::encode(sha256(b)));
        let predicate_statement = format!("{} {}", field_pattern, shown_predicate);

        // -- Build provenance ----------------------------------------------
        // NOTE: `computed_hash` above is the bare SHA-256 that the Content-Digest
        // check needs, because the bare body is what the origin signed. The
        // journal commits a separate, salted value.
        let body_hash = hex::encode(sha256(&gps_core::commitment_preimage(
            body_salt.as_deref(), body_bytes)));
        let key_id     = extract_keyid(params_str).unwrap_or_else(|| "unknown".to_string());
        let timestamp  = extract_created(params_str).unwrap_or_else(|| target.timestamp.clone());
        let authority  = target.response.headers
            .get("x-gps-authority").cloned()
            .unwrap_or_else(|| target.domain.clone());
        let target_uri = target.response.headers
            .get("x-gps-target-uri").cloned()
            .unwrap_or_else(|| field_target_url.clone());

        if i == 0 {
            legacy_field_pattern       = field_pattern.clone();
            legacy_predicate_statement = predicate_statement.clone();
            legacy_session_id          = session.session_id.clone();
            legacy_domain              = authority.clone();
            legacy_target_url          = target_uri.clone();
            legacy_body_hash           = body_hash.clone();
            legacy_timestamp           = timestamp.clone();
            legacy_trust_anchor        = key_id.clone();
            legacy_method              = target.request.method.clone();
            legacy_authority           = authority.clone();
        }

        field_results.push(gps_core::FieldResult {
            field_label:          field_req.field_label.clone(),
            field_selected:       field_pattern,
            predicate_statement,
            predicate_result:     true,
            source_domain:        authority,
            source_url:           target_uri,
            source_body_hash:     body_hash,
            body_commitment_scheme: commitment_scheme.clone(),
            source_session_id:    session.session_id.clone(),
            trust_anchor:         key_id,
        });
    }

    env::commit(&ProofReceipt {
        session_id:          legacy_session_id,
        server_domain:       legacy_domain.clone(),
        target_url:          legacy_target_url,
        signed_method:       legacy_method,
        signed_authority:    legacy_authority,
        body_hash:           legacy_body_hash.clone(),
        ciphertext_hash:     legacy_body_hash,
        server_timestamp:    legacy_timestamp,
        predicate_statement: legacy_predicate_statement,
        predicate_result:    true,
        field_selected:      legacy_field_pattern,
        field_results,
        trust_anchor:        legacy_trust_anchor,
        binding:             "in-circuit".to_string(),
    });
}

// -- Signature base builders ---------------------------------------------------

fn build_full_signature_base(
    target: &Transcript,
    content_digest: &str,
    params_str: &str,
) -> String {
    let method = &target.request.method;
    let authority = target.response.headers
        .get("x-gps-authority")
        .map(|s| s.as_str())
        .unwrap_or(&target.domain);
    let target_uri = target.response.headers
        .get("x-gps-target-uri")
        .map(|s| s.as_str())
        .unwrap_or("/");
    let date = target.response.headers
        .get("date")
        .map(|s| s.as_str())
        .unwrap_or("");

    format!(
        "\"@method\": {}\n\
         \"@authority\": {}\n\
         \"@target-uri\": {}\n\
         \"@status\": {}\n\
         \"content-digest\": {}\n\
         \"date\": {}\n\
         \"@signature-params\": {}",
        method, authority, target_uri,
        target.response.status, content_digest,
        date, params_str
    )
}

// -- Field extraction ----------------------------------------------------------

fn extract_field_from(target: &Transcript, field_req: &gps_core::FieldRequest,
                      salt: Option<&[u8]>) -> (String, String) {
    let raw_body = &target.response.body;

    // If body is a PDF, extract text first
    let extracted_text;
    let body = if raw_body.starts_with("__PDF_BASE64__") {
        extracted_text = extract_pdf_text(raw_body);
        &extracted_text
    } else {
        raw_body
    };

    // Every extractor runs IN-CIRCUIT against the verified body and produces the
    // authoritative value; the host's pre-extracted value is only a UI hint and
    // is bound to the in-circuit result below. A prover cannot pass off some
    // other substring of the page as this field.
    let (val, descriptor) = match &field_req.extractor {
        Extractor::JsonPath(path) => {
            let json: serde_json::Value = serde_json::from_str(body)
                .expect("Body is not valid JSON — use Regex extractor for HTML");
            let v = extract_json_field(&json, path)
                .unwrap_or_else(|| panic!("Field '{}' not found in JSON", path));
            (value_to_string(v), path.clone())
        }
        // Path A′: cheap, deterministic, auditable anchored extraction.
        Extractor::Anchored { anchor, window, kind } => {
            let v = gps_core::extract_anchored(body, anchor, *window, kind)
                .unwrap_or_else(|| panic!(
                    "Anchored extraction failed: anchor '{}' or its value not found in the signed body",
                    anchor));
            // Commit the extraction window (max bytes from the anchor to the value) into the
            // descriptor, so a verifier can audit how far from the label the value was bound,
            // not only the label and token kind.
            let descriptor = match kind {
                gps_core::AnchoredKind::Number      => format!("anchored:\"{}\"->number(w={})", anchor, window),
                // The literal is simultaneously the rule and the value, so
                // publishing the rule publishes the value. Committed instead, under
                // the same per-proof salt: a verifier who knows what they are
                // checking recomputes it, and nobody else learns it.
                gps_core::AnchoredKind::Literal(l)  => match gps_core::value_commitment_preimage(salt, l) {
                    Some(pre) => format!("anchored:\"{}\"->h:{}(w={})", anchor, hex::encode(sha256(&pre)), window),
                    None      => format!("anchored:\"{}\"->\"{}\"(w={})", anchor, l, window),
                },
                // The date format is committed, not just the fact that a date was
                // read. 01/02/2026 is two different days under DmySlash and
                // MdySlash, so a verifier auditing the rule needs the reading that
                // produced the value, and the value itself is normalised to ISO.
                gps_core::AnchoredKind::Date(f)     => format!("anchored:\"{}\"->date({:?},w={})", anchor, f, window),
            };
            (v, descriptor)
        }
        // General fallback: full regex in-circuit (sound but expensive).
        Extractor::Regex(pattern) => {
            let re = regex::RegexBuilder::new(pattern).dot_matches_new_line(true).build()
                .unwrap_or_else(|e| panic!("Invalid regex '{}': {}", pattern, e));
            let caps = re.captures(body)
                .unwrap_or_else(|| panic!("Regex '{}' did not match the signed body", pattern));
            let v = caps.get(1).or_else(|| caps.get(0))
                .unwrap_or_else(|| panic!("Regex '{}' matched but produced no capture group", pattern))
                .as_str().to_string();
            (v, pattern.clone())
        }
    };

    // Sound binding: the host's pre-extracted hint (if supplied) must equal what
    // the in-circuit extractor produced from the verified body, else abort.
    if !field_req.extracted_value.is_empty() {
        assert!(val == field_req.extracted_value,
            "Field binding violated: host supplied '{}' but the in-circuit extractor produced '{}' from the signed body",
            field_req.extracted_value, val);
    }
    (val, descriptor)
}

// -- Page finder ---------------------------------------------------------------

fn find_target_page<'a>(session: &'a Session, target_url: &str) -> Option<&'a Transcript> {
    let target_path = target_url.split('?').next().unwrap_or(target_url);
    // Exact path match
    if let Some(t) = session.pages.iter().find(|t| {
        t.request.path.split('?').next().unwrap_or(&t.request.path) == target_path
    }) { return Some(t); }
    // Root path: "/" or empty both represent the site root
    if target_path == "/" || target_path.is_empty() {
        if let Some(t) = session.pages.iter().find(|t| {
            let p = t.request.path.split('?').next().unwrap_or(&t.request.path);
            p == "/" || p.is_empty()
        }) { return Some(t); }
    }
    // No match — return None so the caller panics with a precise error
    None
}

// -- Predicate evaluation ------------------------------------------------------

fn evaluate_predicate(value_str: &str, predicate: &str, timestamp_secs: i64) -> bool {
    let pred     = predicate.trim();
    // Handle both European (2.847,50) and standard (2847.50) number formats
    let normalized_value = if value_str.contains(',') && value_str.contains('.') {
        // European format: 2.847,50 → remove dots, replace comma with dot
        value_str.replace('.', "").replace(',', ".")
    } else if value_str.contains(',') && !value_str.contains('.') {
        // Simple decimal comma: 86,72 → 86.72
        value_str.replace(',', ".")
    } else {
        value_str.to_string()
    };
    let value_f64 = normalized_value.parse::<f64>();

    if let Some(r) = pred.strip_prefix(">=") {
        let r: f64 = r.trim().parse().expect("bad number in >=");
        return value_f64.map(|v| v >= r).unwrap_or(false);
    }
    if let Some(r) = pred.strip_prefix("<=") {
        let r: f64 = r.trim().parse().expect("bad number in <=");
        return value_f64.map(|v| v <= r).unwrap_or(false);
    }
    if let Some(r) = pred.strip_prefix("> ") {
        let r: f64 = r.trim().parse().expect("bad number in >");
        return value_f64.map(|v| v > r).unwrap_or(false);
    }
    if let Some(r) = pred.strip_prefix("< ") {
        let r: f64 = r.trim().parse().expect("bad number in <");
        return value_f64.map(|v| v < r).unwrap_or(false);
    }
    if let Some(r) = pred.strip_prefix("!=") {
        return value_str != r.trim().trim_matches('"');
    }
    if let Some(r) = pred.strip_prefix("==") {
        let r = r.trim().trim_matches('"');
        if let (Ok(lv), Ok(rv)) = (value_f64, r.parse::<f64>()) { return lv == rv; }
        return value_str == r;
    }
    if let Some(r) = pred.strip_prefix("contains") {
        return value_str.contains(r.trim().trim_matches('"'));
    }
    if let Some(rest) = pred.strip_prefix("age") {
        let rest = rest.trim();
        if let Some(r) = rest.strip_prefix(">=") {
            return compute_age(value_str, timestamp_secs) >= r.trim().parse::<i64>().expect("bad age");
        }
        if let Some(r) = rest.strip_prefix("<=") {
            return compute_age(value_str, timestamp_secs) <= r.trim().parse::<i64>().expect("bad age");
        }
        if let Some(r) = rest.strip_prefix("> ") {
            return compute_age(value_str, timestamp_secs) > r.trim().parse::<i64>().expect("bad age");
        }
        if let Some(r) = rest.strip_prefix("< ") {
            return compute_age(value_str, timestamp_secs) < r.trim().parse::<i64>().expect("bad age");
        }
        if let Some(r) = rest.strip_prefix("==") {
            return compute_age(value_str, timestamp_secs) == r.trim().parse::<i64>().expect("bad age");
        }
        panic!("Unknown age predicate: {}", pred);
    }
    panic!("Unknown predicate: '{}'", pred);
}

fn compute_age(date_str: &str, now_secs: i64) -> i64 {
    // KI-22: calendar-correct age (counts leap years, ticks over only on/after the
    // birthday). Delegates to the unit-tested gps_core::age_years.
    let n = date_str.replace('/', "-");
    let p: Vec<&str> = n.split('-').collect();
    if p.len() != 3 { panic!("Invalid date: '{}'", date_str); }
    let y: i64 = p[0].parse().expect("bad year");
    let m: i64 = p[1].parse().expect("bad month");
    let d: i64 = p[2].parse().expect("bad day");
    gps_core::age_years(y, m, d, now_secs)
}

// -- JSON helpers --------------------------------------------------------------

fn extract_json_field<'a>(v: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = v;
    for key in path.split('.') {
        if let Ok(i) = key.parse::<usize>() { cur = cur.get(i)?; }
        else { cur = cur.get(key)?; }
    }
    Some(cur)
}

fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b)   => b.to_string(),
        _ => v.to_string(),
    }
}

// -- Crypto --------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    // Use RISC Zero's hardware-accelerated SHA-256 syscall for the body digest.
    use risc0_zkvm::sha::{Impl, Sha256};
    Impl::hash_bytes(data).as_bytes().try_into().unwrap()
}
fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s).map_err(|e| e.to_string())
}
fn verify_ecdsa_p256(key_pem: &str, message: &[u8], sig: &[u8]) -> Result<(), String> {
    use p256::ecdsa::{signature::DigestVerifier, DerSignature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    use sha2::{Digest, Sha256};
    let vk = VerifyingKey::from_public_key_pem(key_pem)
        .map_err(|e| format!("Key error: {}", e))?;
    let s = DerSignature::try_from(sig)
        .map_err(|e| format!("Sig parse error: {}", e))?;
    vk.verify_digest(Sha256::new_with_prefix(message), &s)
        .map_err(|e| format!("Verification failed: {}", e))
}
fn extract_keyid(params: &str) -> Option<String> {
    params.split(';').find(|s| s.trim_start().starts_with("keyid="))
        .map(|s| s.trim_start().trim_start_matches("keyid=").trim_matches('"').to_string())
}
fn extract_created(params: &str) -> Option<String> {
    params.split(';').find(|s| s.trim_start().starts_with("created="))
        .map(|s| s.trim_start().trim_start_matches("created=").to_string())
}

// -- PDF text extraction -------------------------------------------------------
// Decompresses FlateDecode streams and extracts text from PDF content streams.
// Works on digitally-generated PDFs (not scanned images).

fn extract_pdf_text(body: &str) -> String {
    // Body is stored as "__PDF_BASE64__" + base64 string
    let b64 = if let Some(stripped) = body.strip_prefix("__PDF_BASE64__") {
        stripped
    } else {
        // Try treating body as raw PDF text (legacy)
        return extract_pdf_content_stream_text(body.as_bytes());
    };

    let pdf_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap_or_else(|e| panic!("PDF base64 decode failed: {}", e));

    extract_pdf_content_stream_text(&pdf_bytes)
}

fn extract_pdf_content_stream_text(pdf_bytes: &[u8]) -> String {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut all_text = String::new();

    // Find all FlateDecode streams in the PDF
    let marker = b"stream\n";
    let endmarker = b"\nendstream";
    let mut pos = 0;

    while pos < pdf_bytes.len() {
        // Find next stream
        if let Some(start) = find_bytes(&pdf_bytes[pos..], marker) {
            let stream_start = pos + start + marker.len();

            // Find end of stream
            if let Some(end) = find_bytes(&pdf_bytes[stream_start..], endmarker) {
                let stream_data = &pdf_bytes[stream_start..stream_start + end];

                // Try to decompress as zlib/deflate
                let mut decoder = ZlibDecoder::new(stream_data);
                let mut decompressed = Vec::new();
                if decoder.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty() {
                    // Extract text from PDF content stream operators
                    let text = extract_text_from_content_stream(&decompressed);
                    if !text.is_empty() {
                        if !all_text.is_empty() {
                            all_text.push('\n');
                        }
                        all_text.push_str(&text);
                    }
                }

                pos = stream_start + end + endmarker.len();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    // Also try \r\n variant of stream marker
    if all_text.is_empty() {
        let marker2 = b"stream\r\n";
        let mut pos2 = 0;
        while pos2 < pdf_bytes.len() {
            if let Some(start) = find_bytes(&pdf_bytes[pos2..], marker2) {
                let stream_start = pos2 + start + marker2.len();
                if let Some(end) = find_bytes(&pdf_bytes[stream_start..], endmarker) {
                    let stream_data = &pdf_bytes[stream_start..stream_start + end];
                    let mut decoder = ZlibDecoder::new(stream_data);
                    let mut decompressed = Vec::new();
                    if decoder.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty() {
                        let text = extract_text_from_content_stream(&decompressed);
                        if !text.is_empty() {
                            if !all_text.is_empty() { all_text.push('\n'); }
                            all_text.push_str(&text);
                        }
                    }
                    pos2 = stream_start + end + endmarker.len();
                } else { break; }
            } else { break; }
        }
    }

    all_text
}

// Extract text from PDF content stream: finds (text)Tj and (text)TJ operators
fn extract_text_from_content_stream(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    let mut result = String::new();
    let mut i = 0;
    let chars: Vec<char> = s.chars().collect();

    while i < chars.len() {
        if chars[i] == '(' {
            // Read until matching closing paren (handle escapes and nesting)
            let mut text = String::new();
            let mut depth = 1;
            i += 1;
            while i < chars.len() && depth > 0 {
                match chars[i] {
                    '\\' => {
                        i += 1;
                        if i < chars.len() {
                            match chars[i] {
                                'n' => text.push('\n'),
                                'r' => text.push('\r'),
                                't' => text.push('\t'),
                                '(' => text.push('('),
                                ')' => text.push(')'),
                                '\\' => text.push('\\'),
                                _ => { text.push('\\'); text.push(chars[i]); }
                            }
                        }
                    }
                    '(' => { depth += 1; text.push('('); }
                    ')' => {
                        depth -= 1;
                        if depth > 0 { text.push(')'); }
                    }
                    c => text.push(c),
                }
                i += 1;
            }
            // Check if followed by Tj or TJ operator
            let rest: String = chars[i..].iter().take(10).collect();
            let rest_trim = rest.trim_start();
            if rest_trim.starts_with("Tj") || rest_trim.starts_with("TJ") {
                // Clean up non-printable chars
                let clean: String = text.chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .collect();
                if !clean.trim().is_empty() {
                    result.push_str(clean.trim());
                    result.push(' ');
                }
            }
        } else {
            i += 1;
        }
    }

    result.trim().to_string()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
