use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RequestInfo {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseInfo {
    pub status: u16,
    pub body: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transcript {
    pub id: String,
    pub timestamp: String,
    pub domain: String,
    pub request: RequestInfo,
    pub response: ResponseInfo,
    pub nginx_public_key: String,
}

impl Transcript {
    pub fn has_signature(&self) -> bool {
        let h = &self.response.headers;
        h.contains_key("signature")
            && h.contains_key("signature-input")
            && h.contains_key("content-digest")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Session {
    pub session_id: String,
    pub domain: String,
    pub started_at: String,
    pub ended_at: String,
    pub pages: Vec<Transcript>,
}

impl Session {
    pub fn signed_count(&self) -> usize {
        self.pages.iter().filter(|p| p.has_signature()).count()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Extractor {
    JsonPath(String),
    Regex(String),
    /// Path A′: cheap, deterministic, auditable extraction. The value is the
    /// first numeric token (or a bound literal) appearing within `window` bytes
    /// after the first occurrence of `anchor` in the signed body. Far cheaper
    /// in-circuit than a general regex, and still sound: the value is fixed by
    /// the (anchor, kind) rule + the signed body, so a prover cannot choose a
    /// different substring. The verifier audits the rule from the journal.
    Anchored { anchor: String, window: usize, kind: AnchoredKind },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AnchoredKind {
    /// The first `[0-9][0-9.,]*` token after the anchor.
    Number,
    /// A specific literal that must occur after the anchor (binds e.g. a name
    /// to its label). The value is the literal itself.
    Literal(String),
    /// The first date after the anchor, in the stated format, normalised to
    /// ISO `YYYY-MM-DD`. Added 2026-09-05: dates were the single largest field
    /// class falling back to the full in-circuit regex at ~8.4M cycles per
    /// field (KI-20). The scan is linear, like `Number`, so a date now costs
    /// the anchored price instead.
    ///
    /// The format is part of the rule and is committed to the journal rather
    /// than inferred. `01/02/2026` is 1 February under `DmySlash` and
    /// 2 January under `MdySlash`, and no amount of scanning can decide which
    /// the page meant. Naming it makes the interpretation auditable instead of
    /// guessed, which is the same reason the anchor and window are committed.
    Date(DateFormat),
}

/// The date shapes the anchored extractor recognises. Each names one
/// unambiguous reading; the extractor never guesses between them.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum DateFormat {
    /// `YYYY-MM-DD` (ISO 8601 calendar date).
    Iso,
    /// `YYYY/MM/DD`, the same order with slashes.
    IsoSlash,
    /// `DD/MM/YYYY`, the common European civil form.
    DmySlash,
    /// `MM/DD/YYYY`, the common US civil form.
    MdySlash,
    /// `DD-MM-YYYY`.
    DmyDash,
    /// `DD.MM.YYYY`, common on Portuguese and German pages.
    DmyDot,
}

impl DateFormat {
    /// The separator byte and whether the year leads.
    fn shape(self) -> (u8, bool) {
        match self {
            DateFormat::Iso      => (b'-', true),
            DateFormat::IsoSlash => (b'/', true),
            DateFormat::DmySlash => (b'/', false),
            DateFormat::MdySlash => (b'/', false),
            DateFormat::DmyDash  => (b'-', false),
            DateFormat::DmyDot   => (b'.', false),
        }
    }
    /// Whether the first of the two leading fields is the day (vs the month).
    fn day_first(self) -> bool {
        !matches!(self, DateFormat::Iso | DateFormat::IsoSlash | DateFormat::MdySlash)
    }
}

/// Parse `n` ASCII digits at `p`, returning the value and the next index.
fn take_digits(region: &[u8], p: usize, n: usize) -> Option<(u32, usize)> {
    if p + n > region.len() { return None; }
    let mut v = 0u32;
    for k in 0..n {
        let b = region[p + k];
        if !b.is_ascii_digit() { return None; }
        v = v * 10 + (b - b'0') as u32;
    }
    Some((v, p + n))
}

/// True if the calendar date is well formed. Rejects month 0 or >12, day 0,
/// and days past the length of the month, with a proleptic Gregorian leap rule
/// so that 29 February is accepted only in a leap year. A guest that accepted
/// `2026-02-30` would be binding a value the page cannot mean.
fn valid_ymd(y: u32, m: u32, d: u32) -> bool {
    if !(1..=12).contains(&m) || d == 0 { return false; }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let last = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if leap { 29 } else { 28 },
        _ => return false,
    };
    d <= last
}

/// Try to read one date of `fmt` starting exactly at `p`. Returns the ISO
/// normalisation and the index just past the match.
fn date_at(region: &[u8], p: usize, fmt: DateFormat) -> Option<(String, usize)> {
    let (sep, year_first) = fmt.shape();
    let (a, i) = if year_first { take_digits(region, p, 4)? } else { take_digits(region, p, 2)? };
    if *region.get(i)? != sep { return None; }
    let (b, j) = take_digits(region, i + 1, 2)?;
    if *region.get(j)? != sep { return None; }
    let (c, k) = if year_first { take_digits(region, j + 1, 2)? } else { take_digits(region, j + 1, 4)? };
    // A longer run of digits either side means this is not a date but part of a
    // larger number, so the match is refused rather than truncated.
    if p > 0 && region[p - 1].is_ascii_digit() { return None; }
    if region.get(k).is_some_and(|x| x.is_ascii_digit()) { return None; }

    let (y, m, d) = if year_first {
        (a, b, c)
    } else if fmt.day_first() {
        (c, b, a)
    } else {
        (c, a, b)
    };
    if !valid_ymd(y, m, d) { return None; }
    Some((alloc_iso(y, m, d), k))
}

/// `YYYY-MM-DD` without pulling in a formatting crate, so the guest keeps the
/// same tiny dependency surface it has for every other extractor.
fn alloc_iso(y: u32, m: u32, d: u32) -> String {
    fn push(s: &mut String, v: u32, w: usize) {
        let mut buf = [0u8; 4];
        let mut n = v;
        for slot in buf.iter_mut().take(w).rev() { *slot = b'0' + (n % 10) as u8; n /= 10; }
        for &b in &buf[..w] { s.push(b as char); }
    }
    let mut s = String::with_capacity(10);
    push(&mut s, y, 4); s.push('-');
    push(&mut s, m, 2); s.push('-');
    push(&mut s, d, 2);
    s
}

impl Default for Extractor {
    fn default() -> Self { Extractor::JsonPath(String::new()) }
}

/// Find the first occurrence of `needle` in `hay` (byte search).
pub fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    if needle.len() > hay.len() { return None; }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Deterministic anchored extraction shared by host and guest, so both compute
/// exactly the same value. Returns `None` if the anchor (or, for `Number`, a
/// digit; for `Literal`, the literal) is not present within the window.
pub fn extract_anchored(body: &str, anchor: &str, window: usize, kind: &AnchoredKind) -> Option<String> {
    let bytes = body.as_bytes();
    let astart = find_subslice(bytes, anchor.as_bytes())?;
    let rstart = astart + anchor.len();
    let rend = core::cmp::min(rstart.saturating_add(window), bytes.len());
    let region = &bytes[rstart..rend];
    match kind {
        AnchoredKind::Number => {
            // Match `[+-]?[0-9][0-9.,]*` at the earliest position (lazy-gap
            // semantics): scan left to right for the first index that begins a
            // number — either a digit, or a single '+'/'-' immediately before a
            // digit. The sign, when present, is included in the value so that
            // negative quantities (e.g. an overdrawn balance) are preserved.
            let n = region.len();
            let mut i = 0usize;
            let start = loop {
                if i >= n { return None; }
                let b = region[i];
                if b.is_ascii_digit() { break i; }
                if (b == b'+' || b == b'-') && i + 1 < n && region[i + 1].is_ascii_digit() {
                    break i;
                }
                i += 1;
            };
            // `start` is a digit, or a sign whose next byte is a digit.
            let digit_start = if region[start] == b'+' || region[start] == b'-' { start + 1 } else { start };
            let mut end = digit_start;
            while end < n
                && (region[end].is_ascii_digit() || region[end] == b'.' || region[end] == b',') {
                end += 1;
            }
            core::str::from_utf8(&region[start..end]).ok().map(|s| s.to_string())
        }
        AnchoredKind::Literal(lit) => {
            find_subslice(region, lit.as_bytes()).map(|_| lit.clone())
        }
        AnchoredKind::Date(fmt) => {
            // Same lazy-gap semantics as Number: the earliest position in the
            // window that begins a well-formed date of the stated format wins.
            // One linear pass, no backtracking.
            (0..region.len()).find_map(|i| date_at(region, i, *fmt).map(|(v, _)| v))
        }
    }
}

// -- Body commitment (metadata-leakage fix, 2026-09-05) ---------------------
//
// The journal commits a hash of the signed body so a verifier can tie a proof to
// a specific artefact. Committing the bare SHA-256 makes that provenance field
// leak the whole page to anyone who can enumerate candidate bodies: hashing is
// cheap, the search space of a page whose only unknown is a balance is about
// 10^8, and the recovery is exact rather than partial. It also made two proofs
// over the same body carry byte-identical commitments, so separate disclosures
// were linkable without anyone learning what the body said.
//
// Salting fixes both. The salt is a private input, so the commitment is
// unpredictable to a verifier and unlinkable across proofs, and the prover can
// still demonstrate provenance later by revealing the salt.
//
// This is NOT the RFC 9421 content digest. That check must stay over the bare
// body, because the bare body is what the origin signed.

/// Scheme label committed alongside the value, so a verifier reads how it was formed.
pub const COMMIT_SALTED: &str   = "sha256(salt||body)";
pub const COMMIT_UNSALTED: &str = "sha256(body)";

/// Decode a hex salt. Returns `None` for the empty string, meaning "unsalted",
/// and errors on anything that is not valid hex, so a malformed salt cannot
/// silently degrade to no salt at all.
pub fn parse_salt(hex_str: &str) -> Result<Option<Vec<u8>>, String> {
    if hex_str.is_empty() { return Ok(None); }
    if hex_str.len() % 2 != 0 { return Err("salt hex has odd length".into()); }
    let mut out = Vec::with_capacity(hex_str.len() / 2);
    let b = hex_str.as_bytes();
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or("salt is not hex")?;
        let lo = (pair[1] as char).to_digit(16).ok_or("salt is not hex")?;
        out.push((hi * 16 + lo) as u8);
    }
    if out.len() < 16 {
        return Err("salt must be at least 128 bits; a short salt is enumerable".into());
    }
    Ok(Some(out))
}

/// The bytes the commitment is taken over: `salt || body`, or just `body` when
/// there is no salt. Prefixing rather than appending keeps the length-extension
/// question from arising at all.
pub fn commitment_preimage(salt: Option<&[u8]>, body: &[u8]) -> Vec<u8> {
    match salt {
        None => body.to_vec(),
        Some(s) => { let mut v = Vec::with_capacity(s.len() + body.len()); v.extend_from_slice(s); v.extend_from_slice(body); v }
    }
}

/// The scheme label for a given salt state.
pub fn commitment_scheme(salt: Option<&[u8]>) -> &'static str {
    if salt.is_some() { COMMIT_SALTED } else { COMMIT_UNSALTED }
}

// -- Value commitments in the journal (2026-09-05) --------------------------
//
// Salting the body commitment stopped the journal handing over the whole page.
// It did not stop the journal handing over the one value the proof is about,
// and for two field shapes it was doing exactly that:
//
//   * an equality predicate carries its operand, so `== Alice Smith` publishes
//     the name to anyone who reads the proof, not only to the verifier who was
//     already checking against it;
//   * the anchored `Literal` rule IS the literal, so `->"Alice Smith"` publishes
//     it a second time, in the descriptor that exists so a verifier can audit
//     how the value was read. For literals, auditing the rule and seeing the
//     value are the same act.
//
// Both are replaced by `h:<hex>` over the same per-proof salt. A verifier who
// knows the value being checked -- which, for an equality, is essentially always
// the case, since they are the one asserting it -- recomputes and confirms. A
// party who does not know it learns nothing, which is the point.
//
// Inequality thresholds are NOT hidden. `> 1000` discloses the bound, and the
// bound is the statement the prover chose to make.
//
// Domain-separated from the body commitment so the two can never be confused
// or substituted for one another.

pub const VALUE_TAG: &[u8] = b"gps-value-v1\x00";

/// Preimage for a committed value: `"gps-value-v1\0" || salt || value`.
/// `None` when there is no salt, since there is then nothing to hide behind and
/// pretending otherwise would be worse than publishing the value plainly.
pub fn value_commitment_preimage(salt: Option<&[u8]>, value: &str) -> Option<Vec<u8>> {
    let s = salt?;
    let mut v = Vec::with_capacity(VALUE_TAG.len() + s.len() + value.len());
    v.extend_from_slice(VALUE_TAG);
    v.extend_from_slice(s);
    v.extend_from_slice(value.as_bytes());
    Some(v)
}

/// Split a predicate into its operator and operand, and say whether the operand
/// names a VALUE (which should be hidden) or a BOUND (which should not).
///
/// Returns `None` for predicates with no operand to consider.
pub fn predicate_operand(pred: &str) -> Option<(&str, &str, bool)> {
    let p = pred.trim();
    // Age predicates compare a derived number against a bound, never a value.
    if p.starts_with("age") { return None; }
    for (op, hides) in [("==", true), ("!=", true), ("contains", true),
                        (">=", false), ("<=", false), (">", false), ("<", false)] {
        if let Some(rest) = p.strip_prefix(op) {
            return Some((op, rest.trim().trim_matches('"'), hides));
        }
    }
    None
}

/// Rewrite a predicate so that a value-bearing operand is replaced by its
/// commitment. `hash` receives the preimage and returns the hex digest; it is a
/// parameter because the guest hashes through the zkVM accelerator and the host
/// through the `sha2` crate, and this crate deliberately depends on neither.
pub fn redact_predicate<F: Fn(&[u8]) -> String>(pred: &str, salt: Option<&[u8]>, hash: F) -> String {
    match predicate_operand(pred) {
        Some((op, operand, true)) => match value_commitment_preimage(salt, operand) {
            Some(pre) => format!("{} h:{}", op, hash(&pre)),
            None => pred.trim().to_string(),
        },
        _ => pred.trim().to_string(),
    }
}

// -- Key registry (v2: distributable trust) ---------------------------------
// The guest no longer pins a single leaf signing key. Instead it pins a long-lived
// ROOT public key, and trusts any origin leaf key that the root has signed into a
// registry entry. Rotating or adding an origin's leaf key only requires a new
// root-signed entry — it does NOT change the guest image_id. This removes the
// "rotation breaks every verifier" and "one origin only" objections while keeping
// soundness: trust still bottoms out at the pinned root.

/// A registry entry binding an origin's RFC 9421 leaf key to its identity.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyRegistryEntry {
    /// The `keyid` used in the origin's Signature-Input (e.g. "gps-nginx").
    pub keyid: String,
    /// The authority this key is valid for (e.g. "172.18.0.50").
    pub domain: String,
    /// The origin's ECDSA P-256 leaf public key, PEM (SPKI).
    pub leaf_pubkey_pem: String,
    /// Unix expiry; 0 means "no expiry" (demo). Guests may reject expired entries.
    pub not_after: i64,
}

/// Strip a PEM to its single-line base64 DER body (drops `-----` headers and all
/// whitespace), so canonicalisation never depends on PEM line-wrapping or a trailing
/// newline — the host (openssl) and the guest derive identical bytes.
pub fn pem_b64_body(pem: &str) -> String {
    pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect()
}

impl KeyRegistryEntry {
    /// Deterministic bytes the ROOT signs (and the guest re-derives). Versioned so
    /// the format can evolve without ambiguity. Both host and guest call this, so a
    /// single source of truth fixes exactly what the root signature covers. The leaf
    /// key is reduced to its base64 DER body so whitespace cannot break the match.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "gps-key-registry-v1\nkeyid={}\ndomain={}\nnot_after={}\nleaf={}",
            self.keyid, self.domain, self.not_after, pem_b64_body(&self.leaf_pubkey_pem)
        ).into_bytes()
    }
}

/// A registry entry plus the root's signature over its `canonical_bytes()`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedKeyEntry {
    pub entry: KeyRegistryEntry,
    /// Base64 of the DER-encoded ECDSA P-256 signature by the root key.
    pub root_sig_b64: String,
}

// -- Calendar-correct age (KI-22) -------------------------------------------

/// Civil (year, month, day) from days since the Unix epoch.
/// Howard Hinnant's `civil_from_days`, exact for the proleptic Gregorian calendar.
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;                                      // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);              // [0, 365]
    let mp = (5 * doy + 2) / 153;                                    // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1;                            // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 };                  // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Whole years elapsed from a birth date to `now_secs` (calendar-correct: counts
/// leap years and only ticks over on/after the birthday). Replaces the old
/// `elapsed_days / 365` approximation that drifted ~1 day every 4 years.
pub fn age_years(birth_y: i64, birth_m: i64, birth_d: i64, now_secs: i64) -> i64 {
    let (ny, nm, nd) = civil_from_days(now_secs.div_euclid(86400));
    let mut age = ny - birth_y;
    if (nm, nd) < (birth_m, birth_d) { age -= 1; }
    age
}

/// A single field+predicate pair within a multi-field proof request
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FieldRequest {
    pub extractor:    Extractor,
    pub predicate:    String,
    pub field_label:  String,
    /// Path to the session JSON file this field comes from
    #[serde(default)]
    pub session_path: String,
    /// URL path of the page this field comes from
    #[serde(default)]
    pub target_url:   String,
    /// Pre-extracted value (set by host to avoid regex in guest)
    #[serde(default)]
    pub extracted_value: String,
}

/// A single proven field result in the journal
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FieldResult {
    pub field_label:         String,
    pub field_selected:      String,
    pub predicate_statement: String,
    pub predicate_result:    bool,
    /// Provenance — cryptographically bound to this field result
    #[serde(default)]
    pub source_domain:     String,
    #[serde(default)]
    pub source_url:        String,
    #[serde(default)]
    pub source_body_hash:  String,
    /// How `source_body_hash` was formed. `sha256(body)` is the legacy unsalted
    /// commitment; `sha256(salt||body)` is the salted one. Committing the scheme
    /// rather than leaving it implied is the same discipline as committing the
    /// extraction window: a verifier should not have to guess how a value in the
    /// journal was produced.
    #[serde(default)]
    pub body_commitment_scheme: String,
    #[serde(default)]
    pub source_session_id: String,
    #[serde(default)]
    pub trust_anchor:      String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofRequest {
    // -- Multi-field (new) -------------------------------------------------
    /// Multiple field+predicate pairs, each with its own source.
    #[serde(default)]
    pub fields: Vec<FieldRequest>,

    // -- Single-field (legacy, kept for backward compat) -------------------
    #[serde(default)]
    pub extractor:   Extractor,
    #[serde(default)]
    pub predicate:   String,
    #[serde(default)]
    pub field_label: String,

    /// Hex-encoded random salt for the journal's body commitment, chosen fresh
    /// by the prover for each proof. It is a private input: it reaches the guest
    /// and is never committed to the journal, which is the whole point.
    ///
    /// Empty means the legacy unsalted commitment, kept so that proofs produced
    /// before this change still describe themselves accurately.
    #[serde(default)]
    pub body_salt_hex: String,

    /// Legacy single target URL (used when fields[].target_url is empty)
    #[serde(default)]
    pub target_url:  String,
}

impl ProofRequest {
    /// Returns all field requests, normalising legacy single-field format
    pub fn all_fields(&self) -> Vec<FieldRequest> {
        if !self.fields.is_empty() {
            self.fields.clone()
        } else {
            vec![FieldRequest {
                extractor:       self.extractor.clone(),
                predicate:       self.predicate.clone(),
                field_label:     self.field_label.clone(),
                session_path:    String::new(),
                target_url:      self.target_url.clone(),
                extracted_value: String::new(),
            }]
        }
    }
}

/// The proof receipt — committed to the zkVM journal.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofReceipt {
    // -- Identity ----------------------------------------------------------
    pub session_id:    String,
    pub server_domain: String,
    pub target_url:    String,

    // -- RFC 9421 signed components ----------------------------------------
    pub signed_method:    String,
    pub signed_authority: String,

    // -- Cryptographic integrity -------------------------------------------
    pub body_hash:       String,
    pub ciphertext_hash: String,

    // -- Multi-field results (new) -----------------------------------------
    /// All proven fields. Always populated (single-field proofs have len=1).
    #[serde(default)]
    pub field_results: Vec<FieldResult>,

    // -- Legacy single-field (kept for backward compat + verifier display) -
    pub server_timestamp:    String,
    pub predicate_statement: String,
    pub predicate_result:    bool,
    pub field_selected:      String,
    pub trust_anchor:        String,

    /// Binding discipline used for field extraction.
    /// v9+ commits "in-circuit": the extraction pattern was run inside the
    /// zkVM against the verified body, so the value is bound to the pattern.
    /// Absent (empty) on v8 and earlier, where extraction was host-side only.
    #[serde(default)]
    pub binding: String,
}

#[cfg(test)]
mod tests {
    use super::{extract_anchored, AnchoredKind, DateFormat};

    #[test]
    fn anchored_number_unsigned() {
        let v = extract_anchored("Balance: 2500.00 EUR", "Balance:", 50, &AnchoredKind::Number);
        assert_eq!(v.as_deref(), Some("2500.00"));
    }

    #[test]
    fn anchored_number_negative_sign_preserved() {
        // The whole point of KI-19: an overdrawn balance keeps its '-'.
        let v = extract_anchored("Balance: -650.50 EUR", "Balance:", 50, &AnchoredKind::Number);
        assert_eq!(v.as_deref(), Some("-650.50"));
    }

    #[test]
    fn anchored_number_positive_sign_preserved() {
        let v = extract_anchored("Delta: +1800.00", "Delta:", 50, &AnchoredKind::Number);
        assert_eq!(v.as_deref(), Some("+1800.00"));
    }

    #[test]
    fn anchored_number_lone_sign_is_not_consumed() {
        // A '-' not immediately before a digit must not start the match; the
        // scan continues to the next real number.
        let v = extract_anchored("rate - then 42 pct", "rate", 30, &AnchoredKind::Number);
        assert_eq!(v.as_deref(), Some("42"));
    }

    #[test]
    fn anchored_literal_matches() {
        let v = extract_anchored("Holder: Alice Smith.", "Holder:", 40,
            &AnchoredKind::Literal("Alice Smith".to_string()));
        assert_eq!(v.as_deref(), Some("Alice Smith"));
    }

    #[test]
    fn anchored_number_absent_is_none() {
        assert!(extract_anchored("no numbers here", "no", 20, &AnchoredKind::Number).is_none());
    }

    use super::{age_years, civil_from_days, KeyRegistryEntry};

    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(18993), (2022, 1, 1));   // 2022-01-01
        assert_eq!(civil_from_days(-719468), (0, 3, 1));    // epoch of the algorithm
    }

    #[test]
    fn age_is_calendar_correct_around_birthday() {
        // Born 2000-06-13. Day before the 18th birthday → 17; on it → 18.
        let jun12_2018 = 1528804800; // 2018-06-12 12:00 UTC
        let jun13_2018 = 1528891200; // 2018-06-13 12:00 UTC
        assert_eq!(age_years(2000, 6, 13, jun12_2018), 17);
        assert_eq!(age_years(2000, 6, 13, jun13_2018), 18);
    }

    #[test]
    fn age_counts_leap_years() {
        // The old `/365` formula over-counted; a calendar count must not. Born
        // 1996-02-29 (leap day); on 2020-02-28 the person is 23, on 2020-03-01 is 24.
        let feb28_2020 = 1582891200; // 2020-02-28 12:00 UTC
        let mar01_2020 = 1583064000; // 2020-03-01 12:00 UTC
        assert_eq!(age_years(1996, 2, 29, feb28_2020), 23);
        assert_eq!(age_years(1996, 2, 29, mar01_2020), 24);
    }

    #[test]
    fn registry_canonical_bytes_are_deterministic_and_bound() {
        let e = KeyRegistryEntry {
            keyid: "gps-nginx".into(),
            domain: "172.18.0.50".into(),
            leaf_pubkey_pem: "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n".into(),
            not_after: 0,
        };
        let b = e.canonical_bytes();
        assert_eq!(b, e.canonical_bytes(), "must be deterministic");
        let s = String::from_utf8(b).unwrap();
        assert!(s.starts_with("gps-key-registry-v1\n"));
        // Every identity field is covered by the signed bytes (no field can be
        // swapped without invalidating the root signature).
        assert!(s.contains("keyid=gps-nginx"));
        assert!(s.contains("domain=172.18.0.50"));
        assert!(s.contains("not_after=0"));
        // Leaf is reduced to its base64 body (no PEM header), so whitespace/newlines
        // in the original PEM cannot change the signed bytes.
        assert!(s.contains("leaf=AAA"));
        assert!(!s.contains("-----BEGIN"));
    }

    #[test]
    fn pem_b64_body_ignores_whitespace_and_headers() {
        use super::pem_b64_body;
        let a = "-----BEGIN PUBLIC KEY-----\nMFkw EwYH\nKoZ==\n-----END PUBLIC KEY-----\n";
        let b = "-----BEGIN PUBLIC KEY-----\r\nMFkwEwYHKoZ==\r\n-----END PUBLIC KEY-----";
        assert_eq!(pem_b64_body(a), "MFkwEwYHKoZ==");
        assert_eq!(pem_b64_body(a), pem_b64_body(b));
    }

    // -- Adversarial extraction tests (the duplicate-label / first-match cases) ----

    /// First-occurrence binding: when the anchor appears more than once the
    /// extractor commits to the FIRST match. This is the stated semantic boundary,
    /// not a bug. The verifier reads the label from the journal and audits the
    /// label's uniqueness in the body if that matters to their use case.
    #[test]
    fn anchored_first_occurrence_is_bound_not_second() {
        let body = "Previous Balance: 5000.00 EUR\nCurrent Balance: 250.00 EUR";
        let v = extract_anchored(body, "Balance:", 30, &AnchoredKind::Number);
        assert_eq!(v.as_deref(), Some("5000.00"),
            "extractor must bind to the FIRST 'Balance:' occurrence");
    }

    /// Currency prefix: non-ASCII bytes (€ = 0xE2 0x82 0xAC) are skipped by the
    /// byte scanner and do not confuse the digit-start search.
    #[test]
    fn anchored_number_skips_currency_prefix() {
        let v = extract_anchored("Amount: \u{20AC}2847.50", "Amount:", 20, &AnchoredKind::Number);
        assert_eq!(v.as_deref(), Some("2847.50"));
    }

    /// Large number with thousand-group separators is collected in one token.
    #[test]
    fn anchored_number_large_with_separators() {
        let v = extract_anchored("Saldo: 1,000,000.00", "Saldo:", 20, &AnchoredKind::Number);
        assert_eq!(v.as_deref(), Some("1,000,000.00"));
    }

    /// EU-format negative balance: sign is preserved and commas/dots are kept as-is.
    #[test]
    fn anchored_number_negative_eu_format() {
        let v = extract_anchored("Balance: -2.847,50 EUR", "Balance:", 20, &AnchoredKind::Number);
        assert_eq!(v.as_deref(), Some("-2.847,50"));
    }

    /// Anchor absent entirely: returns None.
    #[test]
    fn anchored_returns_none_when_anchor_absent() {
        let v = extract_anchored("Amount: 100.00", "Balance:", 20, &AnchoredKind::Number);
        assert!(v.is_none(), "must return None when anchor is not present");
    }

    /// Literal outside window: when the literal is beyond the window, returns None.
    #[test]
    fn anchored_literal_beyond_window_returns_none() {
        // Window of 5 bytes after "Name:" cannot reach "Alice" (7 bytes away incl. space).
        let v = extract_anchored("Name:  Alice", "Name:", 5,
            &AnchoredKind::Literal("Alice".to_string()));
        assert!(v.is_none(), "literal beyond window must return None");
    }
    // -- Anchored dates (added 2026-09-05, KI-20) ---------------------------

    #[test]
    fn anchored_date_iso() {
        let v = extract_anchored("Issued: 2026-03-09 by the registry", "Issued:", 40,
            &AnchoredKind::Date(DateFormat::Iso));
        assert_eq!(v, Some("2026-03-09".to_string()));
    }

    #[test]
    fn anchored_date_european_slash_is_day_first() {
        let v = extract_anchored("Data: 01/02/2026", "Data:", 20,
            &AnchoredKind::Date(DateFormat::DmySlash));
        assert_eq!(v, Some("2026-02-01".to_string()));
    }

    #[test]
    fn anchored_date_us_slash_is_month_first() {
        // Same bytes as the test above; only the committed rule differs. This
        // is why the format is part of the rule and not inferred.
        let v = extract_anchored("Date: 01/02/2026", "Date:", 20,
            &AnchoredKind::Date(DateFormat::MdySlash));
        assert_eq!(v, Some("2026-01-02".to_string()));
    }

    #[test]
    fn anchored_date_portuguese_dot() {
        let v = extract_anchored("Validade: 31.12.2027", "Validade:", 20,
            &AnchoredKind::Date(DateFormat::DmyDot));
        assert_eq!(v, Some("2027-12-31".to_string()));
    }

    #[test]
    fn anchored_date_dash_dmy() {
        let v = extract_anchored("Expiry 15-08-2026", "Expiry", 20,
            &AnchoredKind::Date(DateFormat::DmyDash));
        assert_eq!(v, Some("2026-08-15".to_string()));
    }

    #[test]
    fn anchored_date_takes_first_match_not_a_later_one() {
        let v = extract_anchored("Opened: 2020-01-01 closed 2024-06-30", "Opened:", 60,
            &AnchoredKind::Date(DateFormat::Iso));
        assert_eq!(v, Some("2020-01-01".to_string()));
    }

    #[test]
    fn anchored_date_rejects_impossible_calendar_dates() {
        assert!(extract_anchored("On 2026-02-30 nothing", "On", 30,
            &AnchoredKind::Date(DateFormat::Iso)).is_none());
        assert!(extract_anchored("On 2026-13-01 nothing", "On", 30,
            &AnchoredKind::Date(DateFormat::Iso)).is_none());
        assert!(extract_anchored("On 2026-00-10 nothing", "On", 30,
            &AnchoredKind::Date(DateFormat::Iso)).is_none());
    }

    #[test]
    fn anchored_date_leap_year_rule() {
        assert_eq!(extract_anchored("D: 2024-02-29", "D:", 20,
            &AnchoredKind::Date(DateFormat::Iso)), Some("2024-02-29".to_string()));
        assert!(extract_anchored("D: 2026-02-29", "D:", 20,
            &AnchoredKind::Date(DateFormat::Iso)).is_none());
        // 1900 is not a leap year under the Gregorian century rule; 2000 is.
        assert!(extract_anchored("D: 1900-02-29", "D:", 20,
            &AnchoredKind::Date(DateFormat::Iso)).is_none());
        assert_eq!(extract_anchored("D: 2000-02-29", "D:", 20,
            &AnchoredKind::Date(DateFormat::Iso)), Some("2000-02-29".to_string()));
    }

    #[test]
    fn anchored_date_does_not_match_inside_a_longer_digit_run() {
        // An account number must not be read as a date.
        assert!(extract_anchored("Acct: 12026-03-091", "Acct:", 30,
            &AnchoredKind::Date(DateFormat::Iso)).is_none());
    }

    #[test]
    fn anchored_date_absent_returns_none() {
        assert!(extract_anchored("Issued: soon", "Issued:", 30,
            &AnchoredKind::Date(DateFormat::Iso)).is_none());
    }

    #[test]
    fn anchored_date_respects_the_window() {
        let body = "Issued:                                        2026-03-09";
        assert!(extract_anchored(body, "Issued:", 10,
            &AnchoredKind::Date(DateFormat::Iso)).is_none());
        assert_eq!(extract_anchored(body, "Issued:", 60,
            &AnchoredKind::Date(DateFormat::Iso)), Some("2026-03-09".to_string()));
    }

    #[test]
    fn anchored_date_host_and_guest_agree() {
        // The whole point of the shared function: two callers, one value.
        let body = "Nascimento: 07/11/1999 ...";
        let a = extract_anchored(body, "Nascimento:", 30, &AnchoredKind::Date(DateFormat::DmySlash));
        let b = extract_anchored(body, "Nascimento:", 30, &AnchoredKind::Date(DateFormat::DmySlash));
        assert_eq!(a, b);
        assert_eq!(a, Some("1999-11-07".to_string()));
    }
    // -- Salted body commitment (metadata-leakage fix, 2026-09-05) ----------

    use super::{parse_salt, commitment_preimage, commitment_scheme, COMMIT_SALTED, COMMIT_UNSALTED};

    #[test]
    fn empty_salt_means_unsalted_and_says_so() {
        let s = parse_salt("").unwrap();
        assert!(s.is_none());
        assert_eq!(commitment_scheme(s.as_deref()), COMMIT_UNSALTED);
        assert_eq!(commitment_preimage(s.as_deref(), b"body"), b"body".to_vec());
    }

    #[test]
    fn a_valid_salt_prefixes_the_body_and_says_so() {
        let s = parse_salt("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(commitment_scheme(s.as_deref()), COMMIT_SALTED);
        let pre = commitment_preimage(s.as_deref(), b"body");
        assert_eq!(&pre[..16], &[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
        assert_eq!(&pre[16..], b"body");
    }

    #[test]
    fn a_short_salt_is_refused_because_it_would_be_enumerable() {
        // 64 bits is inside reach of a determined search; the whole point of the
        // change is to put the commitment out of reach, so a short salt must not
        // be silently accepted.
        assert!(parse_salt("0001020304050607").is_err());
    }

    #[test]
    fn a_malformed_salt_errors_and_does_not_degrade_to_unsalted() {
        // The dangerous failure mode: garbage in, no salt out, and a prover who
        // believes they are protected. It must be an error, not a fallback.
        assert!(parse_salt("zz0102030405060708090a0b0c0d0e0f").is_err());
        assert!(parse_salt("abc").is_err());
    }

    #[test]
    fn different_salts_give_different_commitments_over_the_same_body() {
        // This is the unlinkability property: two proofs over one captured page
        // must not carry the same fingerprint.
        let a = parse_salt("000102030405060708090a0b0c0d0e0f").unwrap();
        let b = parse_salt("0f0e0d0c0b0a09080706050403020100").unwrap();
        assert_ne!(commitment_preimage(a.as_deref(), b"same body"),
                   commitment_preimage(b.as_deref(), b"same body"));
    }

    #[test]
    fn revealing_the_salt_reproduces_the_commitment() {
        // Provenance on demand: a prover who later reveals the salt lets a verifier
        // recompute the journal value from the body they hold.
        let s = parse_salt("00112233445566778899aabbccddeeff").unwrap();
        let once  = commitment_preimage(s.as_deref(), b"the signed body");
        let again = commitment_preimage(parse_salt("00112233445566778899aabbccddeeff").unwrap().as_deref(),
                                        b"the signed body");
        assert_eq!(once, again);
    }
    // -- Value commitments in the journal (2026-09-05) ----------------------

    use super::{value_commitment_preimage, predicate_operand, redact_predicate, VALUE_TAG};

    fn fake_hash(b: &[u8]) -> String { format!("{:04x}", b.iter().map(|x| *x as u32).sum::<u32>()) }

    #[test]
    fn equality_operands_are_values_and_thresholds_are_not() {
        assert_eq!(predicate_operand("== Alice Smith").map(|(o,v,h)| (o,v,h)),
                   Some(("==", "Alice Smith", true)));
        assert_eq!(predicate_operand("!= 0").map(|(_,_,h)| h), Some(true));
        assert_eq!(predicate_operand("contains Lda").map(|(_,_,h)| h), Some(true));
        // A bound is the statement the prover chose to make; it stays visible.
        assert_eq!(predicate_operand("> 1000").map(|(_,_,h)| h), Some(false));
        assert_eq!(predicate_operand(">= 18").map(|(_,_,h)| h), Some(false));
        // Age compares a derived number to a bound, never a value.
        assert_eq!(predicate_operand("age >= 18"), None);
    }

    #[test]
    fn an_equality_operand_is_hidden_when_salted() {
        let salt = super::parse_salt("000102030405060708090a0b0c0d0e0f").unwrap();
        let out = redact_predicate("== Alice Smith", salt.as_deref(), fake_hash);
        assert!(out.starts_with("== h:"), "{out}");
        assert!(!out.contains("Alice"), "the name must not survive: {out}");
    }

    #[test]
    fn a_threshold_survives_redaction_unchanged() {
        let salt = super::parse_salt("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(redact_predicate("> 1000", salt.as_deref(), fake_hash), "> 1000");
    }

    #[test]
    fn without_a_salt_the_predicate_is_left_alone_rather_than_faked() {
        // Emitting `h:...` with no salt would look private and be enumerable in
        // one pass. Publishing plainly is the honest failure.
        assert_eq!(redact_predicate("== Alice Smith", None, fake_hash), "== Alice Smith");
        assert!(value_commitment_preimage(None, "Alice Smith").is_none());
    }

    #[test]
    fn value_commitments_are_domain_separated_from_body_commitments() {
        let salt = super::parse_salt("000102030405060708090a0b0c0d0e0f").unwrap();
        let v = value_commitment_preimage(salt.as_deref(), "x").unwrap();
        let b = super::commitment_preimage(salt.as_deref(), b"x");
        assert_ne!(v, b);
        assert!(v.starts_with(VALUE_TAG));
    }

    #[test]
    fn the_same_value_under_different_salts_commits_differently() {
        let a = super::parse_salt("000102030405060708090a0b0c0d0e0f").unwrap();
        let b = super::parse_salt("0f0e0d0c0b0a09080706050403020100").unwrap();
        assert_ne!(value_commitment_preimage(a.as_deref(), "Alice Smith"),
                   value_commitment_preimage(b.as_deref(), "Alice Smith"));
    }
}
