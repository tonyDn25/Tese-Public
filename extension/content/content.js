// GPS, content script v5
// Robust field extraction with 4-layer strategy:
//   1. Semantic HTML (label/input, dt/dd, th/td, aria-label)
//   2. Element attribute regex (id, class-based)
//   3. Context-anchored regex (label + value pattern)
//   4. Numeric/date fallback

(function () {
  if (window.__gpsLoaded) return;
  window.__gpsLoaded = true;

  let selectionMode = false;
  let step = 0;
  let labelEl = null;
  let labelText = '';
  let highlightEl = null;

  // -- Utilities -------------------------------------------------------------

  function getAncestors(el) {
    const ancestors = [];
    let cur = el;
    while (cur && cur !== document.body) { ancestors.push(cur); cur = cur.parentElement; }
    return ancestors;
  }

  function isGpsElement(el) { return el.id && el.id.startsWith('__gps'); }

  function lowestCommonAncestor(el1, el2) {
    const ancestors1 = new Set(getAncestors(el1));
    let cur = el2;
    while (cur && cur !== document.body) {
      if (ancestors1.has(cur)) return cur;
      cur = cur.parentElement;
    }
    return document.body;
  }

  function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function cleanText(el) {
    return (el.textContent || el.innerText || '').trim().replace(/\s+/g, ' ');
  }

  function currentUrlPath() { return window.location.pathname || '/'; }

  // -- Value pattern generator -----------------------------------------------
  // Converts a raw value string into the most appropriate regex capture group.
  // This is the core of robustness, the pattern must match in the signed body.

  // -- Numeric convention ----------------------------------------------------
  // A number pattern names the convention its value is written in, exactly as a
  // date pattern names its format. Emitting one convention-free shape was the
  // 2026-09-09 defect: the guest was left to infer a reading from whichever
  // separators appeared, and read "5.500" as five and a half, so a page stating
  // a balance of 5.500 could prove "< 1000".
  //
  // Each branch below produces the pattern the host lowers to exactly one
  // NumberFormat, and the guest commits that name to the journal, so the reading
  // a proof used is on the record instead of being guessed at both ends.
  const NUM_PLAIN = '([+-]?[0-9]+(\\.[0-9]+)?)';
  const NUM_EU    = '([+-]?[0-9]{1,3}(\\.[0-9]{3})+(,[0-9]+)?)';
  const NUM_EU_DEC= '([+-]?[0-9]+,[0-9]+)';
  const NUM_US    = '([+-]?[0-9]{1,3}(,[0-9]{3})+(\\.[0-9]+)?)';

  // Locales that write thousands with a dot and decimals with a comma. Consulted
  // ONLY for the one string shape that is genuinely ambiguous (see below), and
  // the outcome is committed to the journal either way.
  const EU_DECIMAL_LANGS = /^(pt|es|de|it|nl|da|fi|sv|nb|no|is|tr|id|vi|ro|el|pl|cs|sk|sl|hr|sr|bg|ru|uk|lt|lv|et|hu|ca|gl|eu|af)\b/i;

  function pageWritesDecimalsWithComma() {
    const lang = (document.documentElement.getAttribute('lang') || navigator.language || '').trim();
    return EU_DECIMAL_LANGS.test(lang);
  }

  function numberPattern(valueText) {
    // Strip a trailing currency word and any sign, leaving the digits and
    // separators that decide the convention.
    const core = valueText.trim().replace(/\s*[A-Za-z€$£]{0,3}\s*$/, '').replace(/^[+-]/, '');
    const lastDot   = core.lastIndexOf('.');
    const lastComma = core.lastIndexOf(',');

    // Both separators present: the LAST one is the decimal point, which settles
    // the convention with no guessing at all.
    if (lastDot >= 0 && lastComma >= 0) {
      return lastComma > lastDot ? NUM_EU : NUM_US;
    }
    // Commas only: a run of three-digit groups is US thousands, anything else is
    // a decimal comma.
    if (lastComma >= 0) {
      return /^[0-9]{1,3}(,[0-9]{3})+$/.test(core) ? NUM_US : NUM_EU_DEC;
    }
    // Dots only.
    if (lastDot >= 0) {
      // Two or more dots can only be thousands grouping; a single decimal point
      // cannot appear twice.
      if ((core.match(/\./g) || []).length > 1) return NUM_EU;
      // Exactly one dot with one to three digits before it and exactly three
      // after is the one shape both conventions accept: 5.500 is 5.5 under a
      // plain reading and 5500 under a European one, and the digits alone cannot
      // decide. The page's declared language is the only evidence available, it
      // is a heuristic and it is recorded as one; whichever way it falls, the
      // convention is named in the rule and committed to the journal, so the
      // reading is auditable rather than silent.
      if (/^[0-9]{1,3}\.[0-9]{3}$/.test(core)) {
        return pageWritesDecimalsWithComma() ? NUM_EU : NUM_PLAIN;
      }
      return NUM_PLAIN;
    }
    return NUM_PLAIN;
  }

  // The convention a pattern names, for display in the popup so the user sees
  // the reading before paying for a proof.
  function patternNumberFormat(pattern) {
    if (pattern === NUM_EU || pattern === NUM_EU_DEC) return 'EuGrouped';
    if (pattern === NUM_US) return 'UsGrouped';
    if (pattern === NUM_PLAIN) return 'Plain';
    return null;
  }

  function valueToPattern(valueText) {
    const v = valueText.trim();

    // Dates. Each civil format gets its OWN pattern, because the host lowers the
    // pattern to a named DateFormat and the guest commits that name to the
    // journal. Emitting one pattern for every shape was wrong twice over:
    // a YYYY/MM/DD page got a dash pattern that could never match its own body,
    // and a DD/MM/YYYY value was not recognised as a date at all, so it fell
    // through to the numeric branch below and bound the DAY as a number
    // (31/12/2027 proved "31"). Fixed 2026-09-05.
    if (v.match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/)) {
      return '([0-9]{4}-[0-9]{2}-[0-9]{2})';
    }
    if (v.match(/^[0-9]{4}\/[0-9]{2}\/[0-9]{2}$/)) {
      return '([0-9]{4}/[0-9]{2}/[0-9]{2})';
    }
    if (v.match(/^[0-9]{2}\/[0-9]{2}\/[0-9]{4}$/)) {
      return '([0-9]{2}/[0-9]{2}/[0-9]{4})';
    }
    if (v.match(/^[0-9]{2}-[0-9]{2}-[0-9]{4}$/)) {
      return '([0-9]{2}-[0-9]{2}-[0-9]{4})';
    }
    if (v.match(/^[0-9]{2}\.[0-9]{2}\.[0-9]{4}$/)) {
      return '([0-9]{2}\\.[0-9]{2}\\.[0-9]{4})';
    }

    // Boolean
    if (v === 'true' || v === 'false') {
      return `(${v})`;
    }

    // Pure numeric → numeric pattern; mixed alphanumeric (IBAN etc.) → exact match
    // Handles: "2500.00 EUR", "+1800.00 EUR", "-650.00", "123456789"
    if (v.match(/[0-9]/)) {
      // Number with optional currency suffix (2500.00 EUR, +1800.00 EUR) → numeric
      if (v.match(/^[+-]?[0-9][0-9.,]*\s*[A-Za-z]{0,3}$/)) {
        return numberPattern(v);
      }
      // Mixed alphanumeric (IBAN, codes) → exact match
      if (v.match(/[a-zA-Z]/) || v.match(/[0-9]\s+[0-9]/)) {
        return `(${escapeRegex(v.slice(0, 80))})`;
      }
      return numberPattern(v);
    }

  // Pure text, exact escaped match
    return `(${escapeRegex(v.slice(0, 80))})`;
  }

  // -- Layer 1: Semantic HTML extraction -------------------------------------
  // Try standard HTML semantic patterns before falling back to regex.

  function trySemanticExtraction(labelEl, valueEl, body) {
    // dt/dd pattern
    if (labelEl && labelEl.tagName === 'DT' && valueEl.tagName === 'DD') {
      const label = cleanText(labelEl);
      const valuePattern = valueToPattern(cleanText(valueEl));
      return `<dt[^>]*>${escapeRegex(label)}</dt>.*?<dd[^>]*>${valuePattern}`;
    }

    // th/td pattern
    if (labelEl && labelEl.tagName === 'TH' && valueEl.tagName === 'TD') {
      const label = cleanText(labelEl);
      const valuePattern = valueToPattern(cleanText(valueEl));
      return `<th[^>]*>${escapeRegex(label)}</th>.*?<td[^>]*>${valuePattern}`;
    }

    // label[for] → input[id] pattern
    if (labelEl && labelEl.tagName === 'LABEL') {
      const forAttr = labelEl.getAttribute('for');
      if (forAttr && valueEl.id === forAttr) {
        const valuePattern = valueToPattern(cleanText(valueEl));
        return `<[^>]+id="${escapeRegex(forAttr)}"[^>]*>${valuePattern}`;
      }
    }

    // aria-label pattern
    const ariaLabel = valueEl.getAttribute('aria-label') ||
                      valueEl.getAttribute('aria-labelledby');
    if (ariaLabel) {
      const valuePattern = valueToPattern(cleanText(valueEl));
      const tag = valueEl.tagName.toLowerCase();
      return `<${tag}[^>]*aria-label="${escapeRegex(ariaLabel)}"[^>]*>${valuePattern}`;
    }

    return null;
  }

  // -- Layer 2: Element attribute regex --------------------------------------
  // Use id or class attributes to anchor the match structurally.

  function tryAttributeRegex(valueEl, valueText) {
    const tag = valueEl.tagName.toLowerCase();
    const id  = valueEl.id;
    const cls = valueEl.className;
    const valuePattern = valueToPattern(valueText);

    // id-based (most specific)
    if (id && !id.startsWith('__gps')) {
      return `<${tag}[^>]+id="${escapeRegex(id)}"[^>]*>${valuePattern}`;
    }

    // class-based (use most specific class only)
    if (cls) {
      const classes = cls.trim().split(/\s+/);
      // Pick longest class name as most specific
      const best = classes.reduce((a, b) => a.length >= b.length ? a : b, '');
      if (best && best.length > 2) {
        return `<${tag}[^>]+class="[^"]*${escapeRegex(best)}[^"]*"[^>]*>${valuePattern}`;
      }
    }

    return null;
  }

  // -- Layer 3: Context-anchored regex ---------------------------------------
  // Label text + flexible gap + value capture. Most general, always works.

  function buildContextRegex(labelText, valueText) {
    const escapedLabel = escapeRegex(labelText.trim().slice(0, 60));
    const valuePattern = valueToPattern(valueText);
    return `${escapedLabel}.{0,300}?${valuePattern}`;
  }

  // -- Layer 4: Verify pattern against body ----------------------------------
  // Test that a regex actually matches the signed body before using it.
  // Falls back to next layer if it doesn't match.

  function patternMatchesBody(pattern, body) {
    try {
      const re = new RegExp(pattern);
      return re.test(body);
    } catch (e) {
      return false;
    }
  }

  // -- Pattern value verifier -----------------------------------------------
  // Check that the pattern extracts the CORRECT value, not just any match.

  function patternExtractsValue(pattern, body, expectedValue) {
    try {
      const re = new RegExp(pattern);
      const m = body.match(re);
      if (!m || !m[1]) return false;
      const extracted = m[1].trim();
      const expected  = expectedValue.trim();
      // Check exact match OR numeric core match
      if (extracted === expected) return true;
      const numExtracted = extracted.replace(/[^0-9.,]/g, '');
      const numExpected  = expected.replace(/[^0-9.,]/g, '');
      return numExtracted.length >= 2 && numExtracted === numExpected;
    } catch (e) {
      return false;
    }
  }

  // -- Master extractor ------------------------------------------------------
  // Order: semantic → context anchor → attribute → value-only
  // Each candidate is verified to extract the CORRECT value before use.
  // When a label is present, context anchor is always tried before attribute.

  function extractBestPattern(labelEl, labelText, valueEl, valueText, body) {
    const candidates = [];

    // Layer 1: semantic HTML (dt/dd, th/td, label[for])
    if (labelEl) {
      const semantic = trySemanticExtraction(labelEl, valueEl, body);
      if (semantic) candidates.push({ pattern: semantic, layer: 'semantic' });
    }

    // Layer 2: context anchor, PREFERRED when we have a label
    // Put this BEFORE attribute so label+value always beats attribute-only
    if (labelText && labelText.trim().length > 0) {
      const ctx = buildContextRegex(labelText, valueText);
      candidates.push({ pattern: ctx, layer: 'context' });
    }

    // Layer 3: attribute-based (id or class anchor)
    // Only use if no label, attribute patterns are ambiguous without label context
    if (!labelText || labelText.trim().length === 0) {
      const attrRegex = tryAttributeRegex(valueEl, valueText);
      if (attrRegex) candidates.push({ pattern: attrRegex, layer: 'attribute' });
    }

    // Layer 4: pure value pattern (absolute last resort, no label)
    if (!labelText || labelText.trim().length === 0) {
      candidates.push({ pattern: valueToPattern(valueText), layer: 'value-only' });
    }

    // Pick first candidate that both matches body AND extracts the correct value
    for (const c of candidates) {
      if (patternExtractsValue(c.pattern, body, valueText)) {
        console.log(`GPS: layer '${c.layer}' verified correct value: ${c.pattern.slice(0, 100)}`);
        return c.pattern;
      }
    }

    // All candidates failed verification, context anchor is safest fallback
    console.warn('GPS: no pattern verified, using context anchor fallback');
    if (labelText) {
      const ctx = buildContextRegex(labelText, valueText);
      console.warn('GPS: fallback pattern:', ctx);
      return ctx;
    }
    // No label at all, use attribute regex if available
    const attrRegex = tryAttributeRegex(valueEl, valueText);
    if (attrRegex) return attrRegex;
    return valueToPattern(valueText);
  }

  // -- JSON path finder ------------------------------------------------------

  function findPathInObject(obj, targetText, prefix) {
    const target = targetText.trim();
    for (const key of Object.keys(obj)) {
      const path = prefix ? `${prefix}.${key}` : key;
      const val = obj[key];
      if (val === null || val === undefined) continue;
      if (typeof val === 'object') {
        const found = findPathInObject(val, target, path);
        if (found) return found;
      } else if (String(val).trim() === target) {
        return { path, value: val };
      }
    }
    return null;
  }

  // -- Session finder --------------------------------------------------------

  async function findBestSessionForValue(valueText) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'list_sessions' }, async (res) => {
        if (!res?.ok || !res.sessions?.length) { resolve(null); return; }

        const currentPath = currentUrlPath();
        const currentHost = window.location.hostname;

        const candidates = [];
        for (const s of res.sessions) {
          const isDirect    = s.path && s.path.includes('session_direct_');
          const domainMatch = s.domain && s.domain.includes(currentHost);
          const score = (isDirect && domainMatch) ? 3
                      : domainMatch               ? 2
                      : isDirect                  ? 1
                      :                             0;
          candidates.push({ session: s, score });
        }
        candidates.sort((a, b) => b.score - a.score);

        const numericValue = valueText.replace(/[^0-9.,]/g, '');

        for (const { session: s } of candidates) {
          const body = await new Promise((res2) => {
            chrome.runtime.sendMessage(
              { action: 'read_body', path: s.path, url: currentPath },
              (data) => res2(data?.ok ? data.body : null)
            );
          });
          if (!body) continue;

          const bodyContainsValue =
            body.includes(valueText) ||
            (numericValue.length >= 2 && body.includes(numericValue));

          if (bodyContainsValue) {
            return resolve({ path: s.path, sessionId: s.session_id, body, urlPath: currentPath });
          }
        }

        // Last resort: best scored candidate
        if (candidates.length > 0) {
          const s = candidates[0].session;
          const body = await new Promise((res2) => {
            chrome.runtime.sendMessage(
              { action: 'read_body', path: s.path, url: currentPath },
              (data) => res2(data?.ok ? data.body : null)
            );
          });
          resolve({ path: s.path, sessionId: s.session_id, body, urlPath: currentPath });
        } else {
          resolve(null);
        }
      });
    });
  }

  // -- Two-click resolve -----------------------------------------------------

  async function resolveFromTwoClicks(labelEl, labelText, valueEl, valueText) {
    const found = await findBestSessionForValue(valueText);
    if (!found) return { field: '', fieldType: 'unknown', session: null, url: '/' };

    const { path, body, urlPath } = found;

    // Try JSON first
    try {
      const json = JSON.parse(body);
      const result = findPathInObject(json, valueText, '');
      if (result) return {
        field: result.path, fieldType: 'json',
        session: path, url: urlPath, label: labelText
      };
    } catch (_) {}

    // Multi-layer HTML extraction
    const pattern = extractBestPattern(labelEl, labelText, valueEl, valueText, body);

    // Verify rule-based pattern extracts correct value
    const ruleBasedOk = patternExtractsValue(pattern, body, valueText);

    if (ruleBasedOk) {
      console.log('GPS: rule-based extractor succeeded');
      return { field: 'regex:' + pattern, fieldType: 'regex', session: path, url: urlPath, label: labelText };
    }

    // Rule-based verification failed, but check if body actually contains the value
    // If it does, trust the context anchor pattern (it's likely correct)
    const numericValue = valueText.replace(/[^0-9]/g, '');
    const bodyHasValue = body.includes(valueText) ||
      (numericValue.length >= 3 && body.includes(numericValue));
    if (bodyHasValue && labelText && pattern.includes(labelText.slice(0, 10))) {
      console.log('GPS: rule-based pattern trusted (value confirmed in body)');
      return { field: 'regex:' + pattern, fieldType: 'regex', session: path, url: urlPath, label: labelText };
    }

    // Fall back to LLM agent only if truly needed
    console.log('GPS: rule-based failed, calling LLM agent...');
    const agentResult = await callFieldAgent(
      body, labelText, valueText,
      valueEl.outerHTML.slice(0, 300)
    );
    if (agentResult) {
      console.log('GPS: LLM agent pattern:', agentResult);
      return { field: 'regex:' + agentResult, fieldType: 'regex', session: path, url: urlPath, label: labelText };
    }

    // Both failed, return rule-based anyway, zkVM will catch it
    console.warn('GPS: both extractors failed, using rule-based fallback');
    return { field: 'regex:' + pattern, fieldType: 'regex', session: path, url: urlPath, label: labelText };
  }

  // -- Single-click resolve --------------------------------------------------

  async function resolveFromSingleClick(el, valueText) {
    const found = await findBestSessionForValue(valueText);
    if (!found) return { field: '', fieldType: 'unknown', session: null, url: '/' };

    const { path, body, urlPath } = found;

    try {
      const json = JSON.parse(body);
      const result = findPathInObject(json, valueText, '');
      if (result) return {
        field: result.path, fieldType: 'json',
        session: path, url: urlPath, label: result.path
      };
    } catch (_) {}

    // Single click: no label, use attribute or value-only pattern
    const pattern = extractBestPattern(null, '', el, valueText, body);
    return {
      field: 'regex:' + pattern,
      fieldType: 'regex',
      session: path,
      url: urlPath,
      label: valueText,
    };
  }


  // -- LLM Agent extractor --------------------------------------------------
  // Calls gps-host which calls ollama phi3:mini locally
  // Only invoked when rule-based extraction fails

  async function callFieldAgent(body, labelText, valueText, htmlContext) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'analyze_field',
        body:         body.slice(0, 8000), // limit to avoid huge messages
        label_text:   labelText,
        value_text:   valueText,
        html_context: htmlContext,
      }, (res) => {
        if (chrome.runtime.lastError) { resolve(null); return; }
        if (res?.ok && res.pattern && res.matches_expected !== false) {
          resolve(res.pattern);
        } else {
          console.warn('GPS agent failed:', res?.error);
          resolve(null);
        }
      });
    });
  }

  // -- UI helpers ------------------------------------------------------------

  function setBanner(text, color = '#1e40af') {
    let b = document.getElementById('__gps_banner');
    if (!b) {
      b = document.createElement('div');
      b.id = '__gps_banner';
      b.style.cssText = `position:fixed;top:16px;left:50%;transform:translateX(-50%);
        z-index:2147483648;color:white;padding:10px 24px;border-radius:24px;
        font:600 14px/1.4 system-ui,sans-serif;box-shadow:0 4px 16px rgba(0,0,0,0.35);
        pointer-events:none;white-space:nowrap;transition:background 0.2s;`;
      document.body.appendChild(b);
    }
    b.textContent = text;
    b.style.background = color;
  }

  function removeBanner() { document.getElementById('__gps_banner')?.remove(); }

  function highlightElement(el, color = '#3b82f6') {
    if (highlightEl && highlightEl !== el) {
      highlightEl.style.outline = '';
      highlightEl.style.outlineOffset = '';
    }
    el.style.outline = `2px solid ${color}`;
    el.style.outlineOffset = '2px';
    highlightEl = el;
  }

  function clearHighlight(el) {
    if (el) { el.style.outline = ''; el.style.outlineOffset = ''; }
  }

  // -- Selection mode --------------------------------------------------------

  function startSelectionMode() {
    if (selectionMode) return;
    selectionMode = true;
    step = 1;
    labelEl = null;
    labelText = '';
    setBanner('  GPS: Click the field LABEL  (e.g. "Account Balance")', '#1e40af');
    document.addEventListener('mouseover', onMouseOver, true);
    document.addEventListener('click', onClick, true);
    document.addEventListener('keydown', onKeyDown, true);
  }

  function stopSelectionMode() {
    selectionMode = false;
    step = 0;
    labelEl = null;
    labelText = '';
    removeBanner();
    clearHighlight(highlightEl);
    highlightEl = null;
    document.removeEventListener('mouseover', onMouseOver, true);
    document.removeEventListener('click', onClick, true);
    document.removeEventListener('keydown', onKeyDown, true);
  }

  function onMouseOver(e) {
    if (!selectionMode) return;
    highlightElement(e.target, step === 1 ? '#f59e0b' : '#22c55e');
  }

  async function onClick(e) {
    if (!selectionMode) return;
    e.preventDefault();
    e.stopPropagation();

    const el = e.target;
    if (isGpsElement(el)) return;
    const text = cleanText(el);
    if (!text) return;

    if (step === 1) {
      labelEl = el;
      labelText = text;
      clearHighlight(el);
      el.style.outline = '2px solid #f59e0b';
      el.style.outlineOffset = '2px';
      step = 2;
      setBanner(`OK Label: "${labelText.slice(0,30)}"  ::  Now click the VALUE`, '#7c3aed');

    } else if (step === 2) {
      const valueEl = el;
      const valueText = text;
      setBanner(' GPS: Analysing field…', '#6b7280');
      document.removeEventListener('mouseover', onMouseOver, true);
      document.removeEventListener('click', onClick, true);

      let result;
      if (labelEl && labelText && labelEl !== valueEl) {
        result = await resolveFromTwoClicks(labelEl, labelText, valueEl, valueText);
      } else {
        result = await resolveFromSingleClick(valueEl, valueText);
      }

      stopSelectionMode();

      chrome.runtime.sendMessage({
        action:     'field_selected',
        text:       valueText,
        field:      result.field,
        fieldType:  result.fieldType,
        fieldLabel: result.label || labelText || valueText,
        session:    result.session || '',
        url:        result.url || '/',
        rawText:    valueText,
      });
    }
  }

  function onKeyDown(e) {
    if (e.key === 'Escape') stopSelectionMode();
    if (e.key === 'Tab' && step === 1) {
      labelEl = null;
      labelText = '';
      step = 2;
      setBanner('  GPS: Click the VALUE directly', '#059669');
      e.preventDefault();
    }
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'start_selection') { startSelectionMode(); sendResponse({ ok: true }); }
    if (message.action === 'stop_selection')  { stopSelectionMode();  sendResponse({ ok: true }); }
    if (message.action === 'get_page_body')   { sendResponse({ body: document.documentElement.outerHTML }); }
  });

})();
