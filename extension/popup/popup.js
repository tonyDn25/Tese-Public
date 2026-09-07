// GPS, popup.js v4 (multi-field)

const $ = id => document.getElementById(id);

// -- State ------------------------------------------------------------------
const state = {
  // Current in-progress field selection (cleared after being pushed to fields[])
  selectedText:    null,
  selectedField:   null,
  selectedLabel:   '',
  selectedSession: null,   // path to session_*.json
  selectedUrl:     '/',
  // Accumulated field+predicate pairs ready for proving
  // Each entry: { text, field, predicate }
  fields:          [],
  lastProof:       null,
};

// -- DOM refs ---------------------------------------------------------------
const hostDot          = $('host-dot');
const hostText         = $('host-text');
const selectBtn        = $('select-btn');
const selectedDisplay  = $('selected-display');
const selectedValue    = $('selected-value');
const selectedPath     = $('selected-path');
const pathEditRow      = $('path-edit-row');
const pathInput        = $('path-input');
const pathSaveBtn      = $('path-save-btn');
const pathEditBtn      = $('path-edit-btn');
const predicateInput   = $('predicate-input');
const predicateField   = $('predicate-field-preview');
const addAnotherPrompt = $('add-another-prompt');
const addAnotherYes    = $('add-another-yes');
const addAnotherNo     = $('add-another-no');
const fieldsList       = $('fields-list');
const step3Label       = $('step3-label');
const devMode          = $('dev-mode');
const proveBtn         = $('prove-btn');
const progress         = $('progress');
const progressText     = $('progress-text');
const errorBox         = $('error-box');
const resultBox        = $('result-box');
const resultHeader     = $('result-header');
const proofJson        = $('proof-json');
const copyBtn          = $('copy-btn');
const downloadBtn      = $('download-btn');
const pdfInputRow      = $('pdf-input-row');
const pdfValueInput    = $('pdf-value-input');
const pdfValueConfirm  = $('pdf-value-confirm');
const pdfHint          = $('pdf-hint');

// -- Helpers ----------------------------------------------------------------
function showError(msg) { errorBox.textContent = msg; errorBox.classList.remove('hidden'); }
function clearError()   { errorBox.classList.add('hidden'); errorBox.textContent = ''; }
function clearResult()  { resultBox.classList.add('hidden'); state.lastProof = null; }
function setProving(active) {
  proveBtn.disabled = active;
  progress.classList.toggle('hidden', !active);
}

function bg(action, extra = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action, ...extra }, (response) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(response);
    });
  });
}

// -- Init -------------------------------------------------------------------
async function init() {
  // Defer async work so popup renders fully before JS blocks, fixes Firefox
  // eating the first click while the ping is in flight.
  await new Promise(r => setTimeout(r, 0));
  try {
    const ping = await bg('ping_host');
    if (ping?.pong) {
      hostDot.className = 'dot dot-green';
      hostText.textContent = `GPS host v${ping.version || '?'} ready`;
    } else {
      hostDot.className = 'dot dot-red';
      hostText.textContent = 'host error';
    }
  } catch (e) {
    hostDot.className = 'dot dot-red';
    hostText.textContent = 'host not found';
  }

  // Field selection is always available; the extension captures signed pages directly.
  selectBtn.disabled = false;

  chrome.storage.local.get(
    ['selectedText', 'selectedField', 'selectedSession', 'selectedUrl', 'pendingFields'],
    (stored) => {
      // Restore accumulated fields from previous popup session
      if (Array.isArray(stored.pendingFields) && stored.pendingFields.length > 0) {
        state.fields = stored.pendingFields;
        renderFieldsList();
      }

      // Restore any pending single-field selection
      if (stored.selectedText) {
        state.selectedText    = stored.selectedText;
        state.selectedField   = stored.selectedField || '';
        state.selectedSession = stored.selectedSession || null;
        state.selectedUrl     = stored.selectedUrl || '/';
        showSelectedField(state.selectedText, state.selectedField);
      }
      // Detect if current tab is a PDF
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          const tabUrl = tabs[0].url || '';
          const isPdf  = tabUrl.endsWith('.pdf') || tabUrl.includes('.pdf?');
          if (isPdf) {
            selectBtn.classList.add('hidden');
            pdfInputRow.classList.remove('hidden');
            pdfHint.classList.remove('hidden');
            state.selectedUrl = new URL(tabUrl).pathname;
          }
        }
      });

      updateProveBtn();
    }
  );
}

// -- Field selection --------------------------------------------------------
selectBtn.addEventListener('click', async () => {
  clearError(); clearResult();
  selectBtn.textContent = ' Click any value on the page…';
  selectBtn.classList.add('active');
  // Hide the "add another?" prompt while re-selecting
  addAnotherPrompt.classList.add('hidden');
  try {
    await bg('start_field_selection');
    window.close();
  } catch (e) {
    selectBtn.textContent = ' Click to select field';
    selectBtn.classList.remove('active');
    showError('Could not start selection: ' + e.message);
  }
});

// content.js → background → popup: field was clicked on the page
chrome.runtime.onMessage.addListener((message) => {
  if (message.action === 'field_ready') {
    state.selectedText    = message.text;
    state.selectedField   = message.field || '';
    state.selectedLabel   = message.label || '';
    state.selectedSession = message.session || null;
    state.selectedUrl     = message.url || '/';
    // Clear predicate input for the new field
    predicateInput.value = '';
    addAnotherPrompt.classList.add('hidden');
    showSelectedField(state.selectedText, state.selectedField);
    updateProveBtn();
  }
});

function showSelectedField(text, fieldPath) {
  selectedDisplay.classList.remove('hidden');
  selectedValue.textContent = text;
  if (fieldPath) {
    const isRegex = fieldPath.startsWith('regex:');
    selectedPath.textContent = (isRegex ? fieldPath.replace('regex:', '') : fieldPath)
      + (isRegex ? ' [regex]' : ' [json]');
    selectedPath.className = isRegex ? 'selected-path regex' : 'selected-path';
    predicateField.textContent = isRegex ? 'match' : fieldPath;
  } else {
    selectedPath.textContent = 'path not found, edit manually';
    selectedPath.className = 'selected-path unknown';
    predicateField.textContent = '?';
    pathEditRow.classList.remove('hidden');
    pathInput.value = '';
    pathInput.focus();
  }
  predicateInput.disabled = false;
  pathEditBtn.textContent = fieldPath ? ' Edit path manually' : ' Type path manually';
}

// -- Path edit --------------------------------------------------------------
// -- PDF manual value input -----------------------------------------------
pdfValueConfirm.addEventListener('click', () => {
  const val = pdfValueInput.value.trim();
  if (!val) return;
  // Build a simple regex: escaped exact match
  const escaped = val.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const fieldSpec = `regex:${escaped}|||${val.slice(0, 30)}`;
  state.selectedText  = val;
  state.selectedField = fieldSpec;
  // session will be resolved at prove time via list_sessions
  showSelectedField(val, fieldSpec);
  updateProveBtn();
});

pdfValueInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') pdfValueConfirm.click();
});

pathEditBtn.addEventListener('click', () => {
  pathEditRow.classList.toggle('hidden');
  if (!pathEditRow.classList.contains('hidden')) {
    pathInput.value = state.selectedField || '';
    pathInput.focus();
  }
});

pathSaveBtn.addEventListener('click', () => {
  const newPath = pathInput.value.trim();
  if (!newPath) return;
  state.selectedField = newPath;
  chrome.storage.local.set({ selectedField: newPath });
  selectedPath.textContent = newPath;
  selectedPath.className = 'selected-path';
  predicateField.textContent = newPath;
  pathEditRow.classList.add('hidden');
  updateProveBtn();
});

pathInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') pathSaveBtn.click();
  if (e.key === 'Escape') pathEditRow.classList.add('hidden');
});

// -- Predicate Enter → show "add another?" prompt --------------------------
predicateInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    const predicate = predicateInput.value.trim();
    if (!predicate) return;
    if (!state.selectedField) return;
    // Commit the field immediately on Enter
    commitCurrentField();
    // Reset Steps 1 & 2 for optional next field
    selectedDisplay.classList.add('hidden');
    predicateInput.value = '';
    predicateInput.disabled = true;
    predicateField.textContent = '\u2013';
    pathEditRow.classList.add('hidden');
    state.selectedText  = null;
    state.selectedField = null;
    selectBtn.textContent = ' Click to select next field';
    selectBtn.classList.remove('active');
    addAnotherPrompt.classList.add('hidden');
    clearError();
  }
});

// Prompt is shown on Enter only (blur removed, it raced with button clicks)

// -- "Add another field" ----------------------------------------------------
addAnotherYes.addEventListener('click', () => {
  commitCurrentField();
  // Reset Steps 1 & 2 for the next selection
  addAnotherPrompt.classList.add('hidden');
  selectedDisplay.classList.add('hidden');
  predicateInput.value = '';
  predicateInput.disabled = true;
  predicateField.textContent = '\u2013';
  pathEditRow.classList.add('hidden');
  state.selectedText  = null;
  state.selectedField = null;
  selectBtn.textContent = ' Click to select next field';
  selectBtn.classList.remove('active');
  clearError();
});

if (addAnotherNo) {
  addAnotherNo.addEventListener('click', () => {
    addAnotherPrompt.classList.add('hidden');
  });
}



// Push the current in-progress field+predicate into state.fields[]
// The host splits a field spec on "|||" into pattern and label, and falls back to
// using the WHOLE PATTERN as the label when the separator is absent. The extension
// never sent one, so a journal read `field_label: "NIF.{0,300}?([+-]?[0-9][0-9.,]*)"`:
// a raw regex sitting in the field a verifier reads as the field's name, while
// `field_selected` already carries the rule properly. The content script knows the
// on-page label; carry it through.
function labelledField(spec, label) {
  if (!spec || !spec.startsWith('regex:') || spec.includes('|||')) return spec;
  const clean = (label || '').trim().replace(/\|/g, ' ').slice(0, 40);
  return clean ? `${spec}|||${clean}` : spec;
}

function commitCurrentField() {
  const predicate = predicateInput.value.trim();
  if (!state.selectedField || !predicate) return;
  state.fields.push({
    text:      state.selectedText,
    field:     labelledField(state.selectedField, state.selectedLabel),
    predicate,
    session:   state.selectedSession,
    url:       state.selectedUrl,
  });
  chrome.storage.local.set({ pendingFields: state.fields });
  renderFieldsList();
  updateProveBtn();
}

// -- Fields list (Step 3 accumulator) --------------------------------------
function renderFieldsList() {
  const count = state.fields.length;
  if (count === 0) {
    fieldsList.classList.add('hidden');
    step3Label.textContent = 'Generate ZK Proof';
    return;
  }

  step3Label.textContent = `Generate ZK Proof (${count} field${count > 1 ? 's' : ''})`;
  fieldsList.classList.remove('hidden');
  fieldsList.innerHTML = '';

  state.fields.forEach((f, i) => {
    const item = document.createElement('div');
    item.className = 'field-item';
    item.innerHTML = `
      <div class="field-item-body">
        <span class="field-item-value">${escHtml(f.text)}</span>
        <span class="field-item-pred">${escHtml(f.predicate)}</span>
      </div>
      <button class="field-item-remove" data-idx="${i}" title="Remove">X</button>
    `;
    fieldsList.appendChild(item);
  });

  fieldsList.querySelectorAll('.field-item-remove').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx, 10);
      state.fields.splice(idx, 1);
      chrome.storage.local.set({ pendingFields: state.fields });
      if (state.fields.length === 0) chrome.storage.local.remove('pendingFields');
      renderFieldsList();
      updateProveBtn();
    });
  });
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// -- Prove button state -----------------------------------------------------
function updateProveBtn() {
  // Enabled if there's at least one committed field ready (fields[])
  // OR there's a current in-progress field+predicate with "prove now" clicked.
  proveBtn.disabled = state.fields.length === 0;
}

predicateInput.addEventListener('input', () => {
  // Hide prompt while user is still typing
  if (predicateInput.value.trim() === '') {
    addAnotherPrompt.classList.add('hidden');
  }
});

// -- Generate proof ---------------------------------------------------------
proveBtn.addEventListener('click', async () => {
  if (state.fields.length === 0) { showError('No fields to prove.'); return; }

  clearResult(); clearError(); setProving(true);
  progressText.textContent = devMode.checked
    ? `Generating proof (dev mode, fast)…`
    : `Generating ZK proof (may take several minutes)…`;

  // Always use the most recent session, the tab session gets updated
  // on every navigation so the stored path may be stale.
  let session = null;
  const url   = state.fields[0].url || state.selectedUrl || '/';

  try {
    const listResult = await bg('list_sessions');
    if (!listResult?.ok || !listResult.sessions?.length) {
      setProving(false);
      showError('No signed session found. Browse a GPS-signed page first.');
      return;
    }
    // Pick the session that contains the target URL
    const targetPath = url.split('?')[0];
    const match = listResult.sessions.find(s =>
      s.pages && s.pages.some(p => p.path === targetPath)
    );
    session = match ? match.path : listResult.sessions[0].path;
  } catch (e) {
    setProving(false);
    showError('GPS host error: ' + e.message);
    return;
  }

  try {
    // Build the fields array with per-field session+url for multi-page support
    const fieldsPayload = state.fields.map(f => ({
      field:     f.field,
      predicate: f.predicate,
      session:   f.session || session,
      url:       f.url    || url,
    }));

    const res = await bg('generate_proof', {
      session,
      url,
      // Multi-field format: pass fields array. background.js should forward
      // this as-is to the host native messaging.
      fields:   fieldsPayload,
      dev_mode: devMode.checked,
    });

    setProving(false);

    if (res?.ok) {
      showResult(res.proof);
      // Clear accumulated fields after a successful proof
      state.fields = [];
      chrome.storage.local.remove('pendingFields');
      renderFieldsList();
    } else {
      const err = res?.error || 'Proof generation failed.';
      if (err.includes('evaluated to FALSE')) {
        // The guest's panic text still carries an em dash and CANNOT be changed:
        // editing the guest alters its ELF and therefore the image_id, which would
        // invalidate every shipped proof. Parse it if present, tolerate it if not.
        const detail = err.includes('\u2014') ? err.split('\u2014')[1]?.trim() : err.trim();
        showError('Predicate is FALSE. ' + (detail ?? ''));
      } else {
        showError(err);
      }
    }
  } catch (e) {
    setProving(false);
    showError('Proof error: ' + e.message);
  }
});

// -- Show result ------------------------------------------------------------
function showResult(proof) {
  if (!proof) { showError('Empty proof returned.'); return; }

  const j = proof.journal || {};

  // Multi-field: journal has field_results[]
  // Single-field (legacy): journal has predicate_result + predicate_statement
  if (Array.isArray(j.field_results) && j.field_results.length > 0) {
    const allTrue = j.field_results.every(r => r.predicate_result);
    const lines = j.field_results.map(r =>
      `${r.predicate_result ? 'OK' : 'FAIL'} ${r.predicate_statement}`
    );
    resultHeader.innerHTML = lines.map((l, i) =>
      `<div class="${j.field_results[i].predicate_result ? 'result-field-true' : 'result-field-false'}">${escHtml(l)}</div>`
    ).join('');
    resultHeader.className = `result-header ${allTrue ? 'true' : 'false'}`;
  } else {
    // Legacy single-field path
    const result = j.predicate_result ?? false;
    resultHeader.textContent = result
      ? `TRUE: ${j.predicate_statement}`
      : `FALSE: ${j.predicate_statement}`;
    resultHeader.className = `result-header ${result ? 'true' : 'false'}`;
  }

  state.lastProof = proof;
  proofJson.textContent = JSON.stringify(proof, null, 2);
  resultBox.classList.remove('hidden');
}

// -- Copy / Download --------------------------------------------------------
copyBtn.addEventListener('click', () => {
  if (!state.lastProof) return;
  navigator.clipboard.writeText(JSON.stringify(state.lastProof, null, 2)).then(() => {
    copyBtn.textContent = 'OK Copied!';
    setTimeout(() => { copyBtn.textContent = ' Copy JSON'; }, 2000);
  });
});

downloadBtn.addEventListener('click', () => {
  if (!state.lastProof) return;
  const json = JSON.stringify(state.lastProof, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const ts   = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const label = state.lastProof?.journal?.field_results?.length > 1
    ? `multi_${state.lastProof.journal.field_results.length}fields`
    : (state.lastProof?.journal?.field_label || 'field');
  const safe = label.replace(/[^a-z0-9]/gi, '_').slice(0, 24);
  const a = document.createElement('a');
  a.href = url; a.download = `gps_proof_${safe}_${ts}.json`; a.click();
  URL.revokeObjectURL(url);
  downloadBtn.textContent = 'OK Downloaded!';
  setTimeout(() => { downloadBtn.textContent = ' Download Proof'; }, 2000);
});

init();
