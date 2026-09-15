// GPS, background service worker v3
// Capture: the extension records GPS-signed responses via the webRequest API
// (x-gps-signed header), fetches the byte-identical body, and saves the session
// to disk through the native host.

const NATIVE_HOST = 'pt.ist.gps_host';

const keepAlive = () => setInterval(chrome.runtime.getPlatformInfo, 20_000);
chrome.runtime.onStartup.addListener(keepAlive);
keepAlive();

// -- In-memory transcript store (direct mode) ----------------------------------
// Key: tabId → { session_id, domain, pages: [...] }
const inMemorySessions = new Map();
// Key: requestId → { method, url, tabId }
const pendingRequests  = new Map();

// -- webRequest: capture outgoing requests -------------------------------------
chrome.webRequest.onBeforeSendHeaders.addListener(
    (details) => {
        if (details.method !== 'GET' && details.method !== 'POST') return;
        if (typeof details.tabId !== 'number' || details.tabId < 0) return;
        if (details.originUrl && details.originUrl.startsWith('moz-extension://')) return;
        pendingRequests.set(details.requestId, {
            method: details.method,
            url:    details.url,
            tabId:  details.tabId,
        });
    },
    { urls: ['https://*/*'] },
    ['requestHeaders']
);

// -- webRequest: capture GPS-signed responses ----------------------------------
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        const req = pendingRequests.get(details.requestId);
        pendingRequests.delete(details.requestId);
        if (!req) return;

        // No tab means this is the extension's own body fetch. Recording it would
        // make each fetch record the page again and schedule another fetch.
        if (typeof req.tabId !== 'number' || req.tabId < 0) return;

        // Check if this is a GPS-signed response
        const headers = {};
        let isGpsSigned = false;
        for (const h of details.responseHeaders || []) {
            headers[h.name.toLowerCase()] = h.value;
            if (h.name.toLowerCase() === 'x-gps-signed' && h.value === 'true') {
                isGpsSigned = true;
            }
        }
        if (!isGpsSigned) return;

        // We have a GPS-signed response, need to fetch the body
        // We can't get body in webRequest, so we store the headers
        // and fetch the body separately via a content script message
        const urlObj    = new URL(req.url);
        const authority = urlObj.host;
        const tabId     = req.tabId;

        if (!inMemorySessions.has(tabId)) {
            inMemorySessions.set(tabId, {
                session_id: crypto.randomUUID(),
                domain:     authority,
                started_at: Math.floor(Date.now() / 1000).toString(),
                ended_at:   '',
                pages:      [],
            });
        }

        const session = inMemorySessions.get(tabId);

        // One capture per path per session, keeping the newest. Checked against
        // all pages, not only fetched ones, because several captures of one path
        // can be in flight at once.
        const path = urlObj.pathname + urlObj.search;
        const existing = session.pages.findIndex(p => p.request.path === path);

        // Store pending page, body will be filled by content script
        const page = {
            id:        crypto.randomUUID(),
            timestamp: (headers['x-gps-timestamp'] || Math.floor(Date.now()/1000).toString()),
            domain:    authority,
            request: {
                method:  req.method,
                path:    urlObj.pathname + urlObj.search,
                headers: { host: authority },
            },
            response: {
                status:  details.statusCode,
                body:    '', // filled later by content script
                headers: headers,
            },
            nginx_public_key: '',
            _pending_url: req.url, // temp field, removed before saving
        };
        if (existing >= 0) session.pages[existing] = page; else session.pages.push(page);
        hostLog(`saw a signed response: ${req.method} ${urlObj.pathname} (tab ${tabId})`);
        // Timer trigger: fires even when no navigation event arrives. It waits
        // longer than a normal page load so the event triggers run first.
        setTimeout(() => drainPendingBodies(tabId, 'timer'), 2500);

    },
    { urls: ['https://*/*'] },
    ['responseHeaders']
);

// -- Fetch the bodies of every page captured for a tab, then save -------------
//
// Three triggers call this: tabs.onUpdated, webNavigation.onCompleted, and the
// timer set when a signed response arrives. tabs.onUpdated alone does not fire
// for every navigation in Firefox. `_draining` stops overlapping runs.
async function drainPendingBodies(tabId, why) {
    if (!inMemorySessions.has(tabId)) return;
    const session = inMemorySessions.get(tabId);
    if (session._draining) return;
    const pendingPages = session.pages.filter(p => p._pending_url);
    if (!pendingPages.length) return;
    session._draining = true;
    hostLog(`draining ${pendingPages.length} body/bodies for tab ${tabId} (trigger: ${why})`);

    // Fetch each pending page's body directly, byte-identical to what NGINX signed.
    //
    // webRequest exposes headers but not bodies, so the body is fetched again. The
    // fetch sends the page's credentials: without them a page behind a login
    // returns a sign-in page and the digest check fails. An origin that answers
    // with `Access-Control-Allow-Origin: *` rejects credentialed fetches, so on
    // failure it retries without credentials. The mode used is stored on the page,
    // because with 'omit' on a gated page a digest mismatch means this fallback,
    // not tampering.
    const fetchBody = async (url) => {
        for (const credentials of ['include', 'omit']) {
            try {
                const resp = await fetch(url, { method: 'GET', cache: 'no-store', credentials });
                if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                return { resp, credentials };
            } catch (e) {
                if (credentials === 'omit') throw e;
                console.warn(`GPS: credentialed fetch of ${url} failed (${e.message}); `
                           + `retrying without credentials. A page behind a login will not `
                           + `capture this way.`);
            }
        }
    };

    await Promise.all(pendingPages.map(async (page) => {
        const url = page._pending_url;
        try {
            const { resp, credentials } = await fetchBody(url);
            const contentType = page.response.headers['content-type'] || '';
            const isPdf = contentType.includes('pdf') || url.endsWith('.pdf');
            let body;
            if (isPdf) {
                const buf = await resp.arrayBuffer();
                const bytes = new Uint8Array(buf);
                const chunks = [];
                for (let i = 0; i < bytes.length; i += 8192) {
                    chunks.push(String.fromCharCode(...bytes.subarray(i, i + 8192)));
                }
                body = '__PDF_BASE64__' + btoa(chunks.join(''));
            } else {
                body = await resp.text();
            }
            hostLog(`fetched ${url} with credentials='${credentials}', ${body.length} bytes`);
            page.response.body = body;
            page._fetch_credentials = credentials;
            delete page._pending_url;
        } catch (e) {
            // Report the failure; otherwise the page is silently dropped at save.
            hostLog(`FETCH FAILED for ${url}: ${e.message}. This page is not captured.`);
            console.error(`GPS: could not fetch the body of ${url}: ${e.message}. `
                        + `This page will NOT be captured.`);
            page._fetch_error = e.message;
            delete page._pending_url;
        }
    }));
    session._draining = false;
    saveSessionToHost(session, tabId);
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'complete') drainPendingBodies(tabId, 'tabs.onUpdated');
});

// Second trigger: the navigation API reporting the same completion.
if (chrome.webNavigation && chrome.webNavigation.onCompleted) {
    chrome.webNavigation.onCompleted.addListener((d) => {
        if (d.frameId === 0) drainPendingBodies(d.tabId, 'webNavigation.onCompleted');
    });
}

function saveSessionToHost(session, tabId) {
    const completedPages = session.pages.filter(
        p => p.response.body && p.response.headers['signature']
    );
    if (!completedPages.length) {
        // Nothing to save: report why each page was dropped.
        const why = session.pages.map(p =>
            `${p.request.path}: ${p._fetch_error ? 'fetch failed, ' + p._fetch_error
              : !p.response.body ? 'no body' : 'no signature header'}`).join('; ');
        hostLog(`NOTHING CAPTURED for ${session.domain}: ${why}`);
        console.error(`GPS: nothing captured for ${session.domain} `
                    + `(${session.pages.length} signed response(s) seen). ${why}`);
        return;
    }

    const sessionToSave = {
        ...session,
        ended_at: Math.floor(Date.now() / 1000).toString(),
        pages: completedPages,
    };

    nativeCall({
        action:   'save_session',
        session:  sessionToSave,
        // Pass stable ID so host overwrites same file on each nav
        filename: `session_direct_${session.domain.replace(/[:.]/g,'_')}_${session.session_id.slice(0,8)}.json`,
    }).then(res => {
        if (res?.ok) {
            const s = inMemorySessions.get(tabId);
            if (s) s._saved_path = res.path;
            hostLog(`SAVED ${completedPages.length} page(s) to ${res.path}`);
        } else {
            hostLog(`SAVE REFUSED by the host: ${res?.error || 'no reply'}`);
        }
    });
}

// -- Native messaging ----------------------------------------------------------
let nativePort = null;
let pendingCallbacks = new Map();
let msgId = 0;

// The native port can drop for reasons unrelated to the request in flight
// (Firefox unloading the background page, the host being rebuilt, a transient
// spawn failure). A fresh host answers immediately, so a drop is recoverable:
// each pending call keeps its message and is re-sent once before failing.
const pendingMessages = new Map();   // id -> the original message
const retriedOnce     = new Set();   // ids already replayed, so a flapping port
                                     // cannot loop a 2-minute proof forever

// The ping sent on every connect is unsolicited, so it carries a fixed id and
// its reply is dropped. A reply that matches no pending id is never handed to
// another caller.
const PING_ID = 0;

function connectNative() {
    try {
        nativePort = chrome.runtime.connectNative(NATIVE_HOST);
        nativePort.onMessage.addListener((msg) => {
            // Route strictly by _id; drop the connect ping and any reply whose
            // id is not pending.
            if (msg._id === undefined || msg._id === PING_ID) return;
            const cb = pendingCallbacks.get(msg._id);
            if (!cb) return;
            pendingCallbacks.delete(msg._id);
            pendingMessages.delete(msg._id);
            retriedOnce.delete(msg._id);
            cb(msg);
        });
        nativePort.onDisconnect.addListener(() => {
            nativePort = null;
            // Snapshot what was in flight, then reconnect and replay it once.
            const inFlight = [...pendingCallbacks.keys()];
            setTimeout(() => {
                connectNative();
                for (const id of inFlight) {
                    const cb  = pendingCallbacks.get(id);
                    const msg = pendingMessages.get(id);
                    if (!cb) continue;
                    if (retriedOnce.has(id) || !msg || !nativePort) {
                        // Second failure, or nothing to replay: report it.
                        pendingCallbacks.delete(id);
                        pendingMessages.delete(id);
                        retriedOnce.delete(id);
                        cb({ ok: false, error: 'Lost the connection to the GPS host and '
                            + 'could not re-establish it. Check that gps-host is installed '
                            + '(see /tmp/gps-host.log), then try again.' });
                        continue;
                    }
                    retriedOnce.add(id);
                    try { nativePort.postMessage(msg); }
                    catch (e) {
                        pendingCallbacks.delete(id);
                        pendingMessages.delete(id);
                        retriedOnce.delete(id);
                        cb({ ok: false, error: 'Could not reach the GPS host: ' + e.message });
                    }
                }
            }, 250);
        });
        nativePort.postMessage({ ping: true, _id: PING_ID });
    } catch (e) { setTimeout(connectNative, 2000); }
}
connectNative();

// Send capture-path messages to the host log (/tmp/gps-host.log).
function hostLog(msg) { try { nativeCall({ action: 'log', msg }); } catch (e) {} }

function nativeCall(msg) {
    return new Promise((resolve) => {
        const id = ++msgId;
        msg._id = id;
        pendingCallbacks.set(id, resolve);
        pendingMessages.set(id, msg);   // kept so a dropped port can replay it
        if (!nativePort) {
            connectNative();
            setTimeout(() => {
                if (pendingCallbacks.has(id)) {
                    pendingCallbacks.delete(id);
                    pendingMessages.delete(id);
                    resolve({ ok: false, error: 'The GPS host is not reachable. Run '
                        + 'launch.sh, or check /tmp/gps-host.log.' });
                }
            }, 5000);
            return;
        }
        try { nativePort.postMessage(msg); }
        catch (e) {
            pendingCallbacks.delete(id);
            pendingMessages.delete(id);
            resolve({ ok: false, error: e.message });
        }
    });
}

// The guest matches a field's target against `Transcript.request.path`, so it
// must receive a path, not the full URL the capture side uses. Normalised here
// because changing the guest would change its image_id.
function toPath(u) {
    if (!u) return '/';
    try { return new URL(u).pathname || '/'; }
    catch (e) { return u.startsWith('/') ? u : '/' + u; }
}

// -- Message handler -----------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {

        case 'start_field_selection':
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (!tabs[0]) { sendResponse({ ok: false }); return; }
                const tabId = tabs[0].id;
                chrome.scripting.executeScript(
                    { target: { tabId }, files: ['content/content.js'] },
                    () => setTimeout(() => {
                        chrome.tabs.sendMessage(tabId, { action: 'start_selection' });
                    }, 100)
                );
                sendResponse({ ok: true });
            });
            return true;

        case 'field_selected':
            chrome.storage.local.set({
                selectedText:    message.text,
                selectedField:   message.field,
                selectedSession: message.session,
                selectedUrl:     message.url,
                rawText:         message.rawText,
            });
            chrome.runtime.sendMessage({
                action:  'field_ready',
                text:    message.text,
                field:   message.field,
                session: message.session,
                url:     message.url,
                rawText: message.rawText,
            }).catch(() => {});
            sendResponse({ ok: true });
            break;

        case 'list_sessions':
            // Include in-memory sessions that have been saved
            nativeCall({ action: 'list_sessions' }).then(sendResponse);
            return true;

        case 'read_body':
            nativeCall({ action: 'read_body', path: message.path, url: message.url })
                .then(sendResponse);
            return true;

        case 'generate_proof':
            nativeCall({
                session:  message.session,
                url:      toPath(message.url),
                dev_mode: message.dev_mode || false,
                // single-field (1 entry or legacy): use field/predicate keys
                // multi-field (2+ entries): use fields array
                ...(message.fields && message.fields.length > 1
                    ? { fields: message.fields.map(f => ({ ...f, url: toPath(f.url) })) }
                    : {
                        field:     (message.fields ? message.fields[0].field     : message.field),
                        predicate: (message.fields ? message.fields[0].predicate : message.predicate),
                      }),
            }).then(sendResponse);
            return true;

        case 'get_in_memory_session':
            // Content script asks for the current tab's in-memory session path
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (!tabs[0]) { sendResponse({ path: null }); return; }
                const session = inMemorySessions.get(tabs[0].id);
                sendResponse({ path: session?._saved_path || null });
            });
            return true;

        case 'analyze_field':
      nativeCall({
        action:       'analyze_field',
        html_context: message.html_context || '',
        label_text:   message.label_text   || '',
        value_text:   message.value_text   || '',
        body:         message.body         || '',
      }).then(sendResponse);
      return true;

    case 'ping_host':
            nativeCall({ ping: true }).then(sendResponse);
            return true;
    }
});


