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

        // Store pending page, body will be filled by content script
        session.pages.push({
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
        });

    },
    { urls: ['https://*/*'] },
    ['responseHeaders']
);

// -- Tab navigation complete: fetch body directly from server -----------------
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete') return;
    if (!inMemorySessions.has(tabId)) return;

    const session = inMemorySessions.get(tabId);
    const pendingPages = session.pages.filter(p => p._pending_url);
    if (!pendingPages.length) return;

    // Fetch each pending page's body directly, byte-identical to what NGINX signed
    Promise.all(pendingPages.map(async (page) => {
        const url = page._pending_url;
        try {
            const resp = await fetch(url, {
                method: 'GET',
                cache: 'no-store',
                credentials: 'omit',
            });
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
            page.response.body = body;
            delete page._pending_url;
        } catch (e) {
            console.error(`GPS: fetch failed for ${url}:`, e);
            delete page._pending_url;
        }
    })).then(() => {
        saveSessionToHost(session, tabId);
    });
});

function saveSessionToHost(session, tabId) {
    const completedPages = session.pages.filter(
        p => p.response.body && p.response.headers['signature']
    );
    if (!completedPages.length) return;

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
        }
    });
}

// -- Native messaging ----------------------------------------------------------
let nativePort = null;
let pendingCallbacks = new Map();
let msgId = 0;

// The native port can drop for reasons that have nothing to do with the request
// in flight: Firefox tearing the background page down, the host being replaced by
// a rebuild, a transient spawn failure. The host itself is a persistent read/reply
// loop and a fresh one answers immediately, so a drop is a RECOVERABLE event and
// not a result. Failing the caller with the raw internal string 'disconnected' was
// wrong twice over: it surfaced an internal state name in the UI, and it threw away
// a request that would have succeeded on the very next port.
//
// Each pending call therefore keeps enough context to be re-sent exactly once.
const pendingMessages = new Map();   // id -> the original message
const retriedOnce     = new Set();   // ids already replayed, so a flapping port
                                     // cannot loop a 2-minute proof forever

// The liveness ping sent on every connect is UNSOLICITED: no caller is waiting for
// its reply. It must therefore be identifiable, because a reply that cannot be routed
// to the caller that asked for it must be DROPPED, never handed to whoever happens to
// be first in the queue. Routing by "first pending callback" is what made a reconnect
// resolve an in-flight proof with {pong:true,version}, which has neither `ok` nor
// `error`, so the popup fell back to its generic "Proof generation failed." while the
// host had done nothing wrong at all.
const PING_ID = 0;

function connectNative() {
    try {
        nativePort = chrome.runtime.connectNative(NATIVE_HOST);
        nativePort.onMessage.addListener((msg) => {
            // Strict routing by _id only. The host echoes the _id of every request
            // that carried one, so a reply without a matching pending id belongs to
            // nobody: the connect ping, or a duplicate from a host replaced mid-flight.
            // Both must be dropped. The old first-in-the-queue fallback silently
            // mis-delivered those to an unrelated caller.
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
                        // Second failure, or nothing to replay: now it is a real
                        // error, and it says what the user can do about it.
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

// The guest matches a field's target against `Transcript.request.path`, so the
// value it is given must be a PATH. The capture side knows pages by their full
// URL, and sending that through meant find_target_page() could never match: the
// guest then aborted, correctly, with "URL not found in session", and every proof
// started from the browser failed while the identical proof from the CLI worked.
// Normalise here, at the boundary, because the guest cannot be changed to be more
// forgiving without altering its ELF and therefore the image_id.
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


