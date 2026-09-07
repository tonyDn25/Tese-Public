-- GPS Server — RFC 9421 HTTP Message Signatures (full implementation)
--
-- Signed components (Section 2.2 of RFC 9421):
--   "@method"        — HTTP method (GET, POST, ...)
--   "@authority"     — Host header (e.g. 172.18.0.50)
--   "@target-uri"    — Full request URI
--   "@status"        — HTTP response status code
--   "content-digest" — SHA-256 of response body (RFC 9530)
--   "date"           — HTTP Date header
--
-- The signature base is a canonicalized string of the above,
-- terminated by the @signature-params line (Section 2.3).
--
-- Trust anchor: ECDSA P-256 private key at /etc/nginx/keys/nginx_private.pem
-- The corresponding public key is hardcoded in the zkVM guest binary.
-- The zkVM Image ID cryptographically binds the guest program to that key.

local pkey   = require "resty.openssl.pkey"
local digest = require "resty.openssl.digest"

-- -- 1. Load and serve the page ------------------------------------------------

local page     = ngx.var.gps_page or "index"
local filepath = "/etc/nginx/html/" .. page .. ".html"

local f = io.open(filepath, "r")
if not f then
    ngx.status = 404
    ngx.header["Content-Type"] = "text/plain"
    ngx.print("GPS Server: page not found: " .. filepath)
    return
end
local body = f:read("*a")
f:close()

-- -- 2. Load signing key (cached after first load via module-level upvalue) ----

local pkey_pem
do
    local kf = io.open("/etc/nginx/keys/nginx_private.pem", "r")
    if not kf then
        ngx.log(ngx.ERR, "GPS: cannot open private key")
        ngx.exit(500)
    end
    pkey_pem = kf:read("*a")
    kf:close()
end

local pk, pk_err = pkey.new(pkey_pem)
if not pk then
    ngx.log(ngx.ERR, "GPS: key load failed: ", pk_err)
    ngx.exit(500)
end

-- -- 3. Compute Content-Digest (RFC 9530) --------------------------------------
-- sha-256=:<base64(sha256(body))>:

local d = digest.new("sha256")
d:update(body)
local body_hash    = d:final()
local content_digest = "sha-256=:" .. ngx.encode_base64(body_hash) .. ":"

-- -- 4. Collect RFC 9421 component values -------------------------------------

local method     = ngx.req.get_method()                          -- "GET"
local authority  = ngx.var.host or ngx.var.server_name          -- "172.18.0.50"
local target_uri = ngx.var.scheme .. "://" ..
                   (ngx.var.host or ngx.var.server_name) ..
                   ngx.var.request_uri                           -- "https://172.18.0.50/"
local status     = "200"
local timestamp  = tostring(ngx.time())

-- RFC 7231 date format for the Date header
local date_str   = ngx.http_time(ngx.time())                     -- "Wed, 19 Mar 2026 13:00:00 GMT"

-- -- 5. Build RFC 9421 Signature Base (Section 2.3) ---------------------------
--
-- Each component is on its own line:
--   "<component-id>": <value>
-- The final line is always @signature-params.
--
-- Component order MUST match the order listed in the sig-params.

local sig_params = '("@method" "@authority" "@target-uri" "@status" "content-digest" "date")'
                .. ';created=' .. timestamp
                .. ';keyid="gps-nginx"'
                .. ';alg="ecdsa-p256-sha256"'

local sig_base =
    '"@method": '        .. method        .. '\n' ..
    '"@authority": '     .. authority     .. '\n' ..
    '"@target-uri": '    .. target_uri    .. '\n' ..
    '"@status": '        .. status        .. '\n' ..
    '"content-digest": ' .. content_digest .. '\n' ..
    '"date": '           .. date_str      .. '\n' ..
    '"@signature-params": ' .. sig_params

-- -- 6. Sign with ECDSA P-256 + SHA-256 ---------------------------------------

local signature, sign_err = pk:sign(sig_base, "sha256")
if not signature then
    ngx.log(ngx.ERR, "GPS: signing failed: ", sign_err)
    ngx.exit(500)
end

local sig_b64 = ngx.encode_base64(signature)

-- -- 7. Build Signature-Input header (RFC 9421 Section 4.1) -------------------

local sig_input = 'sig1=' .. sig_params

-- -- 8. Set response headers ---------------------------------------------------

ngx.status = 200
ngx.header["Content-Type"]      = "text/html; charset=utf-8"
ngx.header["Date"]              = date_str
ngx.header["Content-Digest"]    = content_digest
ngx.header["Signature-Input"]   = sig_input
ngx.header["Signature"]         = 'sig1=:' .. sig_b64 .. ':'
ngx.header["X-GPS-Timestamp"]   = timestamp
ngx.header["X-GPS-Method"]      = method
ngx.header["X-GPS-Authority"]   = authority
ngx.header["X-GPS-Target-Uri"]  = target_uri
ngx.header["X-GPS-Signed"]      = "true"
ngx.header["Access-Control-Allow-Origin"]  = "*"
ngx.header["Access-Control-Expose-Headers"] =
    "Signature,Signature-Input,Content-Digest,Date," ..
    "X-GPS-Timestamp,X-GPS-Signed,X-GPS-Method,X-GPS-Authority,X-GPS-Target-Uri"

-- -- 9. Log for debugging ------------------------------------------------------

ngx.log(ngx.INFO,
    "GPS signed: method=" .. method ..
    " uri=" .. target_uri ..
    " body_bytes=" .. #body ..
    " created=" .. timestamp)

ngx.print(body)
