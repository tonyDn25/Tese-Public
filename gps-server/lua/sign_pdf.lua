-- GPS sign_pdf.lua — RFC 9421 signing for binary/PDF responses

local resty_openssl_digest = require "resty.openssl.digest"
local resty_openssl_pkey   = require "resty.openssl.pkey"
local resty_openssl_bn     = require "resty.openssl.bn"

-- Load private key from the volume-mounted key directory (same path as sign_page.lua)
local key_path = "/etc/nginx/keys/nginx_private.pem"
local f = io.open(key_path, "rb")
if not f then ngx.status = 500; ngx.say("key not found"); return end
local key_pem = f:read("*a"); f:close()
local pkey = resty_openssl_pkey.new(key_pem)

-- Load PDF file
local page = ngx.var.gps_page
local pdf_path = "/etc/nginx/html/" .. page
local pf = io.open(pdf_path, "rb")
if not pf then
    ngx.status = 404
    ngx.say("PDF not found: " .. pdf_path)
    return
end
local body = pf:read("*a"); pf:close()

-- Compute SHA-256 of body
local digest = resty_openssl_digest.new("sha256")
digest:update(body)
local hash_raw = digest:final()
local b64_hash = ngx.encode_base64(hash_raw)
local content_digest = "sha-256=:" .. b64_hash .. ":"

-- Build RFC 9421 signature base
local date_str = ngx.http_time(ngx.time())
local method   = ngx.req.get_method()
local authority = ngx.var.host or "172.18.0.50"
local scheme   = "https"
local target_uri = scheme .. "://" .. authority .. ngx.var.request_uri
local status   = "200"
local created  = tostring(ngx.time())
local keyid    = "gps-nginx"
local alg      = "ecdsa-p256-sha256"

local sig_input_params = 'created=' .. created ..
    ';keyid="' .. keyid .. '";alg="' .. alg .. '"'

local covered = '("@method" "@authority" "@target-uri" "@status" "content-digest" "date")'
-- The @signature-params LINE in the signature base carries the bare params
-- (no "sig1=" label); the label appears only in the Signature-Input header.
-- This makes the PDF base identical to sign_page.lua so the guest accepts
-- exactly one base format (MF2). Previously this script signed the labelled
-- form, an old non-standard variant the guest had to special-case.
local sig_params_inner = covered .. ';' .. sig_input_params
local sig_input_value  = 'sig1=' .. sig_params_inner

local sig_base = '"@method": ' .. method .. '\n'
sig_base = sig_base .. '"@authority": ' .. authority .. '\n'
sig_base = sig_base .. '"@target-uri": ' .. target_uri .. '\n'
sig_base = sig_base .. '"@status": ' .. status .. '\n'
sig_base = sig_base .. '"content-digest": ' .. content_digest .. '\n'
sig_base = sig_base .. '"date": ' .. date_str .. '\n'
sig_base = sig_base .. '"@signature-params": ' .. sig_params_inner

-- Sign (pass sig_base directly — pkey:sign handles SHA-256 internally)
local sig_raw, sign_err = pkey:sign(sig_base, "sha256")
if not sig_raw then
    ngx.status = 500
    ngx.say("Sign error: " .. (sign_err or "unknown"))
    return
end
local sig_b64 = ngx.encode_base64(sig_raw)

-- Send response
ngx.header["Content-Type"]        = "application/pdf"
ngx.header["Content-Digest"]      = content_digest
ngx.header["Date"]                 = date_str
ngx.header["Signature-Input"]     = sig_input_value
ngx.header["Signature"]           = "sig1=:" .. sig_b64 .. ":"
ngx.header["X-GPS-Signed"]        = "true"
ngx.header["X-GPS-Authority"]     = authority
ngx.header["X-GPS-Target-Uri"]    = target_uri
ngx.header["X-GPS-Method"]        = method
ngx.header["X-GPS-Content-Type"]  = "application/pdf"
ngx.header["Access-Control-Allow-Origin"] = "*"
ngx.header["Access-Control-Expose-Headers"] =
    "Signature,Signature-Input,Content-Digest,Date," ..
    "X-GPS-Timestamp,X-GPS-Signed,X-GPS-Method,X-GPS-Authority," ..
    "X-GPS-Target-Uri,X-GPS-Content-Type"

ngx.status = 200
ngx.print(body)
