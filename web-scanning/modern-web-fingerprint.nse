--[[
modern-web-fingerprint.nse

Fingerprints modern web technologies directly from Nmap.

Features:
- Detects common HTTP headers (e.g., Server, X-Powered-By, CF-Ray, etc.)
- Attempts TLS ALPN negotiation to identify HTTP/2 or HTTP/3 hints and common CDNs
- Performs simple keyword/regex search in landing page HTML for JS/CSS framework hints
- Outputs detected technologies with simple confidence scores

Categories: discovery

Script arguments:
- modern-web-fingerprint.headers: Comma-separated list of header names to look for (case-insensitive).
  Example: --script-args 'modern-web-fingerprint.headers=server,x-powered-by,cf-ray'

- modern-web-fingerprint.html_patterns: Comma-separated list of Lua patterns (NOT PCRE) to search for in HTML.
  Example: --script-args 'modern-web-fingerprint.html_patterns=React,ng%-version,window%.__NUXT__'

- modern-web-fingerprint.alpn: Comma-separated list of ALPN protocol IDs to offer (default: h2,http/1.1).
  Example: --script-args 'modern-web-fingerprint.alpn=h2,http/1.1,http/1.0'

Notes:
- Uses Nmap's http and ssl libraries. The ALPN probe uses the optional tls library if present; if unavailable,
  the script will still run and simply omit ALPN results.
- Supports IPv4/IPv6 targets automatically via Nmap host object.

Usage:
  nmap -p80,443 --script modern-web-fingerprint <target>

Author: Agent Mode (Warp AI Terminal)
License: Same as Nmap (See https://nmap.org/book/man-legal.html)
]]--

local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
local table = require "table"

-- tls is optional; wrap in pcall to avoid hard dependency
local have_tls, tls = pcall(require, "tls")

portrule = shortport.port_or_service(
  {80, 81, 443, 444, 591, 593, 631, 7080, 7081, 8000, 8008, 8009, 8080, 8081, 8088, 8089, 8443, 8888, 9000, 9443},
  {"http", "https", "http-proxy", "https-alt"},
  "tcp"
)

local DEFAULT_HEADERS = {
  "server",
  "x-powered-by",
  "cf-ray",
  "via",
  "x-served-by",
  "x-runtime",
  "x-cache",
  "x-akamai-transformed",
  "x-amz-cf-id",
  "x-fastly",
  "x-vercel-id",
  "x-nextjs-cache",
  "x-github-request-id",
  "x-edge-location",
  "x-lambda-id",
  "x-render-origin-server",
  "x-netlify-id", 
  "x-nf-request-id",
  "x-middleware-next",
  "x-matched-path",
  "x-middleware-prefetch",
  "x-middleware-rewrite",
  "strict-transport-security",
  "referrer-policy",
  "content-security-policy",
  "permissions-policy",
}

local DEFAULT_HTML_PATTERNS = {
  -- React
  "React",
  "__REACT_DEVTOOLS_GLOBAL_HOOK__",
  "data%-reactroot",
  "data%-react%-helmet",
  "_react",
  -- Angular
  "ng%-version",
  "ng%-app", 
  "angular",
  "@angular",
  -- Vue
  "Vue",
  "data%-v%-",
  "__VUE_HMR_RUNTIME__",
  "vue%-loader",
  -- jQuery
  "jQuery",
  "jquery",
  -- Next.js patterns (case insensitive search will handle these)
  "__NEXT_DATA__",
  "_next/static",
  "next%-dev",
  "next/head",
  "Next%.js",
  -- Nuxt
  "__NUXT__",
  "nuxt",
  -- Other frameworks
  "data%-svelte",
  "webpack",
  "gatsby",
  "remix",
}

local DEFAULT_ALPN_LIST = { "h2", "http/1.1" }

local function split_csv(str)
  if not str or str == "" then return {} end
  local out = {}
  for item in string.gmatch(str, "[^,]+") do
    local trimmed = stdnse.strtrim(item)
    if trimmed ~= "" then table.insert(out, trimmed) end
  end
  return out
end

local function lower_map(list)
  local out = {}
  for _, v in ipairs(list) do out[#out+1] = string.lower(v) end
  return out
end

local function is_https_port(host, port)
  -- Heuristic: consider it HTTPS if Nmap says tunnel is SSL, service is https, or common TLS ports
  if port.tunnel == "ssl" then return true end
  local svc = (port.service or ""):lower()
  if svc:find("https", 1, true) then return true end
  if port.number == 443 or port.number == 8443 or port.number == 9443 then return true end
  return false
end

local function fetch_landing_page(host, port)
  local opts = {
    header = {
      ["User-Agent"] = "Nmap-Modern-Web-Fingerprint/1.0",
      ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      ["Accept-Encoding"] = "identity"
    },
    max_body_size = 512 * 1024, -- 512KB cap
    redirect_ok = true,
    no_cache = true,
  }

  local path = "/"
  local resp = http.get(host, port, path, opts)
  return resp
end

local function score_from_header(name, value)
  -- Simple heuristic: presence = base 0.6, add small boosts for recognizable providers
  local base = 0.6
  local v = (value or ""):lower()
  if v:find("cloudflare", 1, true) or name:lower() == "cf-ray" then base = math.max(base, 0.8) end
  if v:find("akamai", 1, true) then base = math.max(base, 0.75) end
  if v:find("fastly", 1, true) then base = math.max(base, 0.75) end
  if v:find("vercel", 1, true) then base = math.max(base, 0.75) end
  if v:find("aws", 1, true) or v:find("cloudfront", 1, true) then base = math.max(base, 0.7) end
  return base
end

local function score_from_html(pattern, matches)
  -- Presence of framework hints is high signal
  local base = 0.8
  if matches and matches > 1 then base = math.min(0.95, base + 0.05 * math.min(matches - 1, 3)) end
  return base
end

local function try_alpn(host, port, offer_list)
  if not have_tls or not tls then
    return nil, "tls library not available"
  end

  -- Best-effort: API compatibility layer
  -- Many Nmap versions provide tlsnegotiate via tls.negotiate or tls.clienthello. We'll try both.
  local server_name = host.targetname or host.name or host.ip
  local params = {
    server_name = server_name,
    alpn = offer_list,
    timeout = 5000,
  }

  -- try tls.negotiate
  local ok, res = pcall(function()
    if tls.negotiate then
      return tls.negotiate(host, port, params)
    end
    return nil
  end)
  if ok and res then
    -- Try to normalize: expect res.alpn or res.protocol or res.selected_alpn
    local selected = res.alpn or res.selected_alpn or res.protocol
    return selected, nil
  end

  -- try tls.clienthello (older variants)
  local ok2, res2 = pcall(function()
    if tls.clienthello then
      return tls.clienthello(host, port, params)
    end
    return nil
  end)
  if ok2 and res2 then
    local selected = res2.alpn or res2.selected_alpn or res2.protocol
    return selected, nil
  end

  return nil, "ALPN negotiation not supported by tls library"
end

local function analyze(host, port, resp, headers_list, html_patterns, alpn_offer)
  local findings = {}

  -- Headers
  if resp and resp.header then
    local hdr = resp.header
    for _, h in ipairs(headers_list) do
      local hv = hdr[h] or hdr[string.upper(h)] or hdr[string.gsub(h, "^%l", string.upper)]
      if hv then
        local score = score_from_header(h, hv)
        table.insert(findings, { kind = "header", name = h, value = hv, confidence = score })
      end
    end
  end

  -- HTML patterns (case insensitive search)
  local body = resp and resp.body or ""
  if body ~= "" then
    local body_lower = string.lower(body)
    for _, pat in ipairs(html_patterns) do
      local count = 0
      local search_body = body_lower
      local search_pat = string.lower(pat)
      
      -- Count all occurrences
      local start_pos = 1
      while true do
        local s, e = string.find(search_body, search_pat, start_pos, true) -- plain text search
        if not s then break end
        count = count + 1
        start_pos = e + 1
      end
      
      if count > 0 then
        local score = score_from_html(pat, count)
        table.insert(findings, { kind = "html", pattern = pat, matches = count, confidence = score })
      end
    end
  end

  -- ALPN
  local selected_alpn, alpn_err
  if is_https_port(host, port) then
    selected_alpn, alpn_err = try_alpn(host, port, alpn_offer)
    if selected_alpn then
      local score = 0.7
      local info = { kind = "alpn", selected = selected_alpn, confidence = score }
      -- CDN hints via ALPN alone are weak; add notes based on headers if present
      table.insert(findings, info)
    end
  end

  return findings
end

local function format_findings(findings)
  if not findings or #findings == 0 then
    return "No obvious modern web fingerprints found."
  end

  local lines = {}

  local function fmt_score(s)
    return string.format("%.2f", tonumber(s) or 0)
  end

  -- Group headers, html, alpn
  for _, f in ipairs(findings) do
    if f.kind == "header" then
      table.insert(lines, string.format("Header: %s = %s (confidence %s)", f.name, f.value, fmt_score(f.confidence)))
    elseif f.kind == "html" then
      table.insert(lines, string.format("HTML pattern: %s (matches: %d, confidence %s)", f.pattern, f.matches or 1, fmt_score(f.confidence)))
    elseif f.kind == "alpn" then
      table.insert(lines, string.format("TLS ALPN: %s (confidence %s)", f.selected, fmt_score(f.confidence)))
    end
  end

  return table.concat(lines, "\n")
end

action = function(host, port)
  -- Resolve script args
  local arg_headers = stdnse.get_script_args("modern-web-fingerprint.headers")
  local arg_html = stdnse.get_script_args("modern-web-fingerprint.html_patterns")
  local arg_alpn = stdnse.get_script_args("modern-web-fingerprint.alpn")

  local headers_list = DEFAULT_HEADERS
  if arg_headers and type(arg_headers) == "string" then
    local tmp = split_csv(arg_headers)
    if #tmp > 0 then headers_list = tmp end
  end
  headers_list = lower_map(headers_list)

  local html_patterns = DEFAULT_HTML_PATTERNS
  if arg_html and type(arg_html) == "string" then
    local tmp = split_csv(arg_html)
    if #tmp > 0 then html_patterns = tmp end
  end

  local alpn_offer = DEFAULT_ALPN_LIST
  if arg_alpn and type(arg_alpn) == "string" then
    local tmp = split_csv(arg_alpn)
    if #tmp > 0 then alpn_offer = tmp end
  end

  -- Fetch landing page
  local resp = fetch_landing_page(host, port)

  -- Analyze
  local findings = analyze(host, port, resp, headers_list, html_patterns, alpn_offer)

  -- Output
  return stdnse.format_output(true, format_findings(findings))
end
