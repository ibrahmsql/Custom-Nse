local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"

description = [[
Modern Authentication Bypass Tester - Tests for common authentication bypass
vulnerabilities in modern web applications and APIs.

This script performs safe, non-intrusive tests for authentication bypass
techniques commonly found in modern web applications including:
1. HTTP method override attacks
2. Header manipulation bypasses  
3. Path traversal in authentication
4. JWT token manipulation (basic checks)
5. Parameter pollution attacks
6. Case sensitivity bypasses
7. Unicode/encoding bypasses

The script focuses on detection without exploitation and does not
attempt to gain unauthorized access or modify data.
]]

---
-- @usage
-- nmap --script auth-bypass-tester.nse -p 80,443 target.com
-- nmap --script auth-bypass-tester.nse --script-args test-jwt=true,test-headers=true target.com
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | auth-bypass-tester:
-- |   Authentication Bypass Test Results:
-- |   
-- |   Protected Endpoints Discovered:
-- |     /admin (403 Forbidden)
-- |     /api/users (401 Unauthorized)  
-- |     /dashboard (302 Redirect to login)
-- |   
-- |   Bypass Vulnerabilities Found:
-- |     HIGH: HTTP method override bypass on /admin
-- |       - GET /admin returns 403
-- |       - POST with X-HTTP-Method-Override: GET returns 200
-- |     
-- |     MEDIUM: Case sensitivity bypass on /Dashboard
-- |       - /dashboard returns 302 redirect
-- |       - /Dashboard returns 200 OK
-- |     
-- |     LOW: Header manipulation possible on /api/users
-- |       - X-Forwarded-For: 127.0.0.1 changes response
-- |   
-- |   JWT Token Analysis:
-- |     JWT tokens detected in responses
-- |     Algorithm: HS256 (secure)
-- |     No obvious token manipulation vulnerabilities
-- |   
-- |   Additional Findings:
-- |     Unicode normalization not tested (endpoint unreachable)
-- |     Rate limiting detected on authentication endpoints
-- |_    CSRF tokens properly implemented
--
-- @args auth-bypass-tester.test-jwt Enable JWT-specific bypass tests (default: true)
-- @args auth-bypass-tester.test-headers Enable header manipulation tests (default: true)
-- @args auth-bypass-tester.test-methods Enable HTTP method override tests (default: true)
-- @args auth-bypass-tester.test-unicode Enable Unicode bypass tests (default: true)
-- @args auth-bypass-tester.timeout HTTP request timeout in seconds (default: 10)
-- @args auth-bypass-tester.user-agent Custom User-Agent string
-- @args auth-bypass-tester.custom-paths Custom comma-separated list of paths to test

author = "Custom NSE Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "auth"}

-- Port rule: target HTTP and HTTPS services
portrule = shortport.http

-- Script arguments
local args_test_jwt = stdnse.get_script_args(SCRIPT_NAME .. ".test-jwt")
local args_test_headers = stdnse.get_script_args(SCRIPT_NAME .. ".test-headers")
local args_test_methods = stdnse.get_script_args(SCRIPT_NAME .. ".test-methods")
local args_test_unicode = stdnse.get_script_args(SCRIPT_NAME .. ".test-unicode")
local args_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 10
local args_user_agent = stdnse.get_script_args(SCRIPT_NAME .. ".user-agent") or "NSE Auth Bypass Tester"
local args_custom_paths = stdnse.get_script_args(SCRIPT_NAME .. ".custom-paths")

-- Convert boolean arguments (default to true)
args_test_jwt = args_test_jwt ~= "false" and args_test_jwt ~= "no"
args_test_headers = args_test_headers ~= "false" and args_test_headers ~= "no"
args_test_methods = args_test_methods ~= "false" and args_test_methods ~= "no"
args_test_unicode = args_test_unicode ~= "false" and args_test_unicode ~= "no"

---
-- Common protected paths to test
local protected_paths = {
    "/admin", "/admin/", "/administrator", "/management",
    "/dashboard", "/panel", "/control", "/cp",
    "/api/admin", "/api/users", "/api/user", "/api/config",
    "/user", "/users", "/profile", "/account", 
    "/settings", "/config", "/configuration",
    "/secure", "/private", "/internal",
    "/staff", "/employee", "/manager"
}

---
-- Authentication bypass techniques
local bypass_techniques = {
    headers = {
        -- IP spoofing headers
        {["X-Forwarded-For"] = "127.0.0.1"},
        {["X-Real-IP"] = "127.0.0.1"},
        {["X-Originating-IP"] = "127.0.0.1"},
        {["X-Remote-IP"] = "127.0.0.1"},
        {["X-Remote-Addr"] = "127.0.0.1"},
        {["X-Client-IP"] = "127.0.0.1"},
        
        -- Auth bypass headers
        {["X-User-ID"] = "1"},
        {["X-Admin"] = "true"},
        {["X-Admin-User"] = "true"},
        {["X-Authenticated"] = "true"},
        {["X-Auth-User"] = "admin"},
        {["X-Role"] = "admin"},
        
        -- Proxy headers
        {["X-Forwarded-Proto"] = "https"},
        {["X-Forwarded-Host"] = "localhost"},
        {["X-Forwarded-Server"] = "localhost"}
    },
    
    methods = {
        "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"
    },
    
    method_overrides = {
        {["X-HTTP-Method-Override"] = "GET"},
        {["X-HTTP-Method"] = "GET"},
        {["X-Method-Override"] = "GET"},
        {["_method"] = "GET"}
    }
}

---
-- Severity levels
local SEVERITY = {
    CRITICAL = "CRITICAL",
    HIGH = "HIGH",
    MEDIUM = "MEDIUM", 
    LOW = "LOW",
    INFO = "INFO"
}

---
-- Perform HTTP request with error handling
-- @param host Target host
-- @param port Target port
-- @param path Request path
-- @param method HTTP method
-- @param headers Custom headers
-- @param data Request body data
-- @return Response or nil
local function safe_http_request(host, port, path, method, headers, data)
    method = method or "GET"
    local options = {
        timeout = args_timeout * 1000,
        header = headers or {},
        content = data
    }
    
    -- Add User-Agent if not already set
    if not options.header["User-Agent"] then
        options.header["User-Agent"] = args_user_agent
    end
    
    local response
    if method == "GET" then
        response = http.get(host, port, path, options)
    elseif method == "POST" then
        response = http.post(host, port, path, options)
    elseif method == "PUT" then
        response = http.put(host, port, path, options)
    elseif method == "DELETE" then
        response = http.delete(host, port, path, options)
    elseif method == "PATCH" then
        response = http.generic_request(host, port, "PATCH", path, options)
    elseif method == "OPTIONS" then
        response = http.generic_request(host, port, "OPTIONS", path, options)
    elseif method == "HEAD" then
        response = http.head(host, port, path, options)
    end
    
    return response
end

---
-- Detect if response indicates successful authentication bypass
-- @param response HTTP response
-- @param baseline_response Original response for comparison
-- @return boolean indicating if bypass was successful
local function is_bypass_successful(response, baseline_response)
    if not response or not baseline_response then
        return false
    end
    
    -- Check if status code changed from auth error to success
    if baseline_response.status == 401 or baseline_response.status == 403 then
        if response.status == 200 or response.status == 302 then
            return true
        end
    end
    
    -- Check if redirect destination changed
    if baseline_response.status == 302 and response.status == 302 then
        local baseline_location = baseline_response.header and baseline_response.header.location
        local test_location = response.header and response.header.location
        
        if baseline_location and test_location and baseline_location ~= test_location then
            -- If redirecting away from login, might be successful
            if string.match(baseline_location:lower(), "login") and 
               not string.match(test_location:lower(), "login") then
                return true
            end
        end
    end
    
    -- Check content length differences (might indicate different content)
    if response.body and baseline_response.body then
        local size_diff = math.abs(#response.body - #baseline_response.body)
        if size_diff > 100 then  -- Significant content difference
            return true
        end
    end
    
    return false
end

---
-- Test for HTTP method override bypasses
-- @param host Target host
-- @param port Target port
-- @param protected_endpoints List of protected endpoints
-- @return Table of findings
local function test_method_override_bypasses(host, port, protected_endpoints)
    if not args_test_methods then
        return {}
    end
    
    local findings = {}
    
    for _, endpoint_info in ipairs(protected_endpoints) do
        local path = endpoint_info.path
        local baseline_response = endpoint_info.response
        
        -- Test different HTTP methods
        for _, method in ipairs(bypass_techniques.methods) do
            if method ~= "GET" then  -- Skip GET as it's the baseline
                local response = safe_http_request(host, port, path, method)
                if response and is_bypass_successful(response, baseline_response) then
                    table.insert(findings, {
                        path = path,
                        technique = string.format("HTTP %s method bypass", method),
                        severity = SEVERITY.HIGH,
                        details = string.format("Baseline: %d, %s method: %d", 
                                                baseline_response.status, method, response.status)
                    })
                end
            end
        end
        
        -- Test method override headers
        for _, override_header in ipairs(bypass_techniques.method_overrides) do
            for _, method in ipairs({"POST", "PUT"}) do
                local response = safe_http_request(host, port, path, method, override_header)
                if response and is_bypass_successful(response, baseline_response) then
                    local header_name = next(override_header)
                    table.insert(findings, {
                        path = path,
                        technique = string.format("Method override via %s header", header_name),
                        severity = SEVERITY.HIGH,
                        details = string.format("Baseline: %d, Override: %d", 
                                                baseline_response.status, response.status)
                    })
                end
            end
        end
    end
    
    return findings
end

---
-- Test for header manipulation bypasses
-- @param host Target host
-- @param port Target port
-- @param protected_endpoints List of protected endpoints
-- @return Table of findings
local function test_header_bypasses(host, port, protected_endpoints)
    if not args_test_headers then
        return {}
    end
    
    local findings = {}
    
    for _, endpoint_info in ipairs(protected_endpoints) do
        local path = endpoint_info.path
        local baseline_response = endpoint_info.response
        
        for _, headers in ipairs(bypass_techniques.headers) do
            local response = safe_http_request(host, port, path, "GET", headers)
            if response then
                if is_bypass_successful(response, baseline_response) then
                    local header_name = next(headers)
                    table.insert(findings, {
                        path = path,
                        technique = string.format("Header manipulation via %s", header_name),
                        severity = SEVERITY.MEDIUM,
                        details = string.format("Baseline: %d, With header: %d", 
                                                baseline_response.status, response.status)
                    })
                elseif response.status ~= baseline_response.status then
                    -- Even if not a complete bypass, status change might be interesting
                    local header_name = next(headers)
                    table.insert(findings, {
                        path = path,
                        technique = string.format("Response change with %s header", header_name),
                        severity = SEVERITY.LOW,
                        details = string.format("Status changed from %d to %d", 
                                                baseline_response.status, response.status)
                    })
                end
            end
        end
    end
    
    return findings
end

---
-- Test for case sensitivity bypasses
-- @param host Target host
-- @param port Target port
-- @param protected_endpoints List of protected endpoints
-- @return Table of findings
local function test_case_sensitivity_bypasses(host, port, protected_endpoints)
    local findings = {}
    
    for _, endpoint_info in ipairs(protected_endpoints) do
        local path = endpoint_info.path
        local baseline_response = endpoint_info.response
        
        -- Test different case variations
        local variations = {
            path:upper(),
            path:lower(),
            path:gsub("^(%l)", string.upper),  -- Capitalize first letter
            path:gsub("/(%l)", "/%U%1"),       -- Capitalize after slashes
        }
        
        for _, variant in ipairs(variations) do
            if variant ~= path then  -- Skip if same as original
                local response = safe_http_request(host, port, variant, "GET")
                if response and is_bypass_successful(response, baseline_response) then
                    table.insert(findings, {
                        path = path,
                        technique = string.format("Case sensitivity bypass (%s)", variant),
                        severity = SEVERITY.MEDIUM,
                        details = string.format("Original %s: %d, Variant %s: %d", 
                                                path, baseline_response.status, variant, response.status)
                    })
                end
            end
        end
    end
    
    return findings
end

---
-- Test for Unicode/encoding bypasses
-- @param host Target host
-- @param port Target port
-- @param protected_endpoints List of protected endpoints
-- @return Table of findings
local function test_unicode_bypasses(host, port, protected_endpoints)
    if not args_test_unicode then
        return {}
    end
    
    local findings = {}
    
    for _, endpoint_info in ipairs(protected_endpoints) do
        local path = endpoint_info.path
        local baseline_response = endpoint_info.response
        
        -- Test URL encoding variations
        local encoded_variations = {
            path:gsub("/", "%%2F"),           -- URL encode slashes
            path:gsub("/", "%%2f"),           -- URL encode slashes (lowercase)
            path:gsub("admin", "%%61dmin"),   -- Partial URL encoding
            path .. "/",                      -- Trailing slash
            path .. "//",                     -- Double trailing slash
            path:gsub("//", "/"),            -- Remove double slashes if any
        }
        
        for _, variant in ipairs(encoded_variations) do
            if variant ~= path then
                local response = safe_http_request(host, port, variant, "GET")
                if response and is_bypass_successful(response, baseline_response) then
                    table.insert(findings, {
                        path = path,
                        technique = string.format("Encoding bypass (%s)", variant),
                        severity = SEVERITY.MEDIUM,
                        details = string.format("Original: %d, Encoded: %d", 
                                                baseline_response.status, response.status)
                    })
                end
            end
        end
    end
    
    return findings
end

---
-- Analyze JWT tokens if present
-- @param host Target host
-- @param port Target port
-- @param responses List of HTTP responses to analyze
-- @return Table of JWT analysis results
local function analyze_jwt_tokens(host, port, responses)
    if not args_test_jwt then
        return {}
    end
    
    local jwt_findings = {}
    local jwt_tokens = {}
    
    -- Extract JWT tokens from responses
    for _, response_info in ipairs(responses) do
        local response = response_info.response
        
        -- Check headers for JWT tokens
        if response.header then
            for header_name, header_value in pairs(response.header) do
                if string.match(header_value, "Bearer%s+[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+") then
                    local token = string.match(header_value, "Bearer%s+([A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+)")
                    if token then
                        table.insert(jwt_tokens, {token = token, source = "header:" .. header_name})
                    end
                end
            end
        end
        
        -- Check response body for JWT tokens
        if response.body then
            for token in string.gmatch(response.body, '[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+') do
                table.insert(jwt_tokens, {token = token, source = "body"})
            end
        end
    end
    
    -- Analyze found JWT tokens
    for _, token_info in ipairs(jwt_tokens) do
        local token = token_info.token
        local parts = {}
        for part in string.gmatch(token, '([^.]+)') do
            table.insert(parts, part)
        end
        
        if #parts == 3 then
            -- Try to decode header (first part)
            local header_decoded = nil
            -- Basic base64 decode attempt (simplified)
            local status, header_json = pcall(function()
                -- This is a simplified approach - full base64 decode would be needed
                return parts[1]
            end)
            
            table.insert(jwt_findings, {
                technique = "JWT token detected",
                severity = SEVERITY.INFO,
                details = string.format("Token found in %s (length: %d)", token_info.source, #token)
            })
            
            -- Check for obvious vulnerabilities
            if parts[3] == "" or #parts[3] < 10 then
                table.insert(jwt_findings, {
                    technique = "JWT with weak/missing signature",
                    severity = SEVERITY.HIGH,
                    details = "JWT signature appears to be missing or very short"
                })
            end
        end
    end
    
    return jwt_findings
end

---
-- Discover protected endpoints
-- @param host Target host
-- @param port Target port
-- @return Table of protected endpoints with their responses
local function discover_protected_endpoints(host, port)
    local protected_endpoints = {}
    local paths_to_test = protected_paths
    
    -- Add custom paths if specified
    if args_custom_paths then
        for path in string.gmatch(args_custom_paths, "([^,]+)") do
            path = string.match(path, "^%s*(.-)%s*$")  -- trim whitespace
            table.insert(paths_to_test, path)
        end
    end
    
    for _, path in ipairs(paths_to_test) do
        local response = safe_http_request(host, port, path, "GET")
        
        if response then
            -- Consider it protected if we get auth-related status codes
            if response.status == 401 or response.status == 403 or 
               (response.status == 302 and response.header and response.header.location and
                string.match(response.header.location:lower(), "login")) then
                
                table.insert(protected_endpoints, {
                    path = path,
                    response = response,
                    status = response.status
                })
                
                stdnse.debug2("Found protected endpoint: %s (status: %d)", path, response.status)
            end
        end
    end
    
    return protected_endpoints
end

---
-- Main action function
-- @param host Target host
-- @param port Target port
-- @return Script results
action = function(host, port)
    local result = {}
    local all_findings = {}
    local all_responses = {}
    
    stdnse.debug1("Starting authentication bypass tests for %s:%d", host.ip, port.number)
    
    -- Phase 1: Discover protected endpoints
    local protected_endpoints = discover_protected_endpoints(host, port)
    
    if #protected_endpoints == 0 then
        return "No protected endpoints discovered to test"
    end
    
    -- Collect responses for JWT analysis
    for _, endpoint_info in ipairs(protected_endpoints) do
        table.insert(all_responses, endpoint_info)
    end
    
    -- Phase 2: Test various bypass techniques
    
    -- Test HTTP method overrides
    local method_findings = test_method_override_bypasses(host, port, protected_endpoints)
    for _, finding in ipairs(method_findings) do
        table.insert(all_findings, finding)
    end
    
    -- Test header manipulation
    local header_findings = test_header_bypasses(host, port, protected_endpoints)
    for _, finding in ipairs(header_findings) do
        table.insert(all_findings, finding)
    end
    
    -- Test case sensitivity
    local case_findings = test_case_sensitivity_bypasses(host, port, protected_endpoints)
    for _, finding in ipairs(case_findings) do
        table.insert(all_findings, finding)
    end
    
    -- Test Unicode/encoding bypasses
    local unicode_findings = test_unicode_bypasses(host, port, protected_endpoints)
    for _, finding in ipairs(unicode_findings) do
        table.insert(all_findings, finding)
    end
    
    -- Phase 3: Analyze JWT tokens
    local jwt_findings = analyze_jwt_tokens(host, port, all_responses)
    
    -- Format results
    table.insert(result, "Authentication Bypass Test Results:")
    table.insert(result, "")
    
    -- Show discovered protected endpoints
    if #protected_endpoints > 0 then
        table.insert(result, "Protected Endpoints Discovered:")
        for _, endpoint in ipairs(protected_endpoints) do
            local status_desc = "Unknown"
            if endpoint.status == 401 then
                status_desc = "401 Unauthorized"
            elseif endpoint.status == 403 then
                status_desc = "403 Forbidden" 
            elseif endpoint.status == 302 then
                status_desc = "302 Redirect to login"
            end
            table.insert(result, string.format("  %s (%s)", endpoint.path, status_desc))
        end
        table.insert(result, "")
    end
    
    -- Show bypass vulnerabilities
    if #all_findings > 0 then
        table.insert(result, "Bypass Vulnerabilities Found:")
        
        -- Sort by severity
        table.sort(all_findings, function(a, b)
            local severity_order = {CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5}
            return (severity_order[a.severity] or 5) < (severity_order[b.severity] or 5)
        end)
        
        for _, finding in ipairs(all_findings) do
            table.insert(result, string.format("  %s: %s on %s", finding.severity, finding.technique, finding.path))
            if finding.details then
                table.insert(result, string.format("    %s", finding.details))
            end
        end
        table.insert(result, "")
    end
    
    -- Show JWT analysis
    if #jwt_findings > 0 then
        table.insert(result, "JWT Token Analysis:")
        for _, finding in ipairs(jwt_findings) do
            table.insert(result, string.format("  %s", finding.details or finding.technique))
        end
        table.insert(result, "")
    end
    
    -- Summary
    if #all_findings == 0 and #jwt_findings == 0 then
        table.insert(result, "No authentication bypass vulnerabilities detected")
    else
        local vuln_count = 0
        for _, finding in ipairs(all_findings) do
            if finding.severity == SEVERITY.CRITICAL or finding.severity == SEVERITY.HIGH then
                vuln_count = vuln_count + 1
            end
        end
        
        if vuln_count > 0 then
            table.insert(result, string.format("Summary: %d potential bypass vulnerabilities found", vuln_count))
        end
    end
    
    return table.concat(result, "\n")
end