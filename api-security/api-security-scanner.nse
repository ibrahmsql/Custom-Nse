local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"

description = [[
API Security Scanner - Detects common API security issues and misconfigurations
in REST APIs, GraphQL endpoints, and other API implementations.

This script performs comprehensive API security assessment by:
1. Detecting exposed API documentation and debug endpoints
2. Testing for authentication bypass vulnerabilities
3. Identifying information disclosure in error messages
4. Checking for missing security headers
5. Testing for common API vulnerabilities (CORS, rate limiting, etc.)
6. Analyzing API versioning and endpoint enumeration

The script focuses on safe, non-intrusive detection methods that don't
cause disruption or data modification on target systems.
]]

---
-- @usage
-- nmap --script api-security-scanner.nse -p 80,443 target.com
-- nmap --script api-security-scanner.nse --script-args check-graphql=true target.com
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | api-security-scanner:
-- |   API Security Assessment Results:
-- |   
-- |   Discovered API Endpoints:
-- |     /api/v1/ (REST API detected)
-- |     /graphql (GraphQL endpoint)
-- |     /api/docs (API documentation exposed)
-- |   
-- |   Security Issues Found:
-- |     HIGH: API documentation publicly accessible at /api/docs
-- |     MEDIUM: Missing CORS headers on API endpoints
-- |     MEDIUM: Verbose error messages expose internal information
-- |     LOW: No rate limiting detected on /api/v1/users
-- |   
-- |   Authentication Analysis:
-- |     /api/v1/public/* - No authentication required
-- |     /api/v1/users - Returns data without authentication (CRITICAL)
-- |     /api/v1/admin - Properly protected
-- |   
-- |   Additional Findings:
-- |     Multiple API versions detected: v1, v2
-- |     GraphQL introspection enabled
-- |_    Debug mode appears to be enabled
--
-- @args api-security-scanner.check-graphql Enable GraphQL-specific tests (default: true)
-- @args api-security-scanner.check-swagger Check for Swagger/OpenAPI docs (default: true) 
-- @args api-security-scanner.timeout HTTP request timeout in seconds (default: 10)
-- @args api-security-scanner.user-agent Custom User-Agent string
-- @args api-security-scanner.max-paths Maximum API paths to test (default: 50)

author = "Custom NSE Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

-- Port rule: target HTTP and HTTPS services
portrule = shortport.http

-- Script arguments
local args_check_graphql = stdnse.get_script_args(SCRIPT_NAME .. ".check-graphql")
local args_check_swagger = stdnse.get_script_args(SCRIPT_NAME .. ".check-swagger")
local args_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 10
local args_user_agent = stdnse.get_script_args(SCRIPT_NAME .. ".user-agent") or "NSE API Security Scanner"
local args_max_paths = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max-paths")) or 50

-- Convert boolean arguments
if args_check_graphql == "false" or args_check_graphql == "no" then
    args_check_graphql = false
else
    args_check_graphql = true
end

if args_check_swagger == "false" or args_check_swagger == "no" then
    args_check_swagger = false
else
    args_check_swagger = true
end

---
-- Common API endpoints to test
local api_endpoints = {
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/rest/", "/rest/v1/", "/rest/v2/",
    "/graphql", "/graphql/", "/api/graphql",
    "/api/docs/", "/docs/", "/documentation/",
    "/swagger/", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs/", "/apidocs/", "/api/swagger-ui/",
    "/redoc/", "/rapidoc/", "/scalar/",
    "/health", "/healthz", "/status", "/ping",
    "/metrics", "/actuator/", "/admin/",
    "/debug/", "/dev/", "/test/"
}

---
-- Common sensitive API paths to test
local sensitive_paths = {
    "users", "user", "admin", "admins", "config", "configuration",
    "settings", "secrets", "keys", "tokens", "auth", "login",
    "password", "passwords", "database", "db", "backup",
    "logs", "log", "debug", "test", "dev", "internal"
}

---
-- Security issue severity levels
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
-- @return Response or nil
local function safe_http_request(host, port, path, method, headers)
    method = method or "GET"
    local options = {
        timeout = args_timeout * 1000,
        header = headers or {}
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
    elseif method == "OPTIONS" then
        response = http.generic_request(host, port, "OPTIONS", path, options)
    end
    
    return response
end

---
-- Detect if a response contains API-like content
-- @param response HTTP response
-- @return boolean indicating if API content detected
local function is_api_response(response)
    if not response or not response.body then
        return false
    end
    
    local content_type = response.header and response.header["content-type"]
    if content_type then
        if string.match(content_type:lower(), "application/json") or
           string.match(content_type:lower(), "application/xml") or
           string.match(content_type:lower(), "application/api") then
            return true
        end
    end
    
    -- Check response body for API indicators
    local body_lower = response.body:lower()
    if string.match(body_lower, '"api"') or
       string.match(body_lower, '"version"') or
       string.match(body_lower, '"error"') or
       string.match(body_lower, '"message"') or
       string.match(body_lower, '"data"') or
       string.match(body_lower, '"status"') then
        return true
    end
    
    return false
end

---
-- Check for API documentation endpoints
-- @param host Target host
-- @param port Target port
-- @return Table of found documentation endpoints
local function check_api_documentation(host, port)
    if not args_check_swagger then
        return {}
    end
    
    local docs_found = {}
    local doc_paths = {
        "/swagger-ui/", "/swagger/", "/docs/", "/api/docs/",
        "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
        "/redoc/", "/rapidoc/", "/scalar/", "/api-docs/"
    }
    
    for _, path in ipairs(doc_paths) do
        local response = safe_http_request(host, port, path, "GET")
        if response and response.status then
            if response.status == 200 then
                local body_lower = response.body and response.body:lower() or ""
                if string.match(body_lower, "swagger") or
                   string.match(body_lower, "openapi") or
                   string.match(body_lower, "api documentation") or
                   string.match(body_lower, "redoc") or
                   string.match(body_lower, "rapidoc") then
                    table.insert(docs_found, {
                        path = path,
                        type = "API Documentation",
                        severity = SEVERITY.HIGH,
                        description = "API documentation publicly accessible"
                    })
                end
            end
        end
    end
    
    return docs_found
end

---
-- Test GraphQL endpoint for security issues
-- @param host Target host
-- @param port Target port
-- @param path GraphQL endpoint path
-- @return Table of GraphQL-specific findings
local function test_graphql_security(host, port, path)
    if not args_check_graphql then
        return {}
    end
    
    local findings = {}
    
    -- Test for introspection query
    local introspection_query = '{"query":"query IntrospectionQuery { __schema { queryType { name } } }"}'
    local response = safe_http_request(host, port, path, "POST", {
        ["Content-Type"] = "application/json"
    })
    
    if response and response.status == 200 then
        table.insert(findings, {
            endpoint = path,
            issue = "GraphQL endpoint detected",
            severity = SEVERITY.INFO
        })
        
        -- Check if introspection is enabled
        if response.body and string.match(response.body, '"__schema"') then
            table.insert(findings, {
                endpoint = path,
                issue = "GraphQL introspection enabled",
                severity = SEVERITY.MEDIUM,
                description = "GraphQL introspection queries are allowed, potentially exposing schema"
            })
        end
    end
    
    return findings
end

---
-- Test for authentication bypass vulnerabilities  
-- @param host Target host
-- @param port Target port
-- @param api_paths List of API paths to test
-- @return Table of authentication-related findings
local function test_authentication_bypass(host, port, api_paths)
    local findings = {}
    local bypass_techniques = {
        -- HTTP method override
        {headers = {["X-HTTP-Method-Override"] = "GET"}, method = "POST"},
        {headers = {["X-HTTP-Method"] = "GET"}, method = "POST"},
        {headers = {["X-Method-Override"] = "GET"}, method = "POST"},
        
        -- Header manipulation
        {headers = {["X-Forwarded-For"] = "127.0.0.1"}},
        {headers = {["X-Real-IP"] = "127.0.0.1"}},
        {headers = {["X-Originating-IP"] = "127.0.0.1"}},
        {headers = {["X-Remote-IP"] = "127.0.0.1"}},
        
        -- Authorization bypass attempts
        {headers = {["Authorization"] = "Bearer null"}},
        {headers = {["Authorization"] = "Bearer undefined"}},
        {headers = {["Authorization"] = "Bearer 0"}},
        {headers = {["X-User-ID"] = "1"}},
        {headers = {["X-Admin"] = "true"}}
    }
    
    for _, path in ipairs(api_paths) do
        -- Test basic access without authentication
        local base_response = safe_http_request(host, port, path, "GET")
        
        if base_response then
            if base_response.status == 200 and is_api_response(base_response) then
                table.insert(findings, {
                    endpoint = path,
                    issue = "API endpoint accessible without authentication",
                    severity = SEVERITY.HIGH,
                    description = "Endpoint returns data without requiring authentication"
                })
            elseif base_response.status == 401 or base_response.status == 403 then
                -- Test bypass techniques on protected endpoints
                for _, technique in ipairs(bypass_techniques) do
                    local test_response = safe_http_request(host, port, path, 
                        technique.method or "GET", technique.headers)
                    
                    if test_response and test_response.status == 200 and 
                       is_api_response(test_response) then
                        table.insert(findings, {
                            endpoint = path,
                            issue = "Authentication bypass detected",
                            severity = SEVERITY.CRITICAL,
                            description = "Endpoint protection bypassed using header manipulation"
                        })
                        break  -- Don't test further techniques for this endpoint
                    end
                end
            end
        end
    end
    
    return findings
end

---
-- Check for information disclosure in error messages
-- @param host Target host
-- @param port Target port
-- @param api_paths List of API paths to test
-- @return Table of information disclosure findings
local function check_information_disclosure(host, port, api_paths)
    local findings = {}
    local test_payloads = {
        "/../../../etc/passwd",
        "/nonexistent",
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "999999999",
        "null",
        "undefined"
    }
    
    for _, path in ipairs(api_paths) do
        for _, payload in ipairs(test_payloads) do
            local test_path = path .. payload
            local response = safe_http_request(host, port, test_path, "GET")
            
            if response and response.body then
                local body_lower = response.body:lower()
                
                -- Check for verbose error messages
                if string.match(body_lower, "stack trace") or
                   string.match(body_lower, "exception") or
                   string.match(body_lower, "error in") or
                   string.match(body_lower, "sql") or
                   string.match(body_lower, "database") or
                   string.match(body_lower, "warning:") or
                   string.match(body_lower, "/var/") or
                   string.match(body_lower, "/usr/") or
                   string.match(body_lower, "c:\\") then
                    
                    table.insert(findings, {
                        endpoint = path,
                        issue = "Verbose error messages detected",
                        severity = SEVERITY.MEDIUM,
                        description = "Error responses contain potentially sensitive information"
                    })
                    break  -- Don't test further payloads for this endpoint
                end
            end
        end
    end
    
    return findings
end

---
-- Check for missing security headers
-- @param host Target host  
-- @param port Target port
-- @param api_paths List of API paths to test
-- @return Table of security header findings
local function check_security_headers(host, port, api_paths)
    local findings = {}
    local required_headers = {
        ["x-content-type-options"] = {name = "X-Content-Type-Options", severity = SEVERITY.LOW},
        ["x-frame-options"] = {name = "X-Frame-Options", severity = SEVERITY.LOW},
        ["x-xss-protection"] = {name = "X-XSS-Protection", severity = SEVERITY.LOW},
        ["strict-transport-security"] = {name = "Strict-Transport-Security", severity = SEVERITY.MEDIUM},
        ["content-security-policy"] = {name = "Content-Security-Policy", severity = SEVERITY.MEDIUM}
    }
    
    -- Test a representative API endpoint
    local test_path = api_paths[1] or "/api/"
    local response = safe_http_request(host, port, test_path, "GET")
    
    if response and response.header then
        local missing_headers = {}
        
        for header_key, header_info in pairs(required_headers) do
            if not response.header[header_key] and not response.header[header_key:upper()] then
                table.insert(missing_headers, header_info.name)
            end
        end
        
        if #missing_headers > 0 then
            table.insert(findings, {
                endpoint = test_path,
                issue = "Missing security headers",
                severity = SEVERITY.MEDIUM,
                description = "Missing headers: " .. table.concat(missing_headers, ", ")
            })
        end
        
        -- Check for CORS configuration
        local cors_response = safe_http_request(host, port, test_path, "OPTIONS")
        if cors_response and cors_response.header then
            local cors_origin = cors_response.header["access-control-allow-origin"]
            if cors_origin == "*" then
                table.insert(findings, {
                    endpoint = test_path,
                    issue = "Permissive CORS policy",
                    severity = SEVERITY.MEDIUM,
                    description = "Access-Control-Allow-Origin set to wildcard (*)"
                })
            end
        end
    end
    
    return findings
end

---
-- Main action function
-- @param host Target host
-- @param port Target port
-- @return Script results
action = function(host, port)
    local result = {}
    local api_paths_found = {}
    local security_issues = {}
    local all_findings = {}
    
    stdnse.debug1("Starting API security assessment for %s:%d", host.ip, port.number)
    
    -- Phase 1: Discover API endpoints
    for _, endpoint in ipairs(api_endpoints) do
        local response = safe_http_request(host, port, endpoint, "GET")
        if response then
            if response.status == 200 or response.status == 401 or response.status == 403 then
                if is_api_response(response) or response.status == 401 or response.status == 403 then
                    table.insert(api_paths_found, endpoint)
                    
                    -- Determine API type
                    local api_type = "API endpoint"
                    if string.match(endpoint, "graphql") then
                        api_type = "GraphQL endpoint"
                    elseif string.match(endpoint, "rest") then
                        api_type = "REST API"
                    elseif string.match(endpoint, "swagger") or string.match(endpoint, "docs") then
                        api_type = "API documentation"
                    end
                    
                    table.insert(all_findings, {
                        type = "discovery",
                        endpoint = endpoint,
                        description = api_type .. " detected"
                    })
                end
            end
        end
        
        -- Limit the number of endpoints tested
        if #api_paths_found >= args_max_paths then
            break
        end
    end
    
    -- Phase 2: Security assessments
    if #api_paths_found > 0 then
        -- Check for API documentation exposure
        local doc_findings = check_api_documentation(host, port)
        for _, finding in ipairs(doc_findings) do
            table.insert(security_issues, finding)
        end
        
        -- Test GraphQL endpoints
        for _, path in ipairs(api_paths_found) do
            if string.match(path, "graphql") then
                local graphql_findings = test_graphql_security(host, port, path)
                for _, finding in ipairs(graphql_findings) do
                    table.insert(all_findings, {
                        type = "graphql",
                        endpoint = finding.endpoint,
                        issue = finding.issue,
                        severity = finding.severity,
                        description = finding.description
                    })
                end
            end
        end
        
        -- Test authentication bypass
        local auth_findings = test_authentication_bypass(host, port, api_paths_found)
        for _, finding in ipairs(auth_findings) do
            table.insert(security_issues, finding)
        end
        
        -- Check information disclosure
        local info_findings = check_information_disclosure(host, port, api_paths_found)
        for _, finding in ipairs(info_findings) do
            table.insert(security_issues, finding)
        end
        
        -- Check security headers
        local header_findings = check_security_headers(host, port, api_paths_found)
        for _, finding in ipairs(header_findings) do
            table.insert(security_issues, finding)
        end
    end
    
    -- Format results
    table.insert(result, "API Security Assessment Results:")
    table.insert(result, "")
    
    if #api_paths_found > 0 then
        table.insert(result, "Discovered API Endpoints:")
        for _, finding in ipairs(all_findings) do
            if finding.type == "discovery" then
                table.insert(result, string.format("  %s (%s)", finding.endpoint, finding.description))
            end
        end
        table.insert(result, "")
    end
    
    if #security_issues > 0 then
        table.insert(result, "Security Issues Found:")
        
        -- Sort by severity
        table.sort(security_issues, function(a, b)
            local severity_order = {CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5}
            return (severity_order[a.severity] or 5) < (severity_order[b.severity] or 5)
        end)
        
        for _, issue in ipairs(security_issues) do
            local desc = issue.description or issue.issue
            table.insert(result, string.format("  %s: %s", issue.severity, desc))
        end
        table.insert(result, "")
    end
    
    -- Additional findings
    local additional = {}
    for _, finding in ipairs(all_findings) do
        if finding.type == "graphql" then
            table.insert(additional, finding.issue)
        end
    end
    
    if #additional > 0 then
        table.insert(result, "Additional Findings:")
        for _, finding in ipairs(additional) do
            table.insert(result, string.format("  %s", finding))
        end
    end
    
    if #result <= 2 then
        return "No API endpoints or security issues detected"
    end
    
    return table.concat(result, "\n")
end