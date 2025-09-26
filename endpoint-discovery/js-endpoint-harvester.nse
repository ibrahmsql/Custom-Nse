local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
JavaScript Endpoint Harvester - Discovers and extracts potential API endpoints, 
URLs, and route paths from JavaScript files found on web applications.

This script:
1. Fetches the main page of HTTP/HTTPS services
2. Recursively discovers linked JavaScript files
3. Downloads and analyzes each JS file for endpoints
4. Extracts API endpoints, URLs, and route paths using regex patterns
5. Outputs a deduplicated list of discovered endpoints

The script respects configurable limits for recursion depth, file size, 
and includes timeout handling for robust scanning.
]]

---
-- @usage
-- nmap --script js-endpoint-harvester.nse -p 80,443 <target>
-- nmap --script js-endpoint-harvester.nse --script-args max-depth=3,max-size=1024000 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | js-endpoint-harvester:
-- |   Discovered JavaScript files (3):
-- |     /js/app.js (45.2KB)
-- |     /assets/vendor.js (234.7KB)
-- |     /static/bundle.js (156.3KB)
-- |   
-- |   Discovered endpoints (15):
-- |     API Endpoints:
-- |       /api/v1/users
-- |       /api/v1/auth/login
-- |       /api/v2/products
-- |     Routes:
-- |       /dashboard
-- |       /profile/settings
-- |       /admin/panel
-- |     External URLs:
-- |       https://api.example.com/v1/
-- |_      https://cdn.example.com/assets/
--
-- @args js-endpoint-harvester.max-depth Maximum recursion depth for following JS links (default: 2)
-- @args js-endpoint-harvester.max-size Maximum JS file size to download in bytes (default: 512000)
-- @args js-endpoint-harvester.timeout HTTP request timeout in seconds (default: 10)
-- @args js-endpoint-harvester.custom-pattern Custom regex pattern for endpoint extraction
-- @args js-endpoint-harvester.user-agent Custom User-Agent string (default: NSE JS Harvester)

author = "Custom NSE Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Port rule: target HTTP and HTTPS services
portrule = shortport.http

-- Script arguments with defaults
local args_max_depth = stdnse.get_script_args(SCRIPT_NAME .. ".max-depth") or 2
local args_max_size = stdnse.get_script_args(SCRIPT_NAME .. ".max-size") or 512000
local args_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or 10
local args_custom_pattern = stdnse.get_script_args(SCRIPT_NAME .. ".custom-pattern")
local args_user_agent = stdnse.get_script_args(SCRIPT_NAME .. ".user-agent") or "NSE JS Harvester"

-- Convert string arguments to numbers
args_max_depth = tonumber(args_max_depth)
args_max_size = tonumber(args_max_size)
args_timeout = tonumber(args_timeout)

---
-- Utility function to format file size
-- @param size Size in bytes
-- @return Formatted size string
local function format_size(size)
    if size < 1024 then
        return string.format("%.1fB", size)
    elseif size < 1024 * 1024 then
        return string.format("%.1fKB", size / 1024)
    else
        return string.format("%.1fMB", size / (1024 * 1024))
    end
end

---
-- Utility function to normalize URLs
-- @param base_url Base URL for resolving relative paths
-- @param link Relative or absolute URL
-- @return Normalized absolute URL
local function normalize_url(base_url, link)
    -- Remove fragments and clean whitespace
    link = string.gsub(link, "#.*", "")
    link = string.match(link, "^%s*(.-)%s*$")
    
    if not link or link == "" then
        return nil
    end
    
    -- If already absolute, return as-is
    if string.match(link, "^https?://") then
        return link
    end
    
    -- Handle protocol-relative URLs
    if string.match(link, "^//") then
        local protocol = string.match(base_url, "^(https?):")
        return protocol .. ":" .. link
    end
    
    -- Parse base URL
    local parsed_base = url.parse(base_url)
    if not parsed_base then
        return nil
    end
    
    -- Handle absolute paths
    if string.match(link, "^/") then
        return parsed_base.scheme .. "://" .. parsed_base.host .. 
               (parsed_base.port and (":" .. parsed_base.port) or "") .. link
    end
    
    -- Handle relative paths
    local base_path = parsed_base.path or "/"
    if not string.match(base_path, "/$") then
        base_path = string.gsub(base_path, "/[^/]*$", "/")
    end
    
    return parsed_base.scheme .. "://" .. parsed_base.host .. 
           (parsed_base.port and (":" .. parsed_base.port) or "") .. 
           base_path .. link
end

---
-- Extract JavaScript file URLs from HTML content
-- @param content HTML content to parse
-- @param base_url Base URL for resolving relative links
-- @return Table of JavaScript URLs
local function extract_js_urls(content, base_url)
    local js_urls = {}
    local seen = {}
    
    -- Pattern for <script src="..."> tags
    for src in string.gmatch(content, '<script[^>]+src=["\']([^"\']+)["\'][^>]*>') do
        local normalized = normalize_url(base_url, src)
        if normalized and not seen[normalized] and 
           (string.match(normalized, "%.js$") or string.match(normalized, "%.js%?")) then
            seen[normalized] = true
            table.insert(js_urls, normalized)
        end
    end
    
    -- Pattern for JavaScript imports and requires in inline scripts
    for js_path in string.gmatch(content, 'import[^"\']]*["\']([^"\']]+%.js[^"\']]*)["\']') do
        local normalized = normalize_url(base_url, js_path)
        if normalized and not seen[normalized] then
            seen[normalized] = true
            table.insert(js_urls, normalized)
        end
    end
    
    return js_urls
end

---
-- Extract potential endpoints from JavaScript content using regex patterns
-- @param content JavaScript content to analyze
-- @return Table of discovered endpoints categorized by type
local function extract_endpoints(content)
    local endpoints = {
        api = {},
        routes = {},
        external = {}
    }
    local seen = {}
    
    -- Default patterns for endpoint discovery
    local patterns = {
        -- API endpoints - more specific patterns
        api = {
            '["\'/]api/[a-zA-Z0-9_/.-]+["\']?',
            '["\'/]v%d+/[a-zA-Z0-9_/.-]+["\']?',
            '["\'/]rest/[a-zA-Z0-9_/.-]+["\']?',
            '["\'/]graphql[a-zA-Z0-9_/.-]*["\']?',
            '["\'/]api["\']?',
            'endpoint["\']?%s*:%s*["\'][^"\']*/[a-zA-Z][^"\']*/[^"\']["\']',
            'url["\']?%s*:%s*["\'][^"\']*/api/[^"\']["\']'
        },
        
        -- Route patterns - more restrictive
        routes = {
            '["\'/][a-zA-Z][a-zA-Z0-9_-]+/[a-zA-Z0-9_/-]*["\']?',  -- Multi-segment paths
            'route["\']?%s*:%s*["\'][^"\']*/[a-zA-Z][^"\']["\']',
            'path["\']?%s*:%s*["\'][^"\']*/[a-zA-Z][^"\']["\']',
            '["\'][/][a-zA-Z][a-zA-Z0-9_-]+[/][a-zA-Z0-9_/-]*["\']',
            'href%s*=%s*["\'][^"\']*/[a-zA-Z][a-zA-Z0-9_/-]*["\']'
        },
        
        -- External URLs - more specific
        external = {
            '["\']https?://[a-zA-Z0-9.-]+[a-zA-Z0-9._/-]*["\']',
            'url["\']?%s*:%s*["\']https?://[^"\']["\']',
            'src["\']?%s*:%s*["\']https?://[^"\']["\']'
        }
    }
    
    -- Add custom pattern if provided
    if args_custom_pattern then
        table.insert(patterns.api, args_custom_pattern)
    end
    
    -- Extract API endpoints
    for _, pattern in ipairs(patterns.api) do
        for match in string.gmatch(content, pattern) do
            -- Clean the match
            match = string.gsub(match, '^["\'/]', '')
            match = string.gsub(match, '["\']$', '')
            match = string.gsub(match, '[?#].*$', '')
            
            -- More strict validation for API endpoints
            if match and #match > 3 and #match < 200 and not seen[match] and 
               (string.match(match, '^api/') or 
                string.match(match, '^v%d+/') or 
                string.match(match, '^rest/') or 
                string.match(match, 'graphql') or
                string.match(match, '^/api/') or 
                string.match(match, '^/v%d+/') or 
                string.match(match, '^/rest/') or 
                string.match(match, '/graphql')) and
               -- Filter out obvious false positives
               not string.match(match, '^[a-z]$') and  -- Single letters
               not string.match(match, '^[A-Z][a-z]*$') and  -- Single words like 'Math'
               not string.match(match, '/[a-z]$') and  -- Ending with single letter
               not string.match(match, '^[a-z]+$') and  -- Single lowercase words
               string.match(match, '/') then  -- Must contain slash
                
                -- Ensure it starts with / if not already
                if not string.match(match, '^/') then
                    match = '/' .. match
                end
                
                seen[match] = true
                table.insert(endpoints.api, match)
            end
        end
    end
    
    -- Extract route patterns
    for _, pattern in ipairs(patterns.routes) do
        for match in string.gmatch(content, pattern) do
            match = string.gsub(match, '^["\'/]', '')
            match = string.gsub(match, '["\']$', '')
            match = string.gsub(match, '[?#].*$', '')
            
            -- More strict validation for routes
            if match and #match > 4 and #match < 100 and not seen[match] and 
               string.match(match, '/') and  -- Must contain slash
               string.match(match, '^[a-zA-Z]') and  -- Start with letter
               not string.match(match, '^/api/') and  -- Not an API endpoint
               not string.match(match, '^/v%d+/') and  -- Not a versioned API
               not string.match(match, '^/rest/') and  -- Not REST API
               not string.match(match, 'graphql') and  -- Not GraphQL
               not string.match(match, '%.js') and  -- Not a JS file
               not string.match(match, '%.css') and  -- Not a CSS file
               not string.match(match, '%.png') and  -- Not an image
               not string.match(match, '%.jpg') and  -- Not an image
               not string.match(match, '%.gif') and  -- Not an image
               not string.match(match, '^[a-z]+$') and  -- Not single word
               not string.match(match, '^[A-Z][a-z]*$') and  -- Not single capitalized word
               not string.match(match, '/[a-z]$') and  -- Not ending with single letter
               not string.match(match, '^[a-zA-Z]/[a-zA-Z]$') and  -- Not single letter paths
               not string.match(match, 'application/') and  -- Not MIME types
               not string.match(match, 'text/') and  -- Not MIME types
               not string.match(match, 'image/') and  -- Not MIME types
               not string.match(match, '/[a-zA-Z0-9+/=]{20,}') and  -- Not base64-like strings
               not string.match(match, '/[A-Za-z0-9]{32,}') and  -- Not hash-like strings
               not string.match(match, '/[A-Za-z0-9/+]{15,}$') and  -- Not long encoded strings
               not string.match(match, '[A-Z][a-z0-9]+/[0-9]+$') and  -- Not version strings like Chrome/66
               not string.match(match, '/[a-z0-9]{10,}/[a-zA-Z0-9/]+$') and  -- Not complex hash paths
               not string.match(match, '/[a-zA-Z0-9]{8,}$') and  -- Not hash endings
               not string.match(match, '^[a-zA-Z0-9]{8,}/') and  -- Not starting with hash
               string.match(match, '[a-zA-Z]') then  -- Must contain at least one letter in meaningful position
                
                -- Ensure it starts with / if not already
                if not string.match(match, '^/') then
                    match = '/' .. match
                end
                
                seen[match] = true
                table.insert(endpoints.routes, match)
            end
        end
    end
    
    -- Extract external URLs
    for _, pattern in ipairs(patterns.external) do
        for match in string.gmatch(content, pattern) do
            match = string.gsub(match, '^["\']', '')
            match = string.gsub(match, '["\']$', '')
            match = string.gsub(match, '[?#].*$', '')
            
            -- Validate external URLs more strictly
            if match and #match > 10 and #match < 200 and not seen[match] and 
               string.match(match, '^https?://') and
               string.match(match, '^https?://[a-zA-Z0-9.-]+') and  -- Valid domain format
               not string.match(match, 'localhost') and  -- Skip localhost unless specifically needed
               not string.match(match, '127%.0%.0%.1') then  -- Skip local IPs
                seen[match] = true
                table.insert(endpoints.external, match)
            end
        end
    end
    
    return endpoints
end

---
-- Download and analyze a JavaScript file
-- @param js_url URL of the JavaScript file
-- @param host Target host
-- @param port Target port
-- @return Table with file info and extracted endpoints
local function analyze_js_file(js_url, host, port)
    -- Parse the URL to get the request path
    local parsed_url = url.parse(js_url)
    if not parsed_url then
        return nil, "Failed to parse URL"
    end
    
    -- Determine if we need to use SSL
    local use_ssl = (parsed_url.scheme == "https")
    local target_port = parsed_url.port or (use_ssl and 443 or 80)
    local target_host = parsed_url.host
    
    -- If the JS file is on a different host, update our target
    if target_host ~= host then
        host = target_host
        port = target_port
    end
    
    -- Make HTTP request
    local options = {
        timeout = args_timeout * 1000,  -- Convert to milliseconds
        header = {
            ["User-Agent"] = args_user_agent,
            ["Accept"] = "application/javascript, text/javascript, */*"
        }
    }
    
    local response
    if use_ssl then
        response = http.get(host, target_port, parsed_url.path .. (parsed_url.query and ("?" .. parsed_url.query) or ""), options)
    else
        response = http.get(host, target_port, parsed_url.path .. (parsed_url.query and ("?" .. parsed_url.query) or ""), options)
    end
    
    if not response or not response.body then
        return nil, "Failed to download JavaScript file"
    end
    
    -- Check content length
    local content_length = #response.body
    if content_length > args_max_size then
        return nil, string.format("File too large (%s > %s)", 
                                format_size(content_length), format_size(args_max_size))
    end
    
    -- Extract endpoints from the JavaScript content
    local endpoints = extract_endpoints(response.body)
    
    return {
        url = js_url,
        size = content_length,
        endpoints = endpoints
    }, nil
end

---
-- Main action function
-- @param host Target host
-- @param port Target port
-- @return Nmap script results
action = function(host, port)
    local result = {}
    local all_endpoints = {api = {}, routes = {}, external = {}}
    local js_files = {}
    local processed_urls = {}
    
    -- Build base URL
    local base_url = (port.version.service_tunnel == "ssl" and "https" or "http") .. 
                    "://" .. host.ip .. ":" .. port.number
    
    -- HTTP options
    local options = {
        timeout = args_timeout * 1000,
        header = {
            ["User-Agent"] = args_user_agent
        }
    }
    
    -- Fetch the main page
    stdnse.debug1("Fetching main page: %s", base_url)
    local response = http.get(host, port, "/", options)
    
    if not response or not response.body then
        return "Failed to fetch main page"
    end
    
    -- Extract JavaScript URLs from main page
    local js_urls_queue = extract_js_urls(response.body, base_url)
    local depth = 0
    
    -- Process JavaScript files with depth limit
    while #js_urls_queue > 0 and depth < args_max_depth do
        local current_batch = js_urls_queue
        js_urls_queue = {}
        
        stdnse.debug1("Processing batch at depth %d with %d files", depth, #current_batch)
        
        for _, js_url in ipairs(current_batch) do
            if not processed_urls[js_url] then
                processed_urls[js_url] = true
                
                stdnse.debug2("Analyzing JavaScript file: %s", js_url)
                local file_info, error_msg = analyze_js_file(js_url, host.ip, port.number)
                
                if file_info then
                    table.insert(js_files, {
                        url = js_url,
                        size = file_info.size
                    })
                    
                    -- Merge endpoints
                    for category, endpoints in pairs(file_info.endpoints) do
                        for _, endpoint in ipairs(endpoints) do
                            -- Deduplicate endpoints
                            local found = false
                            for _, existing in ipairs(all_endpoints[category]) do
                                if existing == endpoint then
                                    found = true
                                    break
                                end
                            end
                            if not found then
                                table.insert(all_endpoints[category], endpoint)
                            end
                        end
                    end
                    
                    -- If we're still within depth limit, look for more JS files
                    -- (This could be expanded to parse JS files for more JS imports)
                    
                elseif error_msg then
                    stdnse.debug1("Failed to analyze %s: %s", js_url, error_msg)
                end
            end
        end
        
        depth = depth + 1
    end
    
    -- Sort endpoints
    table.sort(all_endpoints.api)
    table.sort(all_endpoints.routes)
    table.sort(all_endpoints.external)
    
    -- Build result output
    if #js_files > 0 then
        table.insert(result, string.format("Discovered JavaScript files (%d):", #js_files))
        for _, file in ipairs(js_files) do
            -- Extract just the path for cleaner display
            local display_path = string.gsub(file.url, "^https?://[^/]+", "")
            table.insert(result, string.format("  %s (%s)", display_path, format_size(file.size)))
        end
        table.insert(result, "")
    end
    
    -- Count total endpoints
    local total_endpoints = #all_endpoints.api + #all_endpoints.routes + #all_endpoints.external
    
    if total_endpoints > 0 then
        table.insert(result, string.format("Discovered endpoints (%d):", total_endpoints))
        
        if #all_endpoints.api > 0 then
            table.insert(result, "  API Endpoints:")
            for _, endpoint in ipairs(all_endpoints.api) do
                table.insert(result, "    " .. endpoint)
            end
        end
        
        if #all_endpoints.routes > 0 then
            table.insert(result, "  Routes:")
            for _, route in ipairs(all_endpoints.routes) do
                table.insert(result, "    " .. route)
            end
        end
        
        if #all_endpoints.external > 0 then
            table.insert(result, "  External URLs:")
            for _, url in ipairs(all_endpoints.external) do
                table.insert(result, "    " .. url)
            end
        end
    else
        table.insert(result, "No endpoints discovered")
    end
    
    -- Return results
    if #result > 0 then
        return table.concat(result, "\n")
    else
        return "No JavaScript files found"
    end
end