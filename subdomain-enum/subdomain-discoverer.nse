local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"

description = [[
Subdomain Discovery - Discovers subdomains using SSL certificates and 
certificate transparency logs without noisy wordlist scanning.

This script performs lightweight subdomain enumeration by:
1. Querying certificate transparency logs (crt.sh)
2. Parsing SSL certificate SAN entries
3. DNS resolution verification of discovered subdomains
4. Clean output with active subdomain validation

Focuses on passive techniques that don't generate noise or alerts.
]]

---
-- @usage
-- nmap --script subdomain-discoverer.nse target.com
-- nmap --script subdomain-discoverer.nse --script-args timeout=10 target.com
--
-- @output  
-- Host script results:
-- | subdomain-discoverer:
-- |   Certificate Transparency Subdomains:
-- |     www.example.com (active)
-- |     api.example.com (active)
-- |     mail.example.com (active)
-- |     blog.example.com (inactive)
-- |     dev.example.com (inactive)
-- |   
-- |_  Total: 5 found, 3 active
--
-- @args subdomain-discoverer.timeout HTTP request timeout in seconds (default: 10)
-- @args subdomain-discoverer.verify-dns Verify subdomains via DNS lookup (default: true)

author = "Custom NSE Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Host rule: target any host
hostrule = function(host)
    return true
end

-- Script arguments
local args_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 10
local args_verify_dns = stdnse.get_script_args(SCRIPT_NAME .. ".verify-dns")

-- Convert verify-dns argument (default to true)
if args_verify_dns == "false" or args_verify_dns == "no" then
    args_verify_dns = false
else
    args_verify_dns = true
end

---
-- Query certificate transparency logs for subdomains
-- @param domain Target domain
-- @return table of found subdomains
local function query_ct_logs(domain)
    stdnse.debug1("Querying certificate transparency logs for %s", domain)
    local found_subdomains = {}
    
    -- Use crt.sh API for CT log queries
    local ct_url = "https://crt.sh/?q=%." .. domain .. "&output=json"
    local response = http.get_url(ct_url, {timeout = args_timeout * 1000})
    
    if response and response.body and response.status == 200 then
        local status, ct_data = pcall(json.parse, response.body)
        if status and ct_data and type(ct_data) == "table" then
            for _, cert in ipairs(ct_data) do
                if cert.name_value then
                    -- Parse certificate common names and SAN entries
                    for line in string.gmatch(cert.name_value, "([^\r\n]+)") do
                        for subdomain in string.gmatch(line, "([^%s]+)") do
                            -- Clean up subdomain
                            subdomain = string.gsub(subdomain, "^%*%.", "")  -- Remove wildcards
                            subdomain = string.lower(subdomain)  -- Normalize case
                            
                            -- Validate subdomain format and ensure it's for our domain
                            if string.match(subdomain, "^[a-zA-Z0-9.-]+$") and
                               string.match(subdomain, "%." .. string.gsub(domain, "%.", "%%.") .. "$") and
                               not string.match(subdomain, "^%.") and
                               #subdomain > #domain then
                                found_subdomains[subdomain] = true
                            end
                        end
                    end
                end
            end
        else
            stdnse.debug1("Failed to parse CT log response for %s", domain)
        end
    else
        stdnse.debug1("Failed to query CT logs for %s", domain)
    end
    
    return found_subdomains
end

---
-- Verify subdomain via DNS lookup
-- @param subdomain Subdomain to verify
-- @return boolean indicating if subdomain is active
local function verify_subdomain(subdomain)
    if not args_verify_dns then
        return true  -- Skip verification if disabled
    end
    
    -- Simple DNS lookup using nslookup command
    local cmd = string.format("nslookup %s > /dev/null 2>&1", subdomain)
    local result = os.execute(cmd)
    
    -- Command returns 0 if successful
    return result == 0 or result == true
end

---
-- Main action function
-- @param host Target host
-- @return Script results
action = function(host)
    local domain = host.targetname or host.name
    if not domain then
        return "Unable to determine target domain"
    end
    
    stdnse.debug1("Starting subdomain discovery for domain: %s", domain)
    
    -- Query certificate transparency logs
    local ct_subdomains = query_ct_logs(domain)
    
    if not ct_subdomains or next(ct_subdomains) == nil then
        return "No subdomains found in certificate transparency logs"
    end
    
    -- Convert to sorted list and verify
    local subdomains = {}
    for subdomain, _ in pairs(ct_subdomains) do
        table.insert(subdomains, subdomain)
    end
    table.sort(subdomains)
    
    -- Verify subdomains if requested
    local results = {}
    local active_count = 0
    
    table.insert(results, "Certificate Transparency Subdomains:")
    
    for _, subdomain in ipairs(subdomains) do
        local is_active = verify_subdomain(subdomain)
        local status = is_active and "active" or "inactive"
        
        if is_active then
            active_count = active_count + 1
        end
        
        table.insert(results, string.format("  %s (%s)", subdomain, status))
    end
    
    table.insert(results, "")
    table.insert(results, string.format("Total: %d found, %d active", #subdomains, active_count))
    
    return table.concat(results, "\n")
end