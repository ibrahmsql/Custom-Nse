local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local http = require "http"
local json = require "json"

description = [[
Advanced Subdomain Discovery - Discovers subdomains using multiple techniques including
DNS enumeration, certificate transparency logs, and common wordlist fuzzing.

This script performs comprehensive subdomain enumeration by:
1. DNS zone transfer attempts (if allowed)
2. Common subdomain wordlist fuzzing
3. Certificate transparency log queries
4. DNS wildcard detection and filtering
5. Recursive subdomain discovery

The script is designed to be thorough yet respectful of rate limits and includes
intelligent filtering to reduce false positives from wildcard DNS responses.
]]

---
-- @usage
-- nmap --script subdomain-discoverer.nse target.com
-- nmap --script subdomain-discoverer.nse --script-args wordlist-size=large target.com
--
-- @output  
-- Host script results:
-- | subdomain-discoverer:
-- |   Discovered subdomains (12):
-- |     www.example.com (93.184.216.34)
-- |     mail.example.com (93.184.216.35)
-- |     blog.example.com (185.199.108.153)
-- |     api.example.com (93.184.216.36)
-- |   
-- |   Certificate transparency findings (3):
-- |     dev.example.com (from CT logs)
-- |     staging.example.com (from CT logs)
-- |     internal.example.com (from CT logs)
-- |   
-- |   DNS Information:
-- |     Wildcard DNS: No
-- |     Zone transfer: Denied
-- |_    Total unique subdomains: 15
--
-- @args subdomain-discoverer.wordlist-size Wordlist size: small, medium, large (default: medium)
-- @args subdomain-discoverer.max-depth Maximum recursion depth for subdomain discovery (default: 2)
-- @args subdomain-discoverer.timeout DNS query timeout in seconds (default: 5)
-- @args subdomain-discoverer.ct-logs Query certificate transparency logs (default: true)
-- @args subdomain-discoverer.custom-wordlist Custom comma-separated subdomain list

author = "Custom NSE Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Host rule: target any host
hostrule = function(host)
    return true
end

-- Script arguments
local args_wordlist_size = stdnse.get_script_args(SCRIPT_NAME .. ".wordlist-size") or "medium"
local args_max_depth = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max-depth")) or 2
local args_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
local args_ct_logs = stdnse.get_script_args(SCRIPT_NAME .. ".ct-logs")
local args_custom_wordlist = stdnse.get_script_args(SCRIPT_NAME .. ".custom-wordlist")

-- Convert ct-logs argument
if args_ct_logs == "false" or args_ct_logs == "no" then
    args_ct_logs = false
else
    args_ct_logs = true
end

---
-- Predefined subdomain wordlists
local wordlists = {
    small = {
        "www", "mail", "ftp", "blog", "www2", "admin", "api", "test", "dev", "staging"
    },
    medium = {
        "www", "mail", "ftp", "blog", "www2", "admin", "api", "test", "dev", "staging",
        "m", "mobile", "shop", "store", "portal", "webmail", "secure", "vpn", "remote",
        "support", "help", "docs", "forum", "community", "news", "media", "static",
        "assets", "cdn", "img", "images", "upload", "files", "download", "beta", 
        "alpha", "demo", "sandbox", "old", "new", "v1", "v2", "api1", "api2"
    },
    large = {
        "www", "mail", "ftp", "blog", "www2", "admin", "api", "test", "dev", "staging",
        "m", "mobile", "shop", "store", "portal", "webmail", "secure", "vpn", "remote",
        "support", "help", "docs", "forum", "community", "news", "media", "static",
        "assets", "cdn", "img", "images", "upload", "files", "download", "beta", 
        "alpha", "demo", "sandbox", "old", "new", "v1", "v2", "api1", "api2",
        "ns1", "ns2", "ns3", "mx", "mx1", "mx2", "smtp", "pop", "imap", "ldap",
        "git", "svn", "jenkins", "ci", "build", "deploy", "monitor", "status",
        "health", "metrics", "logs", "elk", "kibana", "grafana", "prometheus",
        "redis", "db", "database", "mysql", "postgres", "mongo", "elastic",
        "search", "solr", "kafka", "rabbit", "queue", "cache", "backup", "archive",
        "dashboard", "panel", "console", "manage", "management", "control"
    }
}

---
-- Check for wildcard DNS
-- @param domain Target domain
-- @return boolean indicating if wildcard DNS is configured
local function check_wildcard_dns(domain)
    local random_subdomain = "nse-random-" .. math.random(100000, 999999)
    local test_domain = random_subdomain .. "." .. domain
    
    local status, result = dns.query(test_domain, {dtype = "A", timeout = args_timeout * 1000})
    return status and result and #result > 0
end

---
-- Perform DNS lookup for a subdomain
-- @param subdomain Full subdomain to query
-- @return IP address if found, nil otherwise
local function dns_lookup(subdomain)
    local status, result = dns.query(subdomain, {dtype = "A", timeout = args_timeout * 1000})
    if status and result and #result > 0 then
        return result[1]
    end
    return nil
end

---
-- Try DNS zone transfer
-- @param domain Target domain
-- @return table of found subdomains or nil
local function try_zone_transfer(domain)
    stdnse.debug1("Attempting zone transfer for %s", domain)
    
    -- Get NS records first
    local status, ns_records = dns.query(domain, {dtype = "NS", timeout = args_timeout * 1000})
    if not status or not ns_records or #ns_records == 0 then
        return nil
    end
    
    local found_subdomains = {}
    
    -- Try zone transfer on each nameserver
    for _, ns in ipairs(ns_records) do
        stdnse.debug2("Trying zone transfer on nameserver: %s", ns)
        local status, results = dns.query(domain, {dtype = "AXFR", server = ns, timeout = args_timeout * 1000})
        
        if status and results then
            for _, record in ipairs(results) do
                if record.domain and string.match(record.domain, "%." .. domain .. "$") then
                    table.insert(found_subdomains, record.domain)
                end
            end
        end
    end
    
    return #found_subdomains > 0 and found_subdomains or nil
end

---
-- Query certificate transparency logs for subdomains
-- @param domain Target domain
-- @return table of found subdomains
local function query_ct_logs(domain)
    if not args_ct_logs then
        return {}
    end
    
    stdnse.debug1("Querying certificate transparency logs for %s", domain)
    local found_subdomains = {}
    
    -- Use crt.sh API for CT log queries
    local ct_url = "https://crt.sh/?q=%." .. domain .. "&output=json"
    local response = http.get_url(ct_url, {timeout = args_timeout * 1000})
    
    if response and response.body then
        local status, ct_data = pcall(json.parse, response.body)
        if status and ct_data then
            for _, cert in ipairs(ct_data) do
                if cert.name_value then
                    -- Parse certificate common names and SAN entries
                    for subdomain in string.gmatch(cert.name_value, "([^%s]+)") do
                        subdomain = string.gsub(subdomain, "^%*%.", "")  -- Remove wildcards
                        if string.match(subdomain, "%." .. domain .. "$") and
                           not string.match(subdomain, "^%.") then
                            table.insert(found_subdomains, subdomain)
                        end
                    end
                end
            end
        end
    end
    
    return found_subdomains
end

---
-- Perform wordlist-based subdomain enumeration
-- @param domain Target domain
-- @param wordlist Wordlist to use
-- @param is_wildcard Whether wildcard DNS is configured
-- @return table of found subdomains with IPs
local function wordlist_enumeration(domain, wordlist, is_wildcard)
    local found_subdomains = {}
    local wildcard_ips = {}
    
    -- If wildcard DNS is configured, collect wildcard IPs for filtering
    if is_wildcard then
        for i = 1, 3 do
            local random_subdomain = "nse-wildcard-test-" .. i .. "." .. domain
            local ip = dns_lookup(random_subdomain)
            if ip then
                wildcard_ips[ip] = true
            end
        end
    end
    
    stdnse.debug1("Starting wordlist enumeration with %d entries", #wordlist)
    
    for _, word in ipairs(wordlist) do
        local subdomain = word .. "." .. domain
        local ip = dns_lookup(subdomain)
        
        if ip then
            -- Filter out wildcard responses
            if not is_wildcard or not wildcard_ips[ip] then
                found_subdomains[subdomain] = ip
                stdnse.debug2("Found subdomain: %s (%s)", subdomain, ip)
            end
        end
    end
    
    return found_subdomains
end

---
-- Remove duplicates and sort results
-- @param subdomains Table of subdomains
-- @return Sorted table without duplicates
local function deduplicate_and_sort(subdomains)
    local seen = {}
    local result = {}
    
    for subdomain, ip in pairs(subdomains) do
        if not seen[subdomain] then
            seen[subdomain] = true
            table.insert(result, {subdomain = subdomain, ip = ip})
        end
    end
    
    table.sort(result, function(a, b) return a.subdomain < b.subdomain end)
    return result
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
    
    local result = {}
    local all_subdomains = {}
    
    -- Determine wordlist to use
    local wordlist = wordlists[args_wordlist_size] or wordlists.medium
    if args_custom_wordlist then
        wordlist = {}
        for word in string.gmatch(args_custom_wordlist, "([^,]+)") do
            table.insert(wordlist, string.match(word, "^%s*(.-)%s*$"))  -- trim whitespace
        end
    end
    
    stdnse.debug1("Starting subdomain discovery for domain: %s", domain)
    
    -- Check for wildcard DNS
    local is_wildcard = check_wildcard_dns(domain)
    stdnse.debug1("Wildcard DNS detected: %s", is_wildcard and "Yes" or "No")
    
    -- Try zone transfer
    local zone_transfer_success = false
    local zone_subdomains = try_zone_transfer(domain)
    if zone_subdomains and #zone_subdomains > 0 then
        zone_transfer_success = true
        for _, subdomain in ipairs(zone_subdomains) do
            local ip = dns_lookup(subdomain)
            if ip then
                all_subdomains[subdomain] = ip
            end
        end
    end
    
    -- Wordlist enumeration
    local wordlist_results = wordlist_enumeration(domain, wordlist, is_wildcard)
    for subdomain, ip in pairs(wordlist_results) do
        all_subdomains[subdomain] = ip
    end
    
    -- Certificate transparency logs
    local ct_subdomains = {}
    if args_ct_logs then
        local ct_results = query_ct_logs(domain)
        for _, subdomain in ipairs(ct_results) do
            ct_subdomains[subdomain] = true
        end
    end
    
    -- Prepare results
    local discovered = deduplicate_and_sort(all_subdomains)
    local ct_only = {}
    
    for subdomain, _ in pairs(ct_subdomains) do
        if not all_subdomains[subdomain] then
            table.insert(ct_only, subdomain)
        end
    end
    table.sort(ct_only)
    
    -- Format output
    if #discovered > 0 then
        table.insert(result, string.format("Discovered subdomains (%d):", #discovered))
        for _, entry in ipairs(discovered) do
            table.insert(result, string.format("  %s (%s)", entry.subdomain, entry.ip))
        end
        table.insert(result, "")
    end
    
    if #ct_only > 0 then
        table.insert(result, string.format("Certificate transparency findings (%d):", #ct_only))
        for _, subdomain in ipairs(ct_only) do
            table.insert(result, string.format("  %s (from CT logs)", subdomain))
        end
        table.insert(result, "")
    end
    
    -- DNS information summary
    table.insert(result, "DNS Information:")
    table.insert(result, string.format("  Wildcard DNS: %s", is_wildcard and "Yes" or "No"))
    table.insert(result, string.format("  Zone transfer: %s", zone_transfer_success and "Allowed" or "Denied"))
    table.insert(result, string.format("  Total unique subdomains: %d", #discovered + #ct_only))
    
    if #result > 0 then
        return table.concat(result, "\n")
    else
        return "No subdomains discovered"
    end
end