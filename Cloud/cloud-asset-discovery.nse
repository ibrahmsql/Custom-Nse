local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"
local string = require "string"
local table = require "table"
local nmap = require "nmap"

description = [[
Cloud Asset Discovery NSE Script

This script detects misconfigured public cloud storage buckets during Nmap scans.
It identifies and tests:
- Amazon S3 buckets (*.s3.amazonaws.com)
- Azure Blob Storage (*.blob.core.windows.net) 
- Google Cloud Storage (*.storage.googleapis.com)

For each detected cloud storage service, it performs unauthenticated HTTP requests
to check for public accessibility, directory listing capabilities, and reports
the security posture of discovered assets.

Usage: nmap --script cloud-asset-discovery <target>

Developed by: ibrahimsql
]]

author = "ibrahimsql 
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "vuln", "safe"}

-- Script arguments
portrule = function(host, port)
    return (port.number == 80 or port.number == 443 or port.number == 8080) 
           and port.state == "open"
end

-- Script arguments for user configuration
local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or "10"
local arg_maxhosts = stdnse.get_script_args(SCRIPT_NAME .. ".maxhosts") or "50"

-- Cloud storage patterns and endpoints
local cloud_patterns = {
    s3 = {
        pattern = "([%w%-%.]+)%.s3%.amazonaws%.com",
        pattern_alt = "([%w%-%.]+)%.s3%-([%w%-]+)%.amazonaws%.com",
        name = "Amazon S3",
        test_paths = {"/", "/?list-type=2"},
        success_indicators = {
            "ListBucketResult",
            "<Contents>",
            "<?xml",
            "AccessDenied"
        },
        public_indicators = {
            "ListBucketResult",
            "<Contents>",
            "<Key>"
        }
    },
    azure = {
        pattern = "([%w%-%.]+)%.blob%.core%.windows%.net",
        name = "Azure Blob Storage",
        test_paths = {"/", "/?restype=container&comp=list"},
        success_indicators = {
            "BlobEnumeration",
            "<?xml",
            "AuthenticationFailed",
            "ResourceNotFound"
        },
        public_indicators = {
            "BlobEnumeration",
            "<Blob>",
            "<Name>"
        }
    },
    gcs = {
        pattern = "([%w%-%.]+)%.storage%.googleapis%.com",
        name = "Google Cloud Storage",
        test_paths = {"/", "/storage/v1/b/"},
        success_indicators = {
            '"kind":"storage#objects"',
            '"items"',
            "AccessDenied",
            "Forbidden"
        },
        public_indicators = {
            '"kind":"storage#objects"',
            '"items"',
            '"name"'
        }
    }
}

-- Function to make HTTP requests with timeout
local function make_http_request(host, port, path, timeout)
    local response
    local status = false
    
    -- Use http library for the request
    local options = {
        timeout = tonumber(timeout) * 1000,
        header = {
            ["User-Agent"] = "Mozilla/5.0 (compatible; Nmap NSE; ibrahimsql Cloud Asset Discovery)"
        }
    }
    
    if port.number == 443 then
        response = http.get(host, port, path, options)
    else
        response = http.get(host, port, path, options)
    end
    
    if response and response.status then
        status = true
    end
    
    return status, response
end

-- Function to analyze cloud storage response
local function analyze_response(response, cloud_type, bucket_name)
    local result = {
        bucket_name = bucket_name,
        cloud_provider = cloud_patterns[cloud_type].name,
        status_code = response.status or "Unknown",
        accessible = false,
        public_read = false,
        directory_listing = false,
        response_size = 0,
        security_issue = "None"
    }
    
    if response.body then
        result.response_size = string.len(response.body)
        local body_lower = string.lower(response.body)
        
        -- Check if bucket/container is accessible
        for _, indicator in ipairs(cloud_patterns[cloud_type].success_indicators) do
            if string.find(body_lower, string.lower(indicator)) then
                result.accessible = true
                break
            end
        end
        
        -- Check for public read access and directory listing
        for _, indicator in ipairs(cloud_patterns[cloud_type].public_indicators) do
            if string.find(body_lower, string.lower(indicator)) then
                result.public_read = true
                result.directory_listing = true
                result.security_issue = "Public Access Detected"
                break
            end
        end
        
        -- Additional status code analysis
        if response.status then
            if response.status == 200 then
                result.accessible = true
                if result.public_read then
                    result.security_issue = "Publicly Readable"
                end
            elseif response.status == 403 then
                result.accessible = true
                result.security_issue = "Access Denied (Bucket Exists)"
            elseif response.status == 404 then
                result.security_issue = "Not Found"
            end
        end
    end
    
    return result
end

-- Function to detect cloud storage from hostname
local function detect_cloud_storage(hostname)
    for cloud_type, config in pairs(cloud_patterns) do
        -- Check primary pattern
        local bucket = string.match(hostname, config.pattern)
        if bucket then
            return cloud_type, bucket
        end
        
        -- Check alternative pattern (for S3 regional endpoints)
        if config.pattern_alt then
            local bucket_alt, region = string.match(hostname, config.pattern_alt)
            if bucket_alt then
                return cloud_type, bucket_alt
            end
        end
    end
    return nil, nil
end

-- Main action function
action = function(host, port)
    local results = {}
    -- Use target name instead of rDNS if available
    local hostname = host.targetname or host.name or host.ip
    
    -- Skip if no hostname available
    if not hostname or hostname == host.ip then
        return nil
    end
    
    -- Check if hostname matches cloud storage patterns
    local cloud_type, bucket_name = detect_cloud_storage(hostname)
    if not cloud_type or not bucket_name then
        return nil
    end
    
    local output = {}
    table.insert(output, string.format("Detected %s bucket: %s", 
                 cloud_patterns[cloud_type].name, bucket_name))
    
    -- Test each path for the detected cloud storage type
    for _, test_path in ipairs(cloud_patterns[cloud_type].test_paths) do
        local success, response = make_http_request(host, port, test_path, arg_timeout)
        
        if success and response then
            local analysis = analyze_response(response, cloud_type, bucket_name)
            
            table.insert(output, string.format("  Test Path: %s", test_path))
            table.insert(output, string.format("  Status Code: %s", analysis.status_code))
            table.insert(output, string.format("  Accessible: %s", 
                         analysis.accessible and "Yes" or "No"))
            table.insert(output, string.format("  Public Read: %s", 
                         analysis.public_read and "Yes" or "No"))
            table.insert(output, string.format("  Directory Listing: %s", 
                         analysis.directory_listing and "Yes" or "No"))
            table.insert(output, string.format("  Response Size: %d bytes", analysis.response_size))
            table.insert(output, string.format("  Security Issue: %s", analysis.security_issue))
            
            -- Add vulnerability warning for public buckets
            if analysis.public_read then
                table.insert(output, "  *** SECURITY ALERT: Publicly accessible cloud storage detected! ***")
            end
            
            table.insert(output, "")
            break -- Only test first successful path
        else
            table.insert(output, string.format("  Test Path: %s - Failed to connect", test_path))
        end
    end
    
    -- Only return results if we found cloud storage
    if #output > 1 then
        return stdnse.format_output(true, output)
    else
        return nil
    end
end

-- Host script version for broader scanning
hostrule = function(host)
    return true
end

-- Alternative action for host-based scanning
local function host_action(host)
    -- This would be used if running as a host script
    -- For now, we focus on the port-based approach
    return nil
end

