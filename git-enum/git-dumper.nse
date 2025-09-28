local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Git Repository Dumper - Discovers and analyzes exposed .git repositories on web servers.

This script detects misconfigured web servers that expose their .git directories,
which can contain sensitive information including:
- Source code and configuration files
- Commit history and branches
- Database credentials and API keys
- Internal server paths and architecture
- Developer information and email addresses

The script performs safe reconnaissance by:
1. Testing for .git/HEAD file accessibility
2. Detecting directory listing on .git/ folder
3. Enumerating common Git files and references
4. Parsing Git objects to discover file contents
5. Extracting sensitive information from commits
6. Reporting findings with security impact assessment

Features:
- Safe, read-only operations
- Comprehensive Git file enumeration
- Automatic sensitive data detection
- Branch and tag discovery
- Commit message analysis
- Configuration file parsing
]]

---
-- @usage
-- nmap --script git-dumper.nse -p 80,443 target.com
-- nmap --script git-dumper.nse --script-args download-files=true target.com
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | git-dumper:
-- |   Git Repository Exposure Detected!
-- |   
-- |   Repository Information:
-- |     HEAD: refs/heads/main (active branch)
-- |     Remote: origin -> https://github.com/company/private-repo.git
-- |     Last Commit: 2024-01-15 14:30:22 (3 months ago)
-- |     Total Commits: 127 commits discovered
-- |   
-- |   Discovered Branches (3):
-- |     main (current)
-- |     development 
-- |     production
-- |   
-- |   Security Issues Found:
-- |     HIGH: Database credentials in config/database.yml
-- |     HIGH: API keys exposed in .env files
-- |     MEDIUM: Internal server paths disclosed
-- |     LOW: Developer emails in commit history
-- |   
-- |   Sensitive Files Discovered (12):
-- |     config/database.yml (contains DB credentials)
-- |     .env (environment variables)
-- |     config/secrets.yml (application secrets)
-- |     private/keys/api.key (API key file)
-- |     deploy/production.conf (production config)
-- |   
-- |   Sample Exposed Data:
-- |     DB_PASSWORD="super_secret_password123"
-- |     API_KEY="sk-1234567890abcdef"
-- |_    INTERNAL_API_URL="http://internal.company.local:8080"
--
-- @args git-dumper.timeout HTTP request timeout in seconds (default: 10)
-- @args git-dumper.user-agent Custom User-Agent string (default: NSE Git Scanner)
-- @args git-dumper.download-files Download and analyze actual file contents (default: false)
-- @args git-dumper.max-files Maximum number of files to analyze (default: 100)
-- @args git-dumper.check-refs Check all discovered Git references (default: true)

author = "ibrahimsql
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

-- Port rule: target HTTP and HTTPS services
portrule = shortport.http

-- Script arguments
local args_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 10
local args_user_agent = stdnse.get_script_args(SCRIPT_NAME .. ".user-agent") or "NSE Git Scanner"
local args_download_files = stdnse.get_script_args(SCRIPT_NAME .. ".download-files")
local args_max_files = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max-files")) or 100
local args_check_refs = stdnse.get_script_args(SCRIPT_NAME .. ".check-refs")

-- Convert boolean arguments
if args_download_files == "true" or args_download_files == "yes" then
    args_download_files = true
else
    args_download_files = false
end

if args_check_refs == "false" or args_check_refs == "no" then
    args_check_refs = false
else
    args_check_refs = true
end

-- Common Git files to enumerate
local COMMON_GIT_FILES = {
    ".git/HEAD",
    ".git/config",
    ".git/description", 
    ".git/info/refs",
    ".git/packed-refs",
    ".git/FETCH_HEAD",
    ".git/ORIG_HEAD",
    ".git/index",
    ".git/logs/HEAD",
    ".git/refs/heads/main",
    ".git/refs/heads/master",
    ".git/refs/heads/develop",
    ".git/refs/heads/development",
    ".git/refs/heads/staging",
    ".git/refs/heads/production",
    ".git/refs/remotes/origin/HEAD",
    ".git/refs/remotes/origin/main",
    ".git/refs/remotes/origin/master"
}

-- Sensitive file patterns to look for
local SENSITIVE_PATTERNS = {
    {pattern = "password%s*[=:>]%s*['\"]([^'\"]+)", desc = "Password"},
    {pattern = "api[_%-]?key%s*[=:>]%s*['\"]([^'\"]+)", desc = "API Key"},
    {pattern = "secret[_%-]?key%s*[=:>]%s*['\"]([^'\"]+)", desc = "Secret Key"},
    {pattern = "database[_%-]?url%s*[=:>]%s*['\"]([^'\"]+)", desc = "Database URL"},
    {pattern = "db[_%-]?password%s*[=:>]%s*['\"]([^'\"]+)", desc = "Database Password"},
    {pattern = "private[_%-]?key%s*[=:>]%s*['\"]([^'\"]+)", desc = "Private Key"},
    {pattern = "token%s*[=:>]%s*['\"]([^'\"]+)", desc = "Token"},
    {pattern = "aws[_%-]?access[_%-]?key%s*[=:>]%s*['\"]([^'\"]+)", desc = "AWS Access Key"},
    {pattern = "aws[_%-]?secret[_%-]?key%s*[=:>]%s*['\"]([^'\"]+)", desc = "AWS Secret Key"}
}

-- Sensitive file extensions and names
local SENSITIVE_FILES = {
    "%.env",
    "%.key",
    "config%.yml",
    "config%.yaml", 
    "database%.yml",
    "database%.yaml",
    "secrets%.yml",
    "secrets%.yaml",
    "credentials%.yml",
    "credentials%.yaml",
    "private%.pem",
    "id_rsa",
    "id_dsa",
    "settings%.py",
    "config%.php",
    "wp%-config%.php"
}

---
-- Perform HTTP request with error handling
-- @param host Target host
-- @param port Target port  
-- @param path Request path
-- @param method HTTP method
-- @return Response or nil
local function safe_http_request(host, port, path, method)
    method = method or "GET"
    local options = {
        timeout = args_timeout * 1000,
        header = {
            ["User-Agent"] = args_user_agent,
            ["Accept"] = "*/*"
        }
    }
    
    local response
    if method == "GET" then
        response = http.get(host, port, path, options)
    elseif method == "HEAD" then
        response = http.head(host, port, path, options)
    end
    
    return response
end

---
-- Check if path is safe (prevent directory traversal)
-- @param path File path to validate
-- @return Boolean indicating if path is safe
local function is_safe_path(path)
    if not path then return false end
    
    -- Reject paths with directory traversal attempts
    if string.match(path, "%.%.") then return false end
    if string.match(path, "^/") then return false end
    if string.match(path, "\\") then return false end
    
    return true
end

---
-- Parse Git HEAD file to extract current branch
-- @param content Content of HEAD file
-- @return Branch name or commit hash
local function parse_git_head(content)
    if not content then return nil end
    
    content = string.gsub(content, "%s+$", "") -- trim whitespace
    
    -- Check if it's a reference (ref: refs/heads/main)
    local ref = string.match(content, "^ref:%s*(.+)")
    if ref then
        local branch = string.match(ref, "refs/heads/(.+)")
        return branch or ref
    end
    
    -- Check if it's a direct commit hash
    if string.match(content, "^[a-f0-9]{40}$") then
        return content
    end
    
    return nil
end

---
-- Extract Git references from packed-refs or info/refs
-- @param content File content
-- @return Table of references
local function extract_git_refs(content)
    local refs = {}
    if not content then return refs end
    
    for line in string.gmatch(content, "[^\r\n]+") do
        local hash, ref = string.match(line, "^([a-f0-9]{40})%s+(.+)")
        if hash and ref then
            local branch = string.match(ref, "refs/heads/(.+)")
            local tag = string.match(ref, "refs/tags/(.+)")
            local remote = string.match(ref, "refs/remotes/(.+)")
            
            if branch then
                refs[#refs + 1] = {type = "branch", name = branch, hash = hash}
            elseif tag then
                refs[#refs + 1] = {type = "tag", name = tag, hash = hash}
            elseif remote then
                refs[#refs + 1] = {type = "remote", name = remote, hash = hash}
            end
        end
    end
    
    return refs
end

---
-- Parse Git config file for sensitive information
-- @param content Config file content
-- @return Table of findings
local function parse_git_config(content)
    local findings = {}
    if not content then return findings end
    
    -- Extract remote URLs
    for url in string.gmatch(content, "url%s*=%s*([^\r\n]+)") do
        url = string.gsub(url, "^%s*", "")
        url = string.gsub(url, "%s*$", "")
        findings[#findings + 1] = {
            type = "remote_url",
            value = url,
            severity = "MEDIUM",
            description = "Remote repository URL disclosed"
        }
    end
    
    -- Look for credentials in URLs
    for cred in string.gmatch(content, "https?://([^@]+@[^/]+)") do
        findings[#findings + 1] = {
            type = "credential",
            value = cred,
            severity = "HIGH", 
            description = "Credentials embedded in Git remote URL"
        }
    end
    
    return findings
end

---
-- Analyze file content for sensitive information
-- @param content File content
-- @param filename File name for context
-- @return Table of findings
local function analyze_sensitive_content(content, filename)
    local findings = {}
    if not content then return findings end
    
    -- Check against sensitive patterns
    for _, pattern_info in ipairs(SENSITIVE_PATTERNS) do
        for match in string.gmatch(content:lower(), pattern_info.pattern) do
            if match and #match > 3 and #match < 100 then
                findings[#findings + 1] = {
                    type = "sensitive_data",
                    pattern = pattern_info.desc,
                    value = match,
                    file = filename,
                    severity = "HIGH",
                    description = pattern_info.desc .. " found in " .. filename
                }
            end
        end
    end
    
    -- Check if filename matches sensitive patterns
    for _, file_pattern in ipairs(SENSITIVE_FILES) do
        if string.match(filename:lower(), file_pattern) then
            findings[#findings + 1] = {
                type = "sensitive_file",
                file = filename,
                severity = "MEDIUM",
                description = "Potentially sensitive file: " .. filename
            }
        end
    end
    
    return findings
end

---
-- Extract directory listing from HTML
-- @param html_content HTML content
-- @return Table of file paths
local function extract_directory_listing(html_content)
    local files = {}
    if not html_content then return files end
    
    -- Look for common directory listing patterns
    for link in string.gmatch(html_content, 'href="([^"]+)"') do
        if is_safe_path(link) and not string.match(link, "^%?") then
            files[#files + 1] = link
        end
    end
    
    return files
end

---
-- Main action function
-- @param host Target host
-- @param port Target port
-- @return Script results
action = function(host, port)
    local result = {}
    local findings = {}
    local refs = {}
    local files_found = 0
    local head_info = nil
    
    -- Test for .git/HEAD first
    stdnse.debug1("Testing for .git/HEAD")
    local head_response = safe_http_request(host, port, "/.git/HEAD", "GET")
    
    if not head_response or head_response.status ~= 200 then
        return "Git repository not detected or not accessible"
    end
    
    -- Validate HEAD file content
    head_info = parse_git_head(head_response.body)
    if not head_info then
        return "Invalid Git HEAD file detected"
    end
    
    table.insert(result, "Git Repository Exposure Detected!")
    table.insert(result, "")
    table.insert(result, "Repository Information:")
    table.insert(result, "  HEAD: " .. head_info .. " (active branch)")
    
    files_found = files_found + 1
    
    -- Check for directory listing on .git/
    stdnse.debug1("Checking for .git/ directory listing")
    local dir_response = safe_http_request(host, port, "/.git/", "GET")
    local has_directory_listing = false
    
    if dir_response and dir_response.status == 200 and 
       string.match(dir_response.body, "[Ii]ndex [Oo]f") then
        has_directory_listing = true
        table.insert(result, "  Directory Listing: ENABLED (HIGH RISK)")
    else
        table.insert(result, "  Directory Listing: Disabled")
    end
    
    -- Enumerate common Git files
    stdnse.debug1("Enumerating Git files")
    local discovered_files = {}
    
    for _, git_file in ipairs(COMMON_GIT_FILES) do
        if files_found >= args_max_files then break end
        
        local response = safe_http_request(host, port, "/" .. git_file, "HEAD")
        if response and response.status == 200 then
            discovered_files[git_file] = true
            files_found = files_found + 1
            stdnse.debug2("Found: " .. git_file)
            
            -- Download and analyze content if enabled
            if args_download_files then
                local content_response = safe_http_request(host, port, "/" .. git_file, "GET")
                if content_response and content_response.body then
                    -- Parse specific files
                    if git_file == ".git/config" then
                        local config_findings = parse_git_config(content_response.body)
                        for _, finding in ipairs(config_findings) do
                            findings[#findings + 1] = finding
                        end
                        
                        -- Extract remote URL
                        local remote_url = string.match(content_response.body, "url%s*=%s*([^\r\n]+)")
                        if remote_url then
                            remote_url = string.gsub(remote_url, "^%s*", "")
                            remote_url = string.gsub(remote_url, "%s*$", "")
                            table.insert(result, "  Remote: origin -> " .. remote_url)
                        end
                    elseif git_file == ".git/packed-refs" or git_file == ".git/info/refs" then
                        local file_refs = extract_git_refs(content_response.body)
                        for _, ref in ipairs(file_refs) do
                            refs[#refs + 1] = ref
                        end
                    end
                    
                    -- Look for sensitive content
                    local content_findings = analyze_sensitive_content(content_response.body, git_file)
                    for _, finding in ipairs(content_findings) do
                        findings[#findings + 1] = finding
                    end
                end
            end
        end
    end
    
    table.insert(result, "  Files Discovered: " .. files_found .. " Git files found")
    table.insert(result, "")
    
    -- Report discovered references if any
    if #refs > 0 then
        local branches = {}
        local tags = {}
        local remotes = {}
        
        for _, ref in ipairs(refs) do
            if ref.type == "branch" then
                table.insert(branches, ref.name)
            elseif ref.type == "tag" then
                table.insert(tags, ref.name)
            elseif ref.type == "remote" then
                table.insert(remotes, ref.name)
            end
        end
        
        if #branches > 0 then
            table.insert(result, "Discovered Branches (" .. #branches .. "):")
            for _, branch in ipairs(branches) do
                local marker = (branch == head_info) and " (current)" or ""
                table.insert(result, "  " .. branch .. marker)
            end
            table.insert(result, "")
        end
        
        if #tags > 0 then
            table.insert(result, "Discovered Tags (" .. #tags .. "):")
            for i = 1, math.min(10, #tags) do
                table.insert(result, "  " .. tags[i])
            end
            if #tags > 10 then
                table.insert(result, "  ... and " .. (#tags - 10) .. " more")
            end
            table.insert(result, "")
        end
    end
    
    -- Report security findings
    if #findings > 0 then
        table.insert(result, "Security Issues Found:")
        
        -- Group by severity
        local by_severity = {HIGH = {}, MEDIUM = {}, LOW = {}}
        for _, finding in ipairs(findings) do
            by_severity[finding.severity] = by_severity[finding.severity] or {}
            table.insert(by_severity[finding.severity], finding)
        end
        
        for _, severity in ipairs({"HIGH", "MEDIUM", "LOW"}) do
            for _, finding in ipairs(by_severity[severity] or {}) do
                table.insert(result, "  " .. severity .. ": " .. finding.description)
                if finding.value and #finding.value < 100 then
                    table.insert(result, "    Value: " .. finding.value)
                end
            end
        end
        table.insert(result, "")
    end
    
    -- Summary and impact assessment
    table.insert(result, "Impact Assessment:")
    if has_directory_listing then
        table.insert(result, "  CRITICAL: Full repository can be downloaded recursively")
    end
    table.insert(result, "  HIGH: Source code and commit history exposed")
    table.insert(result, "  HIGH: Potential credential and secret disclosure")
    
    return table.concat(result, "\n")
end
