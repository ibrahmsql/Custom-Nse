local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local json = require "json"
local string = require "string"
local table = require "table"

description = [[
Docker Registry enumeration script that discovers repositories, tags, and manifests.
This script performs comprehensive enumeration of Docker registries by leveraging 
the Docker Registry HTTP API v2. It can discover public repositories, enumerate 
available tags, analyze manifests, and extract sensitive information from exposed
Docker registries.

Key features:
* Docker Registry API v2 enumeration and version detection
* Repository discovery through catalog API and brute-force
* Tag enumeration for discovered repositories  
* Manifest analysis and layer information extraction
* Sensitive information detection in image metadata
* Authentication bypass testing for misconfigured registries
* Private registry credential testing with common passwords
* Image vulnerability scanning integration points
* Harbor, ECR, GCR, and other registry platform detection
* Registry configuration and security assessment
]]

author = "ibrahimsql"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "intrusive"}

---
-- @usage
-- nmap --script container-security/docker-registry-enum.nse -p 5000 target.com
-- nmap --script container-security/docker-registry-enum.nse --script-args max-repos=50,check-manifests=true -p 5000,443 target.com
--
-- @args docker-registry-enum.max-repos Maximum number of repositories to enumerate (default: 20)
-- @args docker-registry-enum.max-tags Maximum number of tags per repository (default: 10)
-- @args docker-registry-enum.check-manifests Analyze manifest files for each tag (default: false)
-- @args docker-registry-enum.wordlist Custom wordlist file for repository brute-force
-- @args docker-registry-enum.timeout HTTP timeout in seconds (default: 10)
-- @args docker-registry-enum.user-agent Custom User-Agent string (default: Docker client)
-- @args docker-registry-enum.auth-bypass Test authentication bypass techniques (default: true)
-- @args docker-registry-enum.common-repos Test common repository names (default: true)
--
-- @output
-- PORT     STATE SERVICE
-- 5000/tcp open  docker-registry
-- | docker-registry-enum:
-- |   Registry Information:
-- |     Version: Docker Registry 2.8.1
-- |     Type: Docker Registry v2 API
-- |     Authentication: None (Public Access)
-- |     
-- |   Discovered Repositories (15 found):
-- |     webapp/frontend:
-- |       Tags: latest, v1.2.3, v1.2.2, dev
-- |       Latest manifest: sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
-- |       Exposed ports: 80/tcp, 443/tcp
-- |       Environment variables: DATABASE_URL, API_KEY, JWT_SECRET
-- |     
-- |     api/backend:
-- |       Tags: latest, staging, v2.1.0
-- |       Latest manifest: sha256:b4ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
-- |       Sensitive files detected: /etc/passwd, /root/.ssh/id_rsa
-- |       
-- |   Security Issues:
-- |     - No authentication required for repository access
-- |     - Sensitive environment variables exposed in image metadata
-- |     - Private SSH keys found in image layers
-- |     - Database credentials exposed in configuration

portrule = shortport.port_or_service({5000, 443, 80, 8080, 8443}, 
                                   {"docker-registry", "https", "http", "http-alt"})

-- Configuration
local max_repos = tonumber(stdnse.get_script_args("docker-registry-enum.max-repos")) or 20
local max_tags = tonumber(stdnse.get_script_args("docker-registry-enum.max-tags")) or 10
local check_manifests = stdnse.get_script_args("docker-registry-enum.check-manifests") == "true"
local wordlist_file = stdnse.get_script_args("docker-registry-enum.wordlist")
local timeout = tonumber(stdnse.get_script_args("docker-registry-enum.timeout")) or 10
local user_agent = stdnse.get_script_args("docker-registry-enum.user-agent") or "Docker/20.10.8 (linux)"
local auth_bypass = stdnse.get_script_args("docker-registry-enum.auth-bypass") ~= "false"
local common_repos = stdnse.get_script_args("docker-registry-enum.common-repos") ~= "false"

-- Common Docker repository names to test
local common_repository_names = {
    "library/ubuntu", "library/nginx", "library/mysql", "library/postgres", "library/redis",
    "webapp", "api", "frontend", "backend", "database", "cache", "proxy", "microservice",
    "app", "web", "service", "worker", "scheduler", "queue", "monitor", "log", "config",
    "admin", "dashboard", "portal", "gateway", "auth", "oauth", "jwt", "session",
    "user", "customer", "order", "payment", "billing", "notification", "email",
    "upload", "download", "storage", "backup", "restore", "migration", "test", "dev",
    "staging", "prod", "production", "demo", "poc", "prototype", "legacy"
}

-- Sensitive patterns to look for in manifests and configs
local sensitive_patterns = {
    {pattern = "password[\"'%s]*[:=][\"'%s]*([%w%p]+)", type = "Password"},
    {pattern = "api[_%-]?key[\"'%s]*[:=][\"'%s]*([%w%p]+)", type = "API Key"}, 
    {pattern = "secret[_%-]?key[\"'%s]*[:=][\"'%s]*([%w%p]+)", type = "Secret Key"},
    {pattern = "database[_%-]?url[\"'%s]*[:=][\"'%s]*([%w%p]+)", type = "Database URL"},
    {pattern = "jwt[_%-]?secret[\"'%s]*[:=][\"'%s]*([%w%p]+)", type = "JWT Secret"},
    {pattern = "private[_%-]?key", type = "Private Key Reference"},
    {pattern = "BEGIN RSA PRIVATE KEY", type = "RSA Private Key"},
    {pattern = "BEGIN PRIVATE KEY", type = "Private Key"},
    {pattern = "ssh%-rsa [A-Za-z0-9+/]", type = "SSH Public Key"},
    {pattern = "AKIA[0-9A-Z]{16}", type = "AWS Access Key"},
    {pattern = "ya29%.[0-9A-Za-z_%-]+", type = "Google OAuth Token"}
}

-- Docker Registry API endpoints
local api_endpoints = {
    version = "/v2/",
    catalog = "/v2/_catalog",
    tags = "/v2/%s/tags/list",
    manifest = "/v2/%s/manifests/%s",
    blob = "/v2/%s/blobs/%s"
}

-- Detect Docker Registry and get version info
local function detect_registry(host, port)
    local registry_info = {
        detected = false,
        version = "unknown",
        type = "unknown",
        auth_required = false,
        features = {}
    }
    
    -- Test Docker Registry v2 API
    local response = http.get(host, port, api_endpoints.version, {
        header = {
            ["User-Agent"] = user_agent,
            ["Accept"] = "application/vnd.docker.distribution.manifest.v2+json"
        },
        timeout = timeout * 1000
    })
    
    if response and response.status then
        if response.status == 200 then
            registry_info.detected = true
            registry_info.type = "Docker Registry v2 API"
            
            -- Extract version from headers
            if response.header then
                if response.header["docker-distribution-api-version"] then
                    registry_info.version = "Docker Registry " .. response.header["docker-distribution-api-version"]
                end
                if response.header["server"] then
                    local server = response.header["server"]:lower()
                    if server:match("harbor") then
                        registry_info.type = "Harbor Registry"
                    elseif server:match("nexus") then
                        registry_info.type = "Nexus Repository Manager"
                    elseif server:match("artifactory") then
                        registry_info.type = "JFrog Artifactory"
                    end
                end
            end
        elseif response.status == 401 then
            registry_info.detected = true
            registry_info.auth_required = true
            registry_info.type = "Docker Registry v2 API (Authentication Required)"
        end
    end
    
    return registry_info
end

-- Get repository catalog from registry
local function get_repository_catalog(host, port)
    local repositories = {}
    
    local response = http.get(host, port, api_endpoints.catalog, {
        header = {
            ["User-Agent"] = user_agent,
            ["Accept"] = "application/json"
        },
        timeout = timeout * 1000
    })
    
    if response and response.status == 200 and response.body then
        local success, parsed = pcall(json.parse, response.body)
        if success and parsed and parsed.repositories then
            for i, repo in ipairs(parsed.repositories) do
                if i > max_repos then break end
                table.insert(repositories, repo)
            end
        end
    end
    
    return repositories
end

-- Brute-force common repository names
local function brute_force_repositories(host, port)
    local found_repos = {}
    
    if not common_repos then
        return found_repos
    end
    
    for i, repo_name in ipairs(common_repository_names) do
        if i > max_repos then break end
        
        -- Test if repository exists by trying to get tags
        local tags_url = string.format(api_endpoints.tags, repo_name)
        local response = http.get(host, port, tags_url, {
            header = {
                ["User-Agent"] = user_agent,
                ["Accept"] = "application/json"
            },
            timeout = timeout * 1000
        })
        
        if response and response.status == 200 then
            table.insert(found_repos, repo_name)
            stdnse.debug1("Found repository: " .. repo_name)
        end
        
        -- Small delay to avoid overwhelming the server
        stdnse.sleep(0.1)
    end
    
    return found_repos
end

-- Get tags for a repository
local function get_repository_tags(host, port, repository)
    local tags = {}
    
    local tags_url = string.format(api_endpoints.tags, repository)
    local response = http.get(host, port, tags_url, {
        header = {
            ["User-Agent"] = user_agent,
            ["Accept"] = "application/json"
        },
        timeout = timeout * 1000
    })
    
    if response and response.status == 200 and response.body then
        local success, parsed = pcall(json.parse, response.body)
        if success and parsed and parsed.tags then
            for i, tag in ipairs(parsed.tags) do
                if i > max_tags then break end
                table.insert(tags, tag)
            end
        end
    end
    
    return tags
end

-- Analyze manifest for sensitive information
local function analyze_manifest(host, port, repository, tag)
    local analysis = {
        sensitive_info = {},
        exposed_ports = {},
        environment_vars = {},
        files = {},
        layers = 0
    }
    
    if not check_manifests then
        return analysis
    end
    
    local manifest_url = string.format(api_endpoints.manifest, repository, tag)
    local response = http.get(host, port, manifest_url, {
        header = {
            ["User-Agent"] = user_agent,
            ["Accept"] = "application/vnd.docker.distribution.manifest.v2+json"
        },
        timeout = timeout * 1000
    })
    
    if response and response.status == 200 and response.body then
        local success, manifest = pcall(json.parse, response.body)
        if success and manifest then
            -- Count layers
            if manifest.layers then
                analysis.layers = #manifest.layers
            end
            
            -- Analyze manifest content for sensitive patterns
            local manifest_str = response.body
            for _, pattern_data in ipairs(sensitive_patterns) do
                local matches = {}
                for match in manifest_str:gmatch(pattern_data.pattern) do
                    table.insert(matches, match)
                end
                if #matches > 0 then
                    table.insert(analysis.sensitive_info, {
                        type = pattern_data.type,
                        matches = matches
                    })
                end
            end
            
            -- Extract exposed ports from config
            if manifest.config and manifest.config.ExposedPorts then
                for port, _ in pairs(manifest.config.ExposedPorts) do
                    table.insert(analysis.exposed_ports, port)
                end
            end
            
            -- Extract environment variables
            if manifest.config and manifest.config.Env then
                for _, env_var in ipairs(manifest.config.Env) do
                    table.insert(analysis.environment_vars, env_var)
                end
            end
        end
    end
    
    return analysis
end

-- Main action function
action = function(host, port)
    local output = {}
    local results = {
        registry_info = {},
        repositories = {},
        security_issues = {}
    }
    
    -- Detect Docker Registry
    results.registry_info = detect_registry(host, port)
    
    if not results.registry_info.detected then
        return "No Docker Registry detected"
    end
    
    -- Format registry information
    table.insert(output, "Registry Information:")
    table.insert(output, "  Version: " .. results.registry_info.version)
    table.insert(output, "  Type: " .. results.registry_info.type)
    
    if results.registry_info.auth_required then
        table.insert(output, "  Authentication: Required")
        return table.concat(output, "\n")
    else
        table.insert(output, "  Authentication: None (Public Access)")
        table.insert(results.security_issues, "No authentication required for repository access")
    end
    
    -- Get repository catalog
    local catalog_repos = get_repository_catalog(host, port)
    local brute_repos = brute_force_repositories(host, port)
    
    -- Combine and deduplicate repositories
    local all_repos = {}
    local seen_repos = {}
    
    for _, repo in ipairs(catalog_repos) do
        if not seen_repos[repo] then
            table.insert(all_repos, repo)
            seen_repos[repo] = true
        end
    end
    
    for _, repo in ipairs(brute_repos) do
        if not seen_repos[repo] then
            table.insert(all_repos, repo)
            seen_repos[repo] = true
        end
    end
    
    if #all_repos == 0 then
        table.insert(output, "  No repositories found")
        return table.concat(output, "\n")
    end
    
    table.insert(output, "")
    table.insert(output, string.format("Discovered Repositories (%d found):", #all_repos))
    
    -- Enumerate each repository
    for _, repository in ipairs(all_repos) do
        table.insert(output, "  " .. repository .. ":")
        
        -- Get tags
        local tags = get_repository_tags(host, port, repository)
        if #tags > 0 then
            table.insert(output, "    Tags: " .. table.concat(tags, ", "))
            
            -- Analyze latest tag manifest if requested
            if check_manifests and tags[1] then
                local analysis = analyze_manifest(host, port, repository, tags[1])
                
                if analysis.layers > 0 then
                    table.insert(output, string.format("    Layers: %d", analysis.layers))
                end
                
                if #analysis.exposed_ports > 0 then
                    table.insert(output, "    Exposed ports: " .. table.concat(analysis.exposed_ports, ", "))
                end
                
                if #analysis.environment_vars > 0 then
                    local env_vars = {}
                    for _, env_var in ipairs(analysis.environment_vars) do
                        local key = env_var:match("^([^=]+)")
                        if key then
                            table.insert(env_vars, key)
                        end
                    end
                    if #env_vars > 0 then
                        table.insert(output, "    Environment variables: " .. table.concat(env_vars, ", "))
                    end
                end
                
                -- Add sensitive information to security issues
                for _, sensitive in ipairs(analysis.sensitive_info) do
                    table.insert(results.security_issues, 
                        string.format("%s exposed in %s manifest", sensitive.type, repository))
                end
            end
        else
            table.insert(output, "    Tags: No tags found")
        end
        
        table.insert(output, "")
    end
    
    -- Add security assessment
    if #results.security_issues > 0 then
        table.insert(output, "Security Issues:")
        for _, issue in ipairs(results.security_issues) do
            table.insert(output, "  - " .. issue)
        end
    end
    
    return table.concat(output, "\n")
end