# Git Enumeration NSE Scripts

This directory contains NSE scripts for discovering and analyzing exposed Git repositories and version control systems.

## Scripts

### 🔍 git-dumper.nse
Advanced Git repository discovery and analysis script that detects exposed .git directories and extracts sensitive information.

**Features:**
- Detects misconfigured .git directory exposure
- Enumerates Git files (HEAD, config, refs, etc.)
- Discovers branches, tags, and remote repositories
- Extracts sensitive information from Git files
- Analyzes configuration files for credentials
- Detects directory listing vulnerabilities
- Provides security impact assessment

**Usage:**
```bash
# Basic Git repository detection
nmap --script git-dumper.nse -p 80,443 target.com

# Enable file content analysis (more thorough)
nmap --script git-dumper.nse --script-args download-files=true -p 80,443 target.com

# Custom timeout and file limits
nmap --script git-dumper.nse --script-args timeout=15,max-files=50 -p 80,443 target.com

# Custom User-Agent
nmap --script git-dumper.nse --script-args user-agent="Security Scanner" -p 80,443 target.com
```

**Script Arguments:**
- `timeout`: HTTP request timeout in seconds (default: 10)
- `user-agent`: Custom User-Agent string (default: "NSE Git Scanner")
- `download-files`: Download and analyze file contents (default: false)
- `max-files`: Maximum number of files to analyze (default: 100)
- `check-refs`: Check all discovered Git references (default: true)

**Detection Capabilities:**
- `.git/HEAD` file accessibility
- Directory listing on `.git/` folder
- Git configuration and metadata files
- Branch and tag enumeration
- Remote repository URLs
- Embedded credentials in Git configs
- Sensitive file patterns (passwords, API keys, etc.)
- Internal server information disclosure

**Security Issues Detected:**
- **CRITICAL**: Full repository downloadable via directory listing
- **HIGH**: Source code and commit history exposure
- **HIGH**: Database credentials in config files
- **HIGH**: API keys and tokens in environment files
- **MEDIUM**: Internal server paths disclosed
- **MEDIUM**: Remote repository URLs exposed
- **LOW**: Developer emails in commit history

## Categories
- **discovery**: Scripts that discover Git repositories
- **safe**: Scripts that perform read-only operations
- **vuln**: Scripts that identify vulnerabilities

## Requirements
- Nmap 7.0+
- HTTP/HTTPS connectivity
- Modern Lua support

## Common Vulnerable Scenarios

### 1. Development Files in Production
```
/.git/HEAD                    # Exposed Git metadata
/.git/config                  # Configuration with remote URLs
/.git/refs/heads/master       # Branch references
```

### 2. Directory Listing Enabled
```
/.git/                        # Directory listing shows all files
/.git/objects/                # Git objects accessible
/.git/logs/                   # Commit logs exposed
```

### 3. Sensitive Information Exposure
```
/.git/config                  # Contains remote repository URLs
/.git/logs/HEAD               # Contains commit messages
/.git/COMMIT_EDITMSG          # Last commit message
```

## Example Output

### Basic Detection
```
PORT   STATE SERVICE
80/tcp open  http
| git-dumper:
|   Git Repository Exposure Detected!
|   
|   Repository Information:
|     HEAD: main (active branch)
|     Directory Listing: Disabled
|     Files Discovered: 12 Git files found
|   
|   Impact Assessment:
|     HIGH: Source code and commit history exposed
|_    HIGH: Potential credential and secret disclosure
```

### Detailed Analysis (with download-files=true)
```
PORT   STATE SERVICE  
80/tcp open  http
| git-dumper:
|   Git Repository Exposure Detected!
|   
|   Repository Information:
|     HEAD: main (active branch)
|     Remote: origin -> https://github.com/company/private-repo.git
|     Directory Listing: ENABLED (HIGH RISK)
|     Files Discovered: 23 Git files found
|   
|   Discovered Branches (3):
|     main (current)
|     development
|     production
|   
|   Security Issues Found:
|     HIGH: Credentials embedded in Git remote URL
|     HIGH: Password found in .git/config
|     MEDIUM: Remote repository URL disclosed
|     MEDIUM: Potentially sensitive file: .git/config
|   
|   Impact Assessment:
|     CRITICAL: Full repository can be downloaded recursively
|     HIGH: Source code and commit history exposed
|_    HIGH: Potential credential and secret disclosure
```

## Notes
- All scripts are safe and perform only read-only operations
- No aggressive techniques or vulnerability exploitation
- Suitable for compliance and security auditing
- Respects timeout limits and HTTP best practices
- Designed to minimize false positives

## Remediation

### Web Server Configuration

**Apache (.htaccess)**
```apache
# Deny access to .git directory
<DirectoryMatch "\.git">
    Require all denied
</DirectoryMatch>
```

**Nginx**
```nginx
# Deny access to .git directory
location ~ /\.git {
    deny all;
    return 404;
}
```

**IIS (web.config)**
```xml
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <hiddenSegments>
          <add segment=".git" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

### Best Practices
1. **Remove .git directories** from production web roots
2. **Use proper deployment processes** that exclude version control files
3. **Implement directory access controls** at web server level
4. **Regular security scanning** to detect exposed repositories
5. **Audit commit history** for accidentally committed sensitive data
6. **Use environment variables** instead of hardcoded credentials
7. **Implement proper .gitignore** to exclude sensitive files
