# Authentication Testing NSE Scripts

This directory contains NSE scripts for testing authentication mechanisms and bypass techniques in modern web applications.

## Scripts

### 🛡️ auth-bypass-tester.nse
Modern authentication bypass tester that performs safe, non-intrusive tests for authentication bypass vulnerabilities commonly found in modern web applications and APIs.

**Features:**
- HTTP method override attack detection
- Header manipulation bypass testing
- Path traversal in authentication mechanisms
- JWT token manipulation (basic security checks)
- Case sensitivity bypass detection
- Unicode/encoding bypass testing
- Protected endpoint discovery and classification

**Usage:**
```bash
# Basic usage
nmap --script auth-bypass-tester.nse -p 80,443 target.com

# Enable all tests with custom timeout
nmap --script auth-bypass-tester.nse --script-args test-jwt=true,test-headers=true,timeout=15 target.com

# Test specific techniques only
nmap --script auth-bypass-tester.nse --script-args test-methods=true,test-unicode=false target.com

# Custom paths and User-Agent
nmap --script auth-bypass-tester.nse --script-args custom-paths="/custom,/private,/secure" target.com
```

**Script Arguments:**
- `test-jwt`: Enable JWT-specific bypass tests (default: true)
- `test-headers`: Enable header manipulation tests (default: true)
- `test-methods`: Enable HTTP method override tests (default: true)
- `test-unicode`: Enable Unicode bypass tests (default: true)
- `timeout`: HTTP request timeout in seconds (default: 10)
- `user-agent`: Custom User-Agent string
- `custom-paths`: Custom comma-separated list of paths to test

**Bypass Techniques Tested:**
- **Method Override**: X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override
- **Header Manipulation**: IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)
- **Auth Headers**: X-User-ID, X-Admin, X-Authenticated, X-Auth-User, X-Role
- **Case Sensitivity**: Various case combinations of protected paths
- **URL Encoding**: Percent encoding, double slashes, trailing slashes
- **JWT Analysis**: Token detection and basic vulnerability checks

**Vulnerability Severity:**
- **CRITICAL**: Complete authentication bypass allowing unauthorized access
- **HIGH**: Method override or header manipulation bypasses
- **MEDIUM**: Case sensitivity or encoding bypasses
- **LOW**: Response differences that may indicate potential issues
- **INFO**: General findings about authentication mechanisms

**Protected Endpoint Detection:**
- Automatically discovers endpoints returning 401, 403, or login redirects
- Tests common protected paths (/admin, /dashboard, /api/users, etc.)
- Supports custom path lists for targeted testing
- Classifies endpoints by protection mechanism

## Categories
- **discovery**: Scripts that discover protected endpoints
- **safe**: Scripts that perform read-only operations
- **auth**: Scripts that test authentication mechanisms

## Requirements
- Nmap 7.0+
- HTTP/HTTPS connectivity
- Modern Lua support with http, json, string, and table libraries

## Notes
- All tests are safe and non-intrusive
- Does not attempt to gain unauthorized access
- Does not modify data or exploit vulnerabilities
- Focuses on detection and classification
- Suitable for authorized security assessments
- Respects application rate limits

## Example Output
```
PORT   STATE SERVICE
80/tcp open  http
| auth-bypass-tester:
|   Authentication Bypass Test Results:
|   
|   Protected Endpoints Discovered:
|     /admin (403 Forbidden)
|     /api/users (401 Unauthorized)  
|     /dashboard (302 Redirect to login)
|   
|   Bypass Vulnerabilities Found:
|     HIGH: HTTP method override bypass on /admin
|       Baseline: 403, Override: 200
|     
|     MEDIUM: Case sensitivity bypass on /Dashboard
|       Original /dashboard: 302, Variant /Dashboard: 200
|     
|     LOW: Header manipulation possible on /api/users
|       Status changed from 401 to 403
|   
|   JWT Token Analysis:
|     JWT token detected in header:authorization (length: 147)
|   
|_  Summary: 2 potential bypass vulnerabilities found
```