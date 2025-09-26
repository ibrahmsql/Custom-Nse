# API Security NSE Scripts

This directory contains NSE scripts for comprehensive API security assessment and vulnerability detection.

## Scripts

### 🔒 api-security-scanner.nse
Comprehensive API security scanner that detects common API security issues and misconfigurations in REST APIs, GraphQL endpoints, and other API implementations.

**Features:**
- Exposed API documentation and debug endpoint detection
- Authentication bypass vulnerability testing
- Information disclosure in error messages identification
- Missing security headers detection
- Common API vulnerabilities (CORS, rate limiting, etc.)
- API versioning and endpoint enumeration analysis
- GraphQL introspection testing

**Usage:**
```bash
# Basic usage
nmap --script api-security-scanner.nse -p 80,443 target.com

# With GraphQL testing enabled
nmap --script api-security-scanner.nse --script-args check-graphql=true target.com

# Disable Swagger checks and set custom timeout
nmap --script api-security-scanner.nse --script-args check-swagger=false,timeout=15 target.com

# Custom User-Agent and max paths
nmap --script api-security-scanner.nse --script-args user-agent="Custom Scanner",max-paths=100 target.com
```

**Script Arguments:**
- `check-graphql`: Enable GraphQL-specific tests (default: true)
- `check-swagger`: Check for Swagger/OpenAPI docs (default: true)
- `timeout`: HTTP request timeout in seconds (default: 10)
- `user-agent`: Custom User-Agent string
- `max-paths`: Maximum API paths to test (default: 50)

**Security Assessments:**
- **Documentation Exposure**: Detects publicly accessible API documentation
- **Authentication Bypass**: Tests header manipulation and method override techniques
- **Information Disclosure**: Analyzes error messages for sensitive information
- **Security Headers**: Checks for missing security headers (CORS, CSP, etc.)
- **GraphQL Security**: Tests introspection and schema exposure
- **Method Override**: Tests HTTP method override attacks

**Vulnerability Categories:**
- **CRITICAL**: Authentication bypass detected
- **HIGH**: API documentation publicly accessible
- **MEDIUM**: Missing security headers, verbose errors, CORS issues
- **LOW**: Minor configuration issues
- **INFO**: General findings and recommendations

## Categories
- **discovery**: Scripts that discover API endpoints and services
- **safe**: Scripts that perform read-only operations
- **vuln**: Scripts that test for vulnerabilities

## Requirements
- Nmap 7.0+
- HTTP/HTTPS connectivity
- Modern Lua support with http, json, string, and table libraries

## Notes
- All operations are safe and non-intrusive
- Does not exploit vulnerabilities or modify data
- Focuses on detection without disruption
- Suitable for authorized security assessments
- Respects rate limits and timeouts

## Example Output
```
PORT   STATE SERVICE
80/tcp open  http
| api-security-scanner:
|   API Security Assessment Results:
|   
|   Discovered API Endpoints:
|     /api/v1/ (REST API detected)
|     /graphql (GraphQL endpoint)
|     /api/docs (API documentation exposed)
|   
|   Security Issues Found:
|     HIGH: API documentation publicly accessible
|     MEDIUM: Missing CORS headers on API endpoints
|     MEDIUM: Verbose error messages expose internal information
|   
|   Additional Findings:
|     GraphQL introspection enabled
|_    Multiple API versions detected: v1, v2
```