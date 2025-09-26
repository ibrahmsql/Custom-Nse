# Endpoint Discovery NSE Scripts

This directory contains NSE scripts for discovering and harvesting API endpoints, routes, and URLs from web applications.

## Scripts

### 🔍 js-endpoint-harvester.nse
Advanced JavaScript endpoint harvester that discovers and extracts potential API endpoints, URLs, and route paths from JavaScript files found on web applications.

**Features:**
- Recursive JavaScript file discovery from HTML pages
- Downloads and analyzes JavaScript files for endpoints
- Extracts API endpoints, application routes, and external URLs using regex patterns
- Configurable recursion depth and file size limits
- Intelligent false positive filtering
- Categorized output (API endpoints, routes, external URLs)
- Respects timeout and size limitations

**Usage:**
```bash
# Basic usage
nmap --script js-endpoint-harvester.nse -p 80,443 target.com

# With custom parameters
nmap --script js-endpoint-harvester.nse --script-args max-depth=3,max-size=1024000 target.com

# With custom regex pattern
nmap --script js-endpoint-harvester.nse --script-args custom-pattern="/custom/[^\"'\\s<>)};,]*" target.com

# Verbose output for debugging
nmap --script js-endpoint-harvester.nse -p 80,443 -d target.com
```

**Script Arguments:**
- `max-depth`: Maximum recursion depth for following JS links (default: 2)
- `max-size`: Maximum JS file size to download in bytes (default: 512000)
- `timeout`: HTTP request timeout in seconds (default: 10)
- `custom-pattern`: Custom regex pattern for endpoint extraction
- `user-agent`: Custom User-Agent string (default: "NSE JS Harvester")

**Discovery Process:**
1. Fetches the main HTTP/HTTPS page
2. Extracts JavaScript file URLs from `<script src="...">` tags
3. Downloads each JavaScript file (respecting size limits)
4. Applies regex patterns to extract potential endpoints
5. Filters out false positives (MIME types, hashes, single letters)
6. Categorizes findings into API endpoints, routes, and external URLs
7. Outputs deduplicated results

**Filtering & False Positive Reduction:**
- Filters out MIME types (application/, text/, image/)
- Removes hash-like and base64-like strings
- Excludes single letters and common JavaScript artifacts
- Length validation (minimum 4 characters, maximum 200)
- Valid path structure validation

**Output Categories:**
- **API Endpoints**: `/api/`, `/v1/`, `/rest/`, `/graphql` patterns
- **Routes**: Application routes like `/dashboard`, `/user/profile`
- **External URLs**: Full HTTPS URLs to external services and APIs

## Categories
- **discovery**: Scripts that discover endpoints and URLs
- **safe**: Scripts that perform read-only operations

## Requirements
- Nmap 7.0+
- HTTP/HTTPS connectivity
- Modern Lua support with http, url, and string libraries

## Notes
- All operations are read-only and safe
- Respects configurable timeouts and size limits
- Does not exploit vulnerabilities or perform aggressive testing
- Suitable for reconnaissance and security assessment
- Output is organized and deduplicated for easy analysis

## Example Output
```
PORT   STATE SERVICE
80/tcp open  http
| js-endpoint-harvester:
|   Discovered JavaScript files (3):
|     /js/app.js (45.2KB)
|     /assets/vendor.js (234.7KB)
|     /static/bundle.js (156.3KB)
|   
|   Discovered endpoints (15):
|     API Endpoints:
|       /api/v1/users
|       /api/v1/auth/login
|       /api/v2/products
|     Routes:
|       /dashboard
|       /profile/settings
|       /admin/panel
|     External URLs:
|       https://api.example.com/v1/
|_      https://cdn.example.com/assets/
```