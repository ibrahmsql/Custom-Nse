# Subdomain Enumeration NSE Scripts

This directory contains NSE scripts for comprehensive subdomain discovery and enumeration.

## Scripts

### 🔍 subdomain-discoverer.nse
Lightweight subdomain discovery script that focuses on SSL certificate analysis without noisy wordlist scanning.

**Features:**
- Certificate transparency log queries via crt.sh API
- SSL certificate SAN entry parsing
- DNS resolution verification of discovered subdomains
- Clean, non-intrusive passive enumeration
- No wordlist noise or aggressive scanning

**Usage:**
```bash
# Basic usage
nmap --script subdomain-discoverer.nse target.com

# With custom timeout
nmap --script subdomain-discoverer.nse --script-args timeout=15 target.com

# Skip DNS verification (faster)
nmap --script subdomain-discoverer.nse --script-args verify-dns=false target.com
```

**Script Arguments:**
- `timeout`: HTTP request timeout in seconds (default: 10)
- `verify-dns`: Verify subdomains via DNS lookup (default: true)

**Discovery Techniques:**
- **Certificate Transparency**: Queries CT logs for historical certificates
- **SSL Certificate Parsing**: Extracts subdomains from certificate SAN entries
- **DNS Verification**: Validates discovered subdomains are still active
- **Passive Enumeration**: No active scanning or wordlist bruteforcing

**Output Categories:**
- **Certificate Transparency Subdomains**: All subdomains found in CT logs
- **Status Verification**: Active/inactive status for each subdomain
- **Summary Statistics**: Total found vs active subdomain counts

## Categories
- **discovery**: Scripts that discover subdomains and DNS information
- **safe**: Scripts that perform read-only operations

## Requirements
- Nmap 7.0+
- Internet connectivity for CT log queries
- Modern Lua support with http, json libraries
- DNS resolution for subdomain verification

## Notes
- Completely passive - no active scanning or bruteforcing
- Uses only public certificate transparency logs
- No noise generation or detection alerts
- Safe for use in sensitive environments
- Requires internet access to query CT logs

## Example Output
```
Host script results:
| subdomain-discoverer:
|   Certificate Transparency Subdomains:
|     api.example.com (active)
|     blog.example.com (active)
|     dev.example.com (inactive)
|     mail.example.com (active)
|     staging.example.com (inactive)
|     www.example.com (active)
|   
|_  Total: 6 found, 4 active
```
