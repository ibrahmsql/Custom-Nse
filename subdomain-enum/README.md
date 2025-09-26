# Subdomain Enumeration NSE Scripts

This directory contains NSE scripts for comprehensive subdomain discovery and enumeration.

## Scripts

### 🔍 subdomain-discoverer.nse
Advanced subdomain discovery script that uses multiple techniques including DNS enumeration, certificate transparency logs, and wordlist fuzzing.

**Features:**
- DNS zone transfer attempts (if allowed)
- Common subdomain wordlist fuzzing (small, medium, large)
- Certificate transparency log queries via crt.sh API
- DNS wildcard detection and filtering
- Intelligent false positive reduction
- Configurable recursion depth and timeouts

**Usage:**
```bash
# Basic usage
nmap --script subdomain-discoverer.nse target.com

# With large wordlist
nmap --script subdomain-discoverer.nse --script-args wordlist-size=large target.com

# With custom wordlist
nmap --script subdomain-discoverer.nse --script-args custom-wordlist="dev,staging,prod,api" target.com

# Disable CT logs and use custom timeout
nmap --script subdomain-discoverer.nse --script-args ct-logs=false,timeout=10 target.com
```

**Script Arguments:**
- `wordlist-size`: Wordlist size - small, medium, large (default: medium)
- `max-depth`: Maximum recursion depth (default: 2)
- `timeout`: DNS query timeout in seconds (default: 5)
- `ct-logs`: Query certificate transparency logs (default: true)
- `custom-wordlist`: Custom comma-separated subdomain list

**Discovery Techniques:**
- **DNS Zone Transfer**: Attempts AXFR requests on discovered nameservers
- **Wordlist Fuzzing**: Tests common subdomain patterns
- **Certificate Transparency**: Queries CT logs for historical certificates
- **Wildcard Detection**: Identifies and filters wildcard DNS responses
- **Intelligent Filtering**: Removes false positives from wildcard responses

**Output Categories:**
- **Discovered Subdomains**: Active subdomains with IP addresses
- **CT Log Findings**: Subdomains found only in certificate transparency logs
- **DNS Information**: Wildcard status and zone transfer results

## Categories
- **discovery**: Scripts that discover subdomains and DNS information
- **safe**: Scripts that perform read-only operations

## Requirements
- Nmap 7.0+
- DNS resolution capability
- Internet connectivity for CT log queries
- Modern Lua support with dns, http, and json libraries

## Notes
- All operations are safe and read-only
- Respects DNS rate limits and timeouts
- Does not perform aggressive techniques
- Suitable for authorized reconnaissance
- Certificate transparency queries require internet access

## Example Output
```
Host script results:
| subdomain-discoverer:
|   Discovered subdomains (12):
|     www.example.com (93.184.216.34)
|     mail.example.com (93.184.216.35)
|     blog.example.com (185.199.108.153)
|     api.example.com (93.184.216.36)
|   
|   Certificate transparency findings (3):
|     dev.example.com (from CT logs)
|     staging.example.com (from CT logs)
|     internal.example.com (from CT logs)
|   
|   DNS Information:
|     Wildcard DNS: No
|     Zone transfer: Denied
|_    Total unique subdomains: 15
```