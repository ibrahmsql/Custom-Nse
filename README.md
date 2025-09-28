# Custom NSE Scripts Collection

A well-organized collection of custom NSE (Nmap Scripting Engine) scripts designed for modern web application scanning, endpoint discovery, and security reconnaissance.

## 📁 Directory Structure

```
organized/
├── web-scanning/           # Web application fingerprinting scripts
│   ├── modern-web-fingerprint.nse
│   └── README.md
├── endpoint-discovery/     # API and endpoint discovery scripts  
│   ├── js-endpoint-harvester.nse
│   └── README.md
├── subdomain-enum/         # Subdomain discovery and enumeration
│   ├── subdomain-discoverer.nse
│   └── README.md
├── api-security/           # API security assessment scripts
│   ├── api-security-scanner.nse
│   └── README.md
├── auth-testing/           # Authentication bypass testing
│   ├── auth-bypass-tester.nse
│   └── README.md
├── cloud-metadata/         # Cloud metadata enumeration
│   ├── cloud-metadata-enum.nse
│   └── README.md
├── git-enum/               # Git repository discovery and analysis
│   ├── git-dumper.nse
│   └── README.md
├── network-enum/           # Network enumeration and infrastructure discovery
│   ├── service-version-fuzzer.nse
│   ├── network-topology-mapper.nse
│   └── README.md
├── documentation/          # Additional documentation
└── README.md              # This file
```

## 🚀 Quick Start

### Web Technology Fingerprinting
```bash
nmap --script organized/web-scanning/modern-web-fingerprint.nse -p 80,443 target.com
```

### JavaScript Endpoint Discovery  
```bash
nmap --script organized/endpoint-discovery/js-endpoint-harvester.nse -p 80,443 target.com
```

### Subdomain Enumeration
```bash
nmap --script organized/subdomain-enum/subdomain-discoverer.nse target.com
```

### API Security Assessment
```bash
nmap --script organized/api-security/api-security-scanner.nse -p 80,443 target.com
```

### Authentication Bypass Testing
```bash
nmap --script organized/auth-testing/auth-bypass-tester.nse -p 80,443 target.com
```

### Cloud Metadata Enumeration
```bash
nmap --script organized/cloud-metadata/cloud-metadata-enum.nse target.com
```

### Git Repository Discovery
```bash
nmap --script git-enum/git-dumper.nse -p 80,443 target.com
```

### Network Enumeration and Infrastructure Discovery
```bash
# Advanced service version detection with fuzzing
nmap --script network-enum/service-version-fuzzer.nse -p 80,443,8080 target.com

# Network topology mapping and infrastructure analysis
nmap --script network-enum/network-topology-mapper.nse target.com
```

## 📋 Script Categories

### 🌐 Web Scanning
- **modern-web-fingerprint.nse**: Advanced web technology stack detection
  - Detects modern frameworks (React, Vue, Angular, etc.)
  - Identifies hosting providers (Vercel, Netlify, etc.)
  - Analyzes security headers and CDN usage

### 🔍 Endpoint Discovery
- **js-endpoint-harvester.nse**: JavaScript-based endpoint harvesting
  - Discovers API endpoints from JS files
  - Extracts application routes and external URLs
  - Intelligent false positive filtering

### 🔍 Subdomain Enumeration
- **subdomain-discoverer.nse**: Comprehensive subdomain discovery
  - DNS zone transfer attempts and wordlist fuzzing
  - Certificate transparency log queries
  - Wildcard DNS detection and filtering

### 🔒 API Security
- **api-security-scanner.nse**: API security vulnerability assessment
  - Detects exposed API documentation and debug endpoints
  - Tests authentication bypass and information disclosure
  - Checks security headers and CORS configuration

### 🛡️ Authentication Testing
- **auth-bypass-tester.nse**: Modern authentication bypass testing
  - HTTP method override and header manipulation tests
  - Case sensitivity and encoding bypass detection
  - JWT token analysis and protected endpoint discovery

### ☁️ Cloud Metadata
- **cloud-metadata-enum.nse**: Cloud metadata service enumeration
  - AWS, Azure, GCP, and Oracle Cloud support
  - Safe metadata extraction with IMDSv2 support
  - Instance, network, and security information discovery

### 🗂️ Git Enumeration
- **git-dumper.nse**: Exposed Git repository discovery and analysis
  - Detects misconfigured .git directory exposure
  - Enumerates branches, tags, and remote repositories
  - Extracts sensitive information and credentials
  - Analyzes configuration files and commit history

### 🌐 Network Enumeration
- **service-version-fuzzer.nse**: Advanced service version detection with fuzzing capabilities
  - Extended HTTP method probing and modern protocol detection
  - Container runtime and Kubernetes service discovery
  - Proxy, load balancer, and API gateway identification
  - SSL/TLS handshake analysis for service fingerprinting
- **network-topology-mapper.nse**: Network infrastructure topology mapping
  - Traceroute analysis with timing correlation and device fingerprinting
  - Load balancer and firewall detection through response patterns
  - Network segmentation boundary identification
  - ISP, ASN identification and multi-path routing detection

## ⚙️ Installation

1. Clone or download the scripts to your local machine
2. Copy scripts to your Nmap scripts directory (optional):
   ```bash
   sudo cp organized/*/*.nse /usr/share/nmap/scripts/
   sudo nmap --script-updatedb
   ```
3. Or run directly with full path:
   ```bash
   nmap --script /path/to/organized/web-scanning/modern-web-fingerprint.nse target.com
   ```

## 🎯 Features

### Safety & Compliance
- ✅ All scripts are categorized as **safe**
- ✅ Read-only operations only
- ✅ No vulnerability exploitation
- ✅ Respects rate limits and timeouts
- ✅ Suitable for compliance auditing

### Modern Technology Support
- 🔧 Detects latest web frameworks and technologies
- 🔧 Identifies cloud hosting and CDN services
- 🔧 Advanced endpoint discovery from JavaScript
- 🔧 Intelligent filtering reduces false positives

### Customization
- ⚙️ Configurable timeouts and limits
- ⚙️ Custom regex patterns support
- ⚙️ Adjustable recursion depth
- ⚙️ Custom User-Agent strings

## 📖 Usage Examples

### Comprehensive Web Analysis
```bash
# Full web technology stack analysis
nmap --script organized/web-scanning/ -p 80,443 target.com

# Endpoint discovery with custom parameters
nmap --script organized/endpoint-discovery/ --script-args max-depth=3,timeout=15 -p 80,443 target.com

# Combined scanning
nmap --script organized/web-scanning/,organized/endpoint-discovery/ -p 80,443 target.com
```

### Advanced Configuration
```bash
# Custom file size limit for endpoint harvester
nmap --script organized/endpoint-discovery/js-endpoint-harvester.nse \
     --script-args max-size=1048576,user-agent="Custom Scanner" \
     -p 80,443 target.com

# Extended timeout for slow targets
nmap --script organized/web-scanning/modern-web-fingerprint.nse \
     --script-args timeout=30 \
     -p 80,443 target.com
```

## 🔒 Security Considerations

- All scripts perform **passive reconnaissance** only
- No data is modified or exploited on target systems  
- Scripts respect standard HTTP conventions
- Suitable for authorized security assessments
- Follow responsible disclosure practices

## 🤝 Contributing

When adding new scripts:
1. Place them in appropriate category directories
2. Update the respective README files
3. Ensure scripts follow NSE best practices
4. Test thoroughly before submission
5. Document all script arguments and features

## 📄 License

These scripts are provided for educational and authorized security testing purposes only. Use responsibly and in compliance with applicable laws and regulations.

## 🆕 Recent Updates

- **NEW**: Added Network Enumeration category with advanced infrastructure discovery
- **service-version-fuzzer.nse**: Advanced service version detection with modern protocol support
- **network-topology-mapper.nse**: Comprehensive network topology mapping and infrastructure analysis
- **NEW**: Added Git repository enumeration category with advanced discovery capabilities
- **git-dumper.nse**: Comprehensive Git repository exposure detection and analysis
- **subdomain-discoverer.nse**: Complete subdomain enumeration with CT logs and wildcard detection
- **api-security-scanner.nse**: Comprehensive API security assessment including GraphQL testing
- **auth-bypass-tester.nse**: Modern authentication bypass testing with multiple techniques
- **cloud-metadata-enum.nse**: Multi-cloud metadata enumeration (AWS, Azure, GCP, Oracle)
- **js-endpoint-harvester.nse**: Significantly improved false positive filtering
- **modern-web-fingerprint.nse**: Enhanced modern framework detection
- **Organization**: All scripts organized into logical categories with detailed documentation

---

**Note**: Always ensure you have proper authorization before scanning any systems. These tools are intended for legitimate security research and authorized penetration testing only.