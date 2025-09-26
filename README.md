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

- **js-endpoint-harvester.nse**: Significantly improved false positive filtering
- **modern-web-fingerprint.nse**: Enhanced modern framework detection
- **Organization**: Scripts organized into logical categories with documentation

---

**Note**: Always ensure you have proper authorization before scanning any systems. These tools are intended for legitimate security research and authorized penetration testing only.