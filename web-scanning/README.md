# Web Scanning NSE Scripts

This directory contains NSE scripts for comprehensive web application scanning and fingerprinting.

## Scripts

### 🌐 modern-web-fingerprint.nse
Advanced web application fingerprinting script that detects modern web technologies, frameworks, and services.

**Features:**
- Technology stack detection (React, Vue, Angular, etc.)
- Framework version identification
- CDN and hosting provider detection
- Security headers analysis
- Modern web technology fingerprinting
- Cloud service detection

**Usage:**
```bash
nmap --script modern-web-fingerprint.nse -p 80,443 target.com

# With custom User-Agent
nmap --script modern-web-fingerprint.nse --script-args user-agent="Custom Bot" -p 80,443 target.com

# With extended timeout
nmap --script modern-web-fingerprint.nse --script-args timeout=15 -p 80,443 target.com
```

**Script Arguments:**
- `timeout`: HTTP request timeout in seconds (default: 10)
- `user-agent`: Custom User-Agent string (default: "NSE Web Fingerprinter")

**Detection Capabilities:**
- JavaScript Frameworks (React, Vue, Angular, Svelte, etc.)
- CSS Frameworks (Bootstrap, Tailwind, Bulma, etc.)
- Build Tools (Webpack, Vite, Parcel, etc.)
- Hosting Providers (Vercel, Netlify, GitHub Pages, etc.)
- CDN Services (Cloudflare, AWS CloudFront, etc.)
- Analytics & Tracking (Google Analytics, etc.)
- Security Headers (CSP, HSTS, etc.)

## Categories
- **discovery**: Scripts that discover web technologies
- **safe**: Scripts that perform read-only operations
- **version**: Scripts that attempt version detection

## Requirements
- Nmap 7.0+
- HTTP/HTTPS connectivity
- Modern Lua support

## Notes
- All scripts are safe and perform only passive scanning
- No aggressive techniques or vulnerability exploitation
- Respects robots.txt and rate limiting
- Suitable for compliance and security auditing