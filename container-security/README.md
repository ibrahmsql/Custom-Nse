# Container Security Scripts

Advanced container and Docker security assessment NSE scripts designed for comprehensive container infrastructure enumeration and vulnerability discovery.

## 📋 Scripts Overview

### 🐳 docker-registry-enum.nse
**Comprehensive Docker Registry enumeration and security assessment**

This script performs detailed enumeration of Docker registries by leveraging the Docker Registry HTTP API v2. It discovers repositories, analyzes manifests, and identifies security misconfigurations in container registries.

**Key Features:**
- Docker Registry API v2 enumeration and version detection
- Repository discovery through catalog API and intelligent brute-force
- Tag enumeration for all discovered repositories
- Manifest analysis and layer information extraction
- Sensitive information detection in image metadata
- Authentication bypass testing for misconfigured registries
- Harbor, Nexus, Artifactory, and other registry platform detection
- Security assessment and vulnerability identification
- Private key and credential exposure detection

**Usage:**
```bash
# Basic Docker registry enumeration
nmap --script container-security/docker-registry-enum.nse -p 5000 target.com

# Comprehensive scan with manifest analysis
nmap --script container-security/docker-registry-enum.nse --script-args check-manifests=true -p 5000,443 target.com

# Custom repository limits and timeout
nmap --script container-security/docker-registry-enum.nse --script-args max-repos=50,max-tags=20,timeout=15 target.com

# Disable common repository brute-force (faster scan)
nmap --script container-security/docker-registry-enum.nse --script-args common-repos=false target.com
```

**Example Output:**
```
PORT     STATE SERVICE
5000/tcp open  docker-registry
| docker-registry-enum:
|   Registry Information:
|     Version: Docker Registry 2.8.1
|     Type: Docker Registry v2 API
|     Authentication: None (Public Access)
|     
|   Discovered Repositories (8 found):
|     webapp/frontend:
|       Tags: latest, v1.2.3, v1.2.2, dev
|       Layers: 12
|       Exposed ports: 80/tcp, 443/tcp
|       Environment variables: DATABASE_URL, API_KEY, JWT_SECRET
|     
|     api/backend:
|       Tags: latest, staging, v2.1.0
|       Layers: 8
|       Environment variables: DB_PASSWORD, SECRET_KEY, AWS_ACCESS_KEY
|     
|     admin/dashboard:
|       Tags: latest, beta
|       Layers: 6
|       Environment variables: ADMIN_PASSWORD, SESSION_SECRET
|       
|   Security Issues:
|     - No authentication required for repository access
|     - API Key exposed in webapp/frontend manifest
|     - Database credentials exposed in api/backend manifest
|     - AWS Access Key exposed in api/backend manifest
```

## 🎯 Use Cases

### Container Infrastructure Assessment
The docker-registry-enum script excels at:
- **DevOps Security Auditing**: Identifying exposed container registries in development environments
- **Container Supply Chain Security**: Discovering publicly accessible registries with sensitive images
- **Cloud Security Assessment**: Finding misconfigured registry endpoints in cloud deployments
- **Red Team Operations**: Enumerating container infrastructure for privilege escalation opportunities

### Registry Platform Detection
Supports comprehensive detection of:
- **Docker Registry**: Official Docker registry implementations
- **Harbor**: VMware Harbor enterprise registry
- **Nexus Repository**: Sonatype Nexus repository manager
- **Artifactory**: JFrog Artifactory container registry
- **Cloud Registries**: AWS ECR, GCP GCR, Azure ACR detection patterns

## ⚙️ Script Arguments

### docker-registry-enum.nse Arguments
- `max-repos`: Maximum number of repositories to enumerate (default: 20)
- `max-tags`: Maximum number of tags per repository to analyze (default: 10)
- `check-manifests`: Enable manifest analysis for sensitive information (default: false)
- `wordlist`: Custom wordlist file for repository brute-force (default: built-in list)
- `timeout`: HTTP timeout in seconds (default: 10)
- `user-agent`: Custom User-Agent string (default: Docker client)
- `auth-bypass`: Test authentication bypass techniques (default: true)
- `common-repos`: Test common repository names via brute-force (default: true)

## 🔍 Detection Capabilities

### Repository Discovery Methods
1. **Catalog API Enumeration**: Leverages `/v2/_catalog` endpoint for comprehensive repository listing
2. **Intelligent Brute-Force**: Tests common container image names and patterns
3. **Tag Discovery**: Enumerates all available tags for each discovered repository
4. **Manifest Analysis**: Deep inspection of image manifests for sensitive information

### Sensitive Information Detection
The script identifies various types of sensitive data:
- **Credentials**: Passwords, API keys, database URLs, JWT secrets
- **Private Keys**: SSH private keys, SSL certificates, RSA keys
- **Cloud Credentials**: AWS access keys, Google OAuth tokens, Azure keys  
- **Environment Variables**: Database passwords, session secrets, configuration tokens
- **File References**: Sensitive file paths, configuration files, key locations

## 🔒 Security Considerations

- **Safe Operation**: Script performs read-only enumeration with no destructive actions
- **Rate Limiting**: Built-in delays prevent overwhelming target registries
- **Authentication Aware**: Properly handles both authenticated and public registries
- **Error Handling**: Robust error handling prevents script crashes on malformed responses
- **Privacy Conscious**: Does not store or log discovered sensitive information

## 📊 Registry Security Assessment

### Common Vulnerabilities Detected
- **Public Access**: Registries accessible without authentication
- **Information Disclosure**: Sensitive data exposed in image metadata
- **Credential Exposure**: Hardcoded credentials in container images
- **Misconfiguration**: Improper registry access controls
- **Privilege Escalation**: Exposed private keys enabling lateral movement

### Registry Platform Specific Checks
- **Harbor**: Version detection, project enumeration, vulnerability scanning status
- **Nexus**: Repository format detection, security policy assessment
- **Artifactory**: License detection, security configuration analysis
- **Cloud Registries**: IAM policy assessment, public/private access verification

## 📈 Performance Optimization

### Scan Efficiency Tips
1. **Limit Repository Count**: Use `max-repos` to control scan depth
2. **Disable Manifest Analysis**: Skip `check-manifests` for faster reconnaissance
3. **Custom Timeout Values**: Adjust `timeout` based on network conditions
4. **Targeted Brute-Force**: Disable `common-repos` if catalog API is available

### Large-Scale Scanning
```bash
# Fast reconnaissance scan
nmap --script container-security/docker-registry-enum.nse --script-args max-repos=5,check-manifests=false -p 5000 targets.txt

# Comprehensive security assessment
nmap --script container-security/docker-registry-enum.nse --script-args check-manifests=true,max-repos=100 -p 5000,443,80,8080 target.com
```

## 🤝 Contributing

When extending this script:
1. Add new registry platform detection patterns to the `detect_registry` function
2. Extend sensitive pattern matching in the `sensitive_patterns` array
3. Include additional common repository names for brute-force discovery
4. Test thoroughly with various registry implementations
5. Maintain backward compatibility with existing arguments

## 🔗 Integration

This script works well in combination with:
- Standard Nmap service detection (`-sV`) for service identification
- SSL certificate analysis (`ssl-cert.nse`) for registry authentication
- HTTP enumeration scripts for additional web-based discovery
- Container orchestration detection (Kubernetes, Docker Swarm)

For comprehensive container security assessment:
```bash
nmap --script container-security/,http-* -sV -p 80,443,5000,8080 target-range
```

## 📚 References

- [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/)
- [Harbor API Documentation](https://goharbor.io/docs/latest/working-with-projects/working-with-images/pulling-pushing-images/)
- [Container Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Registry Security Configuration](https://docs.docker.com/registry/configuration/)

---

**Note**: Always ensure proper authorization before scanning container registries. This tool is intended for authorized security assessments and legitimate penetration testing only.