# Cloud Metadata Enumeration NSE Scripts

This directory contains NSE scripts for safely enumerating cloud metadata services when targets are running in cloud environments.

## Scripts

### ☁️ cloud-metadata-enum.nse
Comprehensive cloud metadata enumeration script that detects and safely enumerates metadata endpoints from major cloud providers including AWS, Azure, Google Cloud, and Oracle Cloud.

**Features:**
- AWS EC2 Instance Metadata Service (IMDS v1/v2) enumeration
- Azure Instance Metadata Service querying
- Google Cloud Metadata Service discovery
- Oracle Cloud Infrastructure metadata detection
- Safe, read-only operations with respect for rate limits
- Automatic cloud provider detection
- Comprehensive instance information extraction

**Usage:**
```bash
# Basic usage (tests all providers)
nmap --script cloud-metadata-enum.nse target.com

# Test specific cloud providers
nmap --script cloud-metadata-enum.nse --script-args check-aws=true,check-azure=false target.com

# Custom timeout and User-Agent
nmap --script cloud-metadata-enum.nse --script-args timeout=10,user-agent="Custom Scanner" target.com

# AWS-only with extended timeout
nmap --script cloud-metadata-enum.nse --script-args check-azure=false,check-gcp=false,timeout=15 target.com
```

**Script Arguments:**
- `check-aws`: Enable AWS metadata checks (default: true)
- `check-azure`: Enable Azure metadata checks (default: true)
- `check-gcp`: Enable GCP metadata checks (default: true)
- `check-oracle`: Enable Oracle Cloud checks (default: true)
- `timeout`: HTTP request timeout in seconds (default: 5)
- `user-agent`: Custom User-Agent string

**Supported Cloud Providers:**
- **AWS (Amazon Web Services)**
  - EC2 Instance Metadata Service (169.254.169.254)
  - IMDSv1 and IMDSv2 support
  - Instance details, networking, security groups, IAM roles
  - User data detection (size only, for security)

- **Microsoft Azure**
  - Azure Instance Metadata Service
  - Virtual machine information
  - Network configuration details
  - Subscription and resource group information

- **Google Cloud Platform**
  - Compute Engine Metadata Service
  - Instance and project information
  - Machine type and zone details
  - Network interface configuration

- **Oracle Cloud Infrastructure**
  - OCI Metadata Service
  - Instance identity and configuration
  - Basic instance information

**Metadata Categories:**
- **Instance Information**: ID, type, region, availability zone
- **Network Information**: Private/public IPs, hostnames, MAC addresses
- **Security Information**: IAM roles, security groups, access policies
- **Additional Information**: User data presence, launch details

## Categories
- **discovery**: Scripts that discover cloud metadata and services
- **safe**: Scripts that perform read-only operations
- **default**: Scripts suitable for default scanning

## Requirements
- Nmap 7.0+
- HTTP connectivity to metadata endpoints (typically 169.254.169.254)
- Modern Lua support with http, json, string, and table libraries
- Target must be running in a cloud environment

## Notes
- All operations are completely safe and read-only
- Respects cloud provider rate limits and timeouts
- Does not access sensitive credential information
- Only retrieves publicly accessible metadata
- Suitable for authorized cloud security assessments
- Will only work when run from within cloud instances

## Example Output
```
Host script results:
| cloud-metadata-enum:
|   Cloud Provider: AWS (Amazon Web Services)
|   Instance Metadata Service: Accessible
|   IMDS Version: v2
|   
|   Instance Information:
|     Instance ID: i-1234567890abcdef0
|     Instance Type: t3.medium
|     Region: us-east-1
|     Availability Zone: us-east-1a
|     AMI ID: ami-0abcdef1234567890
|   
|   Network Information:
|     Private IPv4: 172.31.32.123
|     Public IPv4: 54.123.45.67
|     Hostname: ip-172-31-32-123.ec2.internal
|   
|   Security Information:
|     IAM Role: MyInstanceRole
|     Security Groups: sg-12345678 (default)
|   
|_  Additional Information:
|_    User Data: [DETECTED - 156 bytes]
```

## Security Considerations
- Script only runs from within cloud instances
- Does not retrieve sensitive credentials or keys
- User data size is reported but content is not displayed
- All requests use appropriate cloud provider headers
- Respects IMDSv2 token requirements for AWS