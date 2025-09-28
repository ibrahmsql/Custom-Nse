# Network Enumeration Scripts

Advanced network enumeration and infrastructure discovery NSE scripts designed for modern network reconnaissance and topology mapping.

## 📋 Scripts Overview

### 🔍 service-version-fuzzer.nse
**Advanced service version detection with fuzzing capabilities for modern services**

Extends Nmap's built-in version detection by using additional probes and techniques to identify services that may be obfuscated, proxied, or running modern protocols.

**Key Features:**
- Extended HTTP method probing (OPTIONS, TRACE, PATCH, etc.)
- SSL/TLS handshake analysis for version detection
- Modern protocol detection (HTTP/2, QUIC, gRPC)
- Proxy and load balancer identification
- Container runtime detection (Docker, containerd)
- Kubernetes service discovery
- Custom header injection for service identification
- Response timing analysis for service fingerprinting

**Usage:**
```bash
# Basic usage
nmap --script service-version-fuzzer -p 80,443,8080,6443 target.com

# Custom timeout and methods
nmap --script service-version-fuzzer --script-args timeout=10,methods="GET,POST,OPTIONS" target.com

# Maximum probes limit
nmap --script service-version-fuzzer --script-args max-probes=20 target.com
```

**Example Output:**
```
PORT     STATE SERVICE    VERSION
80/tcp   open  http       nginx 1.19.6 (reverse proxy -> Apache/2.4.41)
|_service-version-fuzzer: Detected load balancer: HAProxy 2.2.0
443/tcp  open  ssl/https  nginx 1.19.6 (with HTTP/2 support)
|_service-version-fuzzer: Backend service: Gunicorn/20.1.0 Python/3.9.2
6443/tcp open  kubernetes Kubernetes API Server v1.21.0
|_service-version-fuzzer: Container runtime: containerd://1.4.4
```

### 🗺️ network-topology-mapper.nse  
**Network topology mapping for infrastructure discovery and segmentation analysis**

Performs advanced network reconnaissance to map the topology between the scanning host and target networks. Identifies routers, firewalls, load balancers, and network segmentation boundaries.

**Key Features:**
- Traceroute analysis with timing correlation
- TTL manipulation for hop discovery
- Network device fingerprinting via response analysis
- Load balancer detection through response patterns
- Network segmentation boundary identification
- Multi-path routing detection
- ISP and ASN identification for discovered hops
- Network latency mapping and analysis
- Firewall rule inference through port behavior

**Usage:**
```bash
# Basic topology mapping
nmap --script network-topology-mapper target.com

# Custom parameters
nmap --script network-topology-mapper --script-args max-hops=20,timeout=5 192.168.1.0/24

# Detailed device fingerprinting
nmap --script network-topology-mapper --script-args detailed=true,threads=5 target.com
```

**Example Output:**
```
Host script results:
| network-topology-mapper:
|   Network Topology Analysis:
|     Hop 1: 192.168.1.1 (0.8ms) [Local Gateway Router]
|     Hop 2: 10.0.1.1 (2.1ms) [Cisco Router]
|     Hop 3: 203.0.113.1 (15.2ms) [Juniper Router]
|     Hop 4: 198.51.100.1 (28.5ms) [F5 BIG-IP Load Balancer]
|     Hop 5: 203.0.113.50 (29.1ms) [nginx Reverse Proxy]
|   
|   Network Infrastructure:
|     Load Balancer detected at hop 4 (High RTT variance 45ms)
|     Network segmentation: 3 distinct subnets identified
|   
|   Timing Analysis:
|     Average RTT increase per hop: 7.2ms
```

## 🎯 Use Cases

### Service Discovery Enhancement
The service-version-fuzzer script is perfect for:
- **Modern Web Applications**: Detecting React, Vue, Angular applications behind proxies
- **Container Environments**: Identifying Docker registries, Kubernetes APIs
- **Microservices**: Discovering API gateways, service meshes, load balancers
- **Cloud Infrastructure**: Detecting AWS, Azure, GCP services and CDNs

### Network Infrastructure Mapping
The network-topology-mapper script excels at:
- **Network Reconnaissance**: Mapping network paths and infrastructure
- **Security Assessment**: Identifying firewalls, IPS/IDS devices
- **Performance Analysis**: Finding network bottlenecks and latency issues
- **Segmentation Testing**: Discovering network boundaries and isolation

## ⚙️ Script Arguments

### service-version-fuzzer.nse Arguments
- `timeout`: Timeout for each probe in seconds (default: 8)
- `methods`: HTTP methods to test, comma-separated (default: "GET,POST,OPTIONS,HEAD,PATCH")
- `user-agent`: Custom User-Agent string (default: rotates through multiple)
- `max-probes`: Maximum number of probes per port (default: 15)

### network-topology-mapper.nse Arguments
- `max-hops`: Maximum TTL/hops to probe (default: 30)
- `timeout`: Timeout per probe in seconds (default: 3)
- `min-rate`: Minimum packet rate (default: 100)
- `probe-ports`: Ports to use for probing (default: "80,443,22,53")
- `detailed`: Enable detailed device fingerprinting (default: false)
- `threads`: Number of parallel threads (default: 10)

## 🔒 Security Considerations

- All scripts perform **reconnaissance only** - no exploitation
- Scripts are categorized as **safe** with some **intrusive** elements for topology mapping
- Rate limiting and delays implemented to avoid overwhelming targets
- Suitable for authorized penetration testing and security assessments
- Follow responsible disclosure practices

## 📈 Performance Tips

1. **Optimize Timeouts**: Adjust timeout values based on network conditions
2. **Limit Probes**: Use `max-probes` to control scan intensity
3. **Thread Management**: Adjust thread count based on target capacity
4. **Port Selection**: Focus on relevant ports for your environment

## 🤝 Contributing

When extending these scripts:
1. Maintain the modular structure and clear documentation
2. Add new detection patterns to the appropriate pattern arrays
3. Test thoroughly with various network configurations
4. Ensure backward compatibility with existing arguments
5. Follow NSE best practices for error handling and output formatting

## 🔗 Integration

These scripts work well in combination with:
- Standard Nmap service detection (`-sV`)
- OS fingerprinting (`-O`)
- Traceroute functionality (`--traceroute`)
- Other custom NSE scripts in this collection

For comprehensive network analysis, consider running both scripts together:
```bash
nmap --script network-enum/ -sV -O --traceroute target.com
```