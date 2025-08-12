# Router Flood - Network Stress Testing Tool

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**⚠️ EDUCATIONAL PURPOSES ONLY - LOCAL NETWORK TESTING**

A sophisticated DDoS simulation tool built in Rust for educational purposes and local network stress testing. This tool helps network administrators and security researchers understand network vulnerabilities and test the resilience of network infrastructure.

## 🚨 Security and Legal Notice

**CRITICAL WARNINGS:**
- ✅ **ONLY** use on networks you own or have explicit written permission to test
- ✅ **ONLY** targets private IP ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- ❌ **NEVER** target public IP addresses or networks you don't control
- ❌ Using this tool against unauthorized targets is **ILLEGAL** and unethical
- 🔒 Built-in safety mechanisms prevent accidental misuse

## 🎯 Features

### Core Capabilities
- **Multi-Protocol Flooding**: UDP, TCP SYN, TCP ACK, ICMP
- **Realistic Traffic Patterns**: Variable packet sizes, randomized timing
- **High Performance**: Async/concurrent architecture using Tokio
- **Production Ready**: Comprehensive error handling and monitoring
- **Plugin System**: Extensible attack patterns and monitoring plugins

### Security Features
- 🛡️ **Private IP Enforcement**: Blocks public IP targeting
- 🔢 **Rate Limiting**: Configurable safety limits
- 📊 **Real-time Monitoring**: Live statistics and performance metrics
- 🎛️ **Graceful Shutdown**: Proper cleanup on Ctrl+C
- 📝 **Audit Logging**: Comprehensive logging for analysis

### Advanced Features
- 📋 **JSON Configuration**: Flexible configuration management
- 🔄 **Burst Modes**: Simulate realistic attack patterns
- 📈 **Performance Metrics**: Detailed bandwidth and packet statistics
- 🔌 **Plugin Architecture**: Extensible with custom attack patterns
- ⏱️ **Duration Control**: Time-limited testing sessions

## 🚀 Quick Start

### Prerequisites
- **Root privileges** (required for raw socket access)
- **Rust 1.70+** (tested with latest stable)
- **Linux system** (tested on Ubuntu, Debian, Arch)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/router-flood.git
cd router-flood

# Build the project (optimized)
cargo build --release

# Install system-wide (optional)
sudo cp target/release/router-flood /usr/local/bin/
```

### Basic Usage

```bash
# Simple HTTP flood test (requires sudo)
sudo ./target/release/router-flood --target 192.168.1.1 --port 80

# Advanced usage with custom parameters
sudo ./target/release/router-flood \
    --target 192.168.1.1 \
    --port 443 \
    --threads 8 \
    --rate 500 \
    --duration 60
```

## 📖 Configuration

### Command Line Options

```
Router Flood - Network Stress Tester 2.0
Educational DDoS simulation for local network testing

USAGE:
    router-flood [OPTIONS] --target <IP> --port <PORT>

OPTIONS:
    -t, --target <IP>        Target router IP (must be private range)
    -p, --port <PORT>        Target port (e.g., 80 for HTTP)
        --threads <NUM>      Number of async tasks (default: 4, max: 100)
        --rate <PPS>         Packets per second per thread (default: 100)
    -d, --duration <SECONDS> Test duration in seconds (default: unlimited)
    -h, --help               Print help information
    -V, --version            Print version information
```

### Configuration File

The tool supports JSON configuration files for advanced scenarios:

```json
{
  "target": {
    "ip": "192.168.1.1",
    "ports": [80, 443, 22, 53],
    "protocol_mix": {
      "udp_ratio": 0.6,
      "tcp_syn_ratio": 0.3,
      "tcp_ack_ratio": 0.05,
      "icmp_ratio": 0.05
    }
  },
  "attack": {
    "threads": 4,
    "packet_rate": 100,
    "duration": 60,
    "packet_size_range": [64, 1400],
    "patterns": [
      {
        "name": "http_flood",
        "description": "HTTP GET flood pattern",
        "enabled": true,
        "weight": 0.4
      }
    ]
  },
  "safety": {
    "max_threads": 100,
    "max_packet_rate": 10000,
    "require_private_ranges": true,
    "enable_monitoring": true
  }
}
```

## 🧪 Real-World Testing Scenarios

### Router Resilience Testing

Test your home router's ability to handle traffic spikes:

```bash
# Test HTTP service resilience
sudo router-flood --target 192.168.1.1 --port 80 --threads 4 --rate 200 --duration 30

# Test DNS service under load
sudo router-flood --target 192.168.1.1 --port 53 --threads 2 --rate 100 --duration 60

# Test SSH brute-force protection
sudo router-flood --target 192.168.1.1 --port 22 --threads 1 --rate 10 --duration 120
```

### Enterprise Network Testing

For enterprise environments (with proper authorization):

```bash
# Load balancer stress test
sudo router-flood --target 10.0.1.100 --port 80 --threads 16 --rate 1000 --duration 300

# Firewall rule testing
sudo router-flood --target 172.16.0.1 --port 443 --threads 8 --rate 500 --duration 180
```

### Performance Benchmarking

Monitor system resources during tests:

```bash
# Terminal 1: Run the flood test
sudo router-flood --target 192.168.1.1 --port 80 --threads 8 --rate 800

# Terminal 2: Monitor system resources
htop

# Terminal 3: Monitor network traffic
sudo iftop -i eth0

# Terminal 4: Monitor target device (if accessible)
ping 192.168.1.1
```

## 📊 Understanding the Output

### Real-time Statistics

```
🚀 Starting Enhanced Router Flood Simulation
   Target: 192.168.1.1:80
   Threads: 4, Rate: 100 pps/thread
   Duration: 60 seconds
   Press Ctrl+C to stop gracefully

📊 Stats - Sent: 2048, Failed: 0, Rate: 341.3 pps, 2.7 Mbps
📊 Stats - Sent: 4096, Failed: 2, Rate: 409.6 pps, 3.3 Mbps
📊 Stats - Sent: 6144, Failed: 5, Rate: 409.6 pps, 3.3 Mbps
```

**Metrics Explanation:**
- **Sent**: Successfully transmitted packets
- **Failed**: Packets that couldn't be sent (usually due to rate limiting)
- **Rate (pps)**: Packets per second achieved
- **Mbps**: Megabits per second bandwidth utilization

### Performance Optimization

**High Performance Settings:**
```bash
# Maximum safe load test
sudo router-flood --target 192.168.1.1 --port 80 --threads 16 --rate 1000
```

**Conservative Testing:**
```bash
# Gentle stress test
sudo router-flood --target 192.168.1.1 --port 80 --threads 2 --rate 50
```

## 🔌 Plugin System

### Built-in Plugins

1. **HTTP Flood**: Realistic HTTP GET request simulation
2. **DNS Flood**: DNS query pattern with various record types
3. **SYN Flood**: TCP SYN flood with randomized parameters
4. **Stats Exporter**: JSON/CSV statistics export
5. **Network Monitor**: Real-time network condition monitoring

### Creating Custom Plugins

```rust
use crate::config::{AttackPatternPlugin, TargetConfig};
use std::collections::HashMap;

pub struct CustomFloodPattern {
    // Your custom fields
}

impl AttackPatternPlugin for CustomFloodPattern {
    fn name(&self) -> &str { "custom_flood" }
    
    fn description(&self) -> &str { "Custom flood pattern" }
    
    fn generate_packet(&mut self, target: &TargetConfig) -> Vec<u8> {
        // Your packet generation logic
        vec![]
    }
    
    fn configure(&mut self, config: &HashMap<String, serde_json::Value>) -> Result<(), String> {
        // Configuration logic
        Ok(())
    }
}
```

## 🔧 Troubleshooting

### Common Issues

**Permission Denied:**
```bash
Error: This program requires root privileges for raw socket access.
```
**Solution:** Run with `sudo` or as root user.

**Target Validation Error:**
```bash
❌ Security Error: Target IP 8.8.8.8 is not in private range.
```
**Solution:** Only use private IP addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x).

**High Failure Rate:**
```bash
📊 Stats - Sent: 100, Failed: 500, Rate: 20.0 pps, 0.2 Mbps
```
**Solution:** Reduce packet rate or thread count. Your network interface may be saturated.

### Performance Tuning

**System Limits:**
```bash
# Increase file descriptor limits
ulimit -n 65536

# Optimize network buffers
echo 'net.core.rmem_max = 26214400' >> /etc/sysctl.conf
echo 'net.core.rmem_default = 26214400' >> /etc/sysctl.conf
sudo sysctl -p
```

**Network Interface:**
```bash
# Check interface capacity
ethtool eth0

# Monitor interface statistics
cat /proc/net/dev
```

## 🛡️ Security Considerations

### Built-in Safety Mechanisms

1. **IP Range Validation**: Automatically blocks public IP targeting
2. **Rate Limiting**: Configurable maximum packet rates
3. **Thread Limiting**: Maximum concurrent task limits  
4. **Duration Control**: Automatic test timeouts
5. **Graceful Shutdown**: Proper cleanup on interruption

### Best Practices

- **Always** test in isolated environments first
- **Monitor** target device resources during testing
- **Document** all testing activities for compliance
- **Limit** test duration to prevent service disruption
- **Coordinate** with network administrators before testing

## 📈 Performance Metrics

### Benchmarks (Test Environment)

**Hardware:** Intel i7-9700K, 32GB RAM, Gigabit Ethernet
**Target:** Home router (Netgear R7000)

| Threads | Rate/Thread | Total PPS | Bandwidth | CPU Usage |
|---------|-------------|-----------|-----------|-----------|
| 4       | 100         | 400       | 3.2 Mbps  | 15%       |
| 8       | 200         | 1600      | 12.8 Mbps | 35%       |
| 16      | 500         | 8000      | 64 Mbps   | 75%       |

### Scaling Recommendations

- **Home Router Testing**: 2-4 threads, 50-200 pps/thread
- **Enterprise Equipment**: 8-16 threads, 200-1000 pps/thread  
- **High-End Hardware**: 16+ threads, 1000+ pps/thread

## 🧪 Testing Methodologies

### Baseline Establishment
1. **Normal Load Testing**: Establish baseline performance metrics
2. **Incremental Scaling**: Gradually increase load to find breaking points  
3. **Recovery Testing**: Verify service recovery after load removal

### Stress Testing Patterns
1. **Sustained Load**: Continuous moderate traffic
2. **Burst Testing**: Short high-intensity bursts
3. **Ramp Testing**: Gradually increasing load over time
4. **Mixed Protocol**: Combine UDP, TCP, and ICMP traffic

## 📚 Educational Resources

### Network Security Concepts
- **DDoS Attack Types**: Volumetric, Protocol, Application Layer
- **Mitigation Strategies**: Rate limiting, Traffic shaping, DPI
- **Network Forensics**: Packet analysis, Traffic pattern recognition

### Recommended Reading
- "Network Security Essentials" by William Stallings
- "DDoS Attacks and Defenses" by Ramin Sadre
- RFC 4987: TCP SYN Flooding Attacks and Common Mitigations

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup
```bash
git clone https://github.com/yourusername/router-flood.git
cd router-flood
cargo test
cargo clippy
cargo fmt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Disclaimer

This software is provided for educational and authorized testing purposes only. Users are solely responsible for complying with applicable laws and regulations. The authors disclaim any responsibility for misuse of this software.

**REMEMBER: Only test networks you own or have explicit written permission to test.**
