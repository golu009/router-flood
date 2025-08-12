# Router Flood

![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)
![Version](https://img.shields.io/badge/Version-0.0.1-green)
![Build](https://github.com/PaulShpilsher/router-flood/workflows/Rust/badge.svg)
![Tests](https://img.shields.io/badge/Tests-140%20Passing-brightgreen)
![Coverage](https://img.shields.io/badge/Coverage-Comprehensive-green)

**Router Flood** is an advanced educational network stress testing tool designed for controlled local network environments. It provides comprehensive multi-protocol simulation capabilities to help network administrators, security researchers, and students understand router behavior under various types of network stress, identify potential vulnerabilities, and evaluate mitigation strategies.

> ## ⚠️ IMPORTANT DISCLAIMER
>
> **This software is exclusively for educational and authorized testing purposes only.**
> 
> - Only use on networks you own or have explicit written permission to test
> - Unauthorized use against systems you don't control is strictly prohibited and may be illegal
> - The authors are not responsible for any misuse or damage caused by this tool
> - Always comply with local, national, and international laws regarding network testing

## ✨ Features

### Core Capabilities
- **🌐 Multi-Protocol Support**: Comprehensive simulation using UDP, TCP (SYN/ACK), ICMP, IPv6 (UDP/TCP/ICMP), and ARP protocols
- **📊 Advanced Traffic Patterns**: Configurable protocol ratios, packet size distributions, and burst patterns
- **🎯 Multi-Port Targeting**: Support for simultaneous testing across multiple target ports
- **⚡ Asynchronous Architecture**: High-performance tokio-based async runtime for concurrent packet generation

### Safety & Security
- **🔒 IP Range Validation**: Automatic validation against RFC 1918 private IP ranges only
- **🚦 Built-in Rate Limiting**: Hard-coded limits (max 100 threads, 10,000 PPS per thread)
- **📝 Comprehensive Audit Logging**: Session tracking with UUID-based identification
- **🔐 Privilege Management**: Root privilege detection with graceful degradation
- **🛡️ Multi-cast & Broadcast Protection**: Prevents targeting of loopback, multicast, or broadcast addresses

### Monitoring & Analytics
- **📈 Real-time Statistics**: Live performance metrics with configurable reporting intervals
- **🖥️ System Resource Monitoring**: CPU, memory, and network usage tracking
- **📁 Flexible Export Options**: JSON/CSV export with customizable formats and intervals
- **🎚️ Protocol Breakdown**: Detailed per-protocol packet statistics
- **📋 Session Management**: UUID-based session tracking for audit trails

### Operational Features
- **⚙️ YAML Configuration**: Comprehensive configuration file support with CLI overrides
- **🧪 Dry-Run Mode**: Safe testing without actual packet transmission
- **🔄 Multiple Burst Patterns**: Sustained, burst, and ramp-up traffic patterns
- **🛑 Graceful Shutdown**: Clean termination handling with final statistics
- **🌐 Interface Management**: Automatic interface detection with manual override options

## Installation

### Prerequisites

- Rust 1.70+ (with Cargo).
- Root privileges for raw socket access (skipped in dry-run mode).
- Linux/macOS (pnet library requires platform-specific features; tested on Linux).

### Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/paulshpilsher/router-flood.git
   cd router-flood
   ```

2. Build the binary:
   ```
   cargo build --release
   ```

3. The executable will be available at `target/release/router-flood`.

### Dependencies

The tool relies on the following production crates (managed via Cargo.toml):

- **Network & Packet Handling**: `pnet` (0.35.0) for low-level packet crafting and sending
- **Async Runtime**: `tokio` (1.38.0) with full features and signal handling
- **CLI & Configuration**: `clap` (4.5.4) with derive features, `serde` (1.0) with derive, `serde_yaml` (0.9), `config` (0.14)
- **Utilities**: `rand` (0.8.5), `chrono` (0.4) with serde, `uuid` (1.0) with v4 feature
- **Monitoring & Export**: `sysinfo` (0.31), `csv` (1.3), `serde_json` (1.0)
- **Logging**: `tracing` (0.1), `tracing-subscriber` (0.3) with env-filter, `log` (0.4), `env_logger` (0.11)
- **System Interface**: `libc` (0.2.155)

**Development Dependencies**: `tokio-test` (0.4), `tempfile` (3.8), `futures` (0.3)

## Usage

Run the tool with root privileges (e.g., `sudo`) unless using `--dry-run`.

### Basic Command

```
sudo ./target/release/router-flood --target <IP> --ports <PORTS>
```

### Command-Line Options

```
Router Flood - Enhanced Network Stress Tester

USAGE:
    router-flood [OPTIONS]

OPTIONS:
    -t, --target <IP>              Target router IP (must be private range, e.g., 192.168.1.1)
    -p, --ports <PORTS>            Target ports (comma-separated, e.g., 80,443,22)
        --threads <NUM>            Number of async tasks (default: 4, max: 100)
        --rate <PPS>               Packets per second per thread (default: 100, max: 10,000)
    -d, --duration <SECONDS>       Test duration in seconds (default: unlimited)
    -c, --config <FILE>            YAML configuration file path (default: router_flood_config.yaml)
    -i, --interface <NAME>         Network interface to use (default: auto-detect)
        --export <FORMAT>          Export statistics (json, csv, both)
        --list-interfaces          List available network interfaces
        --dry-run                  Simulate the attack without sending packets
    -h, --help                     Print help information
    -V, --version                  Print version information
```

### Examples

1. **Basic Simulation**:
   ```
   sudo ./target/release/router-flood --target 192.168.1.1 --ports 80,443 --threads 8 --rate 500 --duration 60
   ```

2. **Dry-Run for Testing**:
   ```
   ./target/release/router-flood --target 192.168.1.1 --ports 80 --dry-run
   ```

3. **With Config File and Export**:
   ```
   sudo ./target/release/router-flood --config custom_config.yaml --export json
   ```

4. **List Interfaces**:
   ```
   ./target/release/router-flood --list-interfaces
   ```

### Configuration File

Use a YAML file (default: `router_flood_config.yaml`) for advanced settings. CLI flags override config values.

Example `router_flood_config.yaml`:

```yaml
target:
  ip: "192.168.1.1"
  ports: [80, 443, 22, 53]
  protocol_mix:
    udp_ratio: 0.60      # 60% UDP packets
    tcp_syn_ratio: 0.25  # 25% TCP SYN packets  
    tcp_ack_ratio: 0.05  # 5% TCP ACK packets
    icmp_ratio: 0.05     # 5% ICMP packets
    ipv6_ratio: 0.03     # 3% IPv6 packets
    arp_ratio: 0.02      # 2% ARP packets
  interface: null        # Auto-detect interface

attack:
  threads: 8
  packet_rate: 500
  duration: 60
  packet_size_range: [64, 1400]
  burst_pattern: !Sustained    # Note: YAML tag format required
    rate: 500
  randomize_timing: true

safety:
  max_threads: 100
  max_packet_rate: 10000
  require_private_ranges: true
  enable_monitoring: true
  audit_logging: true
  dry_run: false

monitoring:
  stats_interval: 5
  system_monitoring: true
  export_interval: 30
  performance_tracking: true

export:
  enabled: true
  format: Both                    # Json, Csv, or Both
  filename_pattern: "router_flood"
  include_system_stats: true
```

## 🏗️ Architecture

### Module Structure

Router Flood is built with a modular architecture designed for maintainability and extensibility:

```
src/
├── main.rs           # Application entry point and orchestration
├── lib.rs            # Library interface and module exports
├── cli.rs            # Command-line argument parsing and validation
├── config.rs         # Configuration management and YAML parsing
├── simulation.rs     # High-level simulation orchestration
├── worker.rs         # Worker thread management and packet generation
├── packet.rs         # Multi-protocol packet construction
├── network.rs        # Network interface detection and management
├── target.rs         # Multi-port target management
├── stats.rs          # Statistics collection and export
├── monitor.rs        # System resource monitoring
├── validation.rs     # Security and safety validation
├── audit.rs          # Audit logging and session tracking
├── error.rs          # Comprehensive error handling
└── constants.rs      # Application constants and defaults
```

### Core Components

1. **Simulation Controller**: Orchestrates the entire testing lifecycle
2. **Worker Manager**: Manages concurrent packet generation threads
3. **Packet Builder**: Constructs realistic multi-protocol packets
4. **Stats Engine**: Provides real-time monitoring and export capabilities
5. **Validation Layer**: Ensures safe and ethical usage
6. **Audit System**: Maintains comprehensive session logs

### Packet Generation Flow

1. Configuration validation and target IP verification
2. Network interface setup and channel creation
3. Worker thread spawning with rate limiting
4. Randomized packet type selection based on protocol mix
5. Realistic packet construction with variable sizes
6. Transport layer transmission or dry-run simulation
7. Real-time statistics collection and reporting

## 📊 Output and Monitoring

### Real-time Statistics
- **Performance Metrics**: Packets sent, failed, rate (PPS/Mbps)
- **Protocol Breakdown**: Per-protocol packet counts and percentages
- **System Resources**: CPU usage, memory consumption
- **Network Interface**: Traffic statistics and interface status

### Export Formats

**JSON Export Example:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-01-12T16:44:28Z",
  "packets_sent": 15420,
  "packets_failed": 23,
  "bytes_sent": 18504000,
  "duration_secs": 60.0,
  "packets_per_second": 257.0,
  "megabits_per_second": 2.47,
  "protocol_breakdown": {
    "UDP": 9252,
    "TCP": 3855,
    "ICMP": 771,
    "IPv6": 462,
    "ARP": 308
  },
  "system_stats": {
    "cpu_usage": 15.2,
    "memory_usage": 52428800,
    "memory_total": 8589934592
  }
}
```

**CSV Export**: Tabular format suitable for spreadsheet analysis and visualization

### Audit Logging
- Session tracking with unique UUIDs
- Complete parameter logging for accountability
- Timestamped entries for forensic analysis
- JSON format for easy parsing and integration

## 🔧 Advanced Configuration

### Burst Patterns

**Sustained Pattern** (Constant Load):
```yaml
burst_pattern: !Sustained
  rate: 500  # Constant 500 PPS
```

**Burst Pattern** (Intermittent High Load):
```yaml
burst_pattern: !Bursts
  burst_size: 50        # 50 packets per burst
  burst_interval_ms: 1000  # Every 1 second
```

**Ramp Pattern** (Gradual Increase):
```yaml
burst_pattern: !Ramp
  start_rate: 100    # Begin at 100 PPS
  end_rate: 1000     # Ramp up to 1000 PPS
  ramp_duration: 60  # Over 60 seconds
```

> **Note**: YAML enum serialization requires explicit tags (!) for proper parsing.

### Protocol Mix Tuning

Customize traffic composition for specific testing scenarios:

**Web Traffic Simulation**:
```yaml
protocol_mix:
  udp_ratio: 0.1      # DNS queries
  tcp_syn_ratio: 0.7  # HTTP requests
  tcp_ack_ratio: 0.15 # Response acknowledgments
  icmp_ratio: 0.03    # Network diagnostics
  ipv6_ratio: 0.02    # Modern web traffic
  arp_ratio: 0.0      # Minimal L2 traffic
```

**Network Discovery Simulation**:
```yaml
protocol_mix:
  udp_ratio: 0.3      # Service discovery
  tcp_syn_ratio: 0.2  # Port scanning
  tcp_ack_ratio: 0.05 # Established connections
  icmp_ratio: 0.2     # Ping sweeps
  ipv6_ratio: 0.15    # IPv6 discovery
  arp_ratio: 0.1      # Network mapping
```

### Performance Tuning

**High-Performance Configuration** (for powerful systems):
```yaml
attack:
  threads: 16
  packet_rate: 2000
  packet_size_range: [64, 1400]
  randomize_timing: false  # Consistent timing for max throughput

monitoring:
  stats_interval: 1        # More frequent reporting
  export_interval: 30      # Regular exports
```

**Conservative Configuration** (for limited systems or careful testing):
```yaml
attack:
  threads: 2
  packet_rate: 50
  packet_size_range: [64, 512]
  randomize_timing: true

safety:
  max_threads: 4          # Lower limits
  max_packet_rate: 200
```

## 🔄 Continuous Integration & Deployment

### GitHub Actions Workflow

Router Flood uses GitHub Actions for automated testing and quality assurance:

**Workflow Configuration** (`.github/workflows/rust.yml`):
- **Triggers**: Pushes and Pull Requests to `main` branch
- **Environment**: Ubuntu Latest with Rust toolchain
- **Steps**: Build verification and comprehensive test execution

**Automated Checks:**
- ✅ **Build Verification**: `cargo build --verbose` ensures compilation success
- ✅ **Test Execution**: `cargo test --verbose` runs all 140 tests
- ✅ **Cross-platform**: Tested on Ubuntu (Linux environment)
- ✅ **Dependency Validation**: Automatic dependency resolution and caching

**Build Status**: ![Build Status](https://github.com/PaulShpilsher/router-flood/workflows/Rust/badge.svg)

**Workflow Triggers:**
```yaml
on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]
```

**Quality Gates:**
- All 140 tests must pass before merge
- Build must complete successfully on Ubuntu
- No compilation errors or warnings allowed
- Comprehensive test coverage verification

### Local Development Integration

The CI/CD pipeline mirrors local development practices:

```bash
# Same commands used in CI
cargo build --verbose    # Build verification
cargo test --verbose     # Full test suite
```

**Benefits:**
- **Early Detection**: Issues caught before merge
- **Consistent Quality**: Same standards across all contributions
- **Automated Testing**: No manual test execution required
- **Build Confidence**: Green builds indicate stable code

## 🧪 Testing & Development

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test modules
cargo test cli_tests
cargo test validation_tests
cargo test packet_tests

# Run tests with output
cargo test -- --nocapture

# Run integration tests
cargo test --test integration_tests
```

### Test Coverage

The project includes **140 comprehensive tests** across 14 test modules:

- ✅ **Audit Tests** (12): Session tracking, logging, and audit trail functionality
- ✅ **CLI Tests** (9): Command-line argument parsing and validation
- ✅ **Config Tests** (10): YAML configuration loading, merging, and validation
- ✅ **Error Tests** (21): Comprehensive error handling and propagation
- ✅ **Integration Tests** (10): End-to-end system integration scenarios
- ✅ **Main Tests** (7): Application entry point and core functionality
- ✅ **Monitor Tests** (10): System resource monitoring and statistics
- ✅ **Network Tests** (10): Network interface detection and management
- ✅ **Packet Tests** (3): Multi-protocol packet construction and validation
- ✅ **Simulation Tests** (8): High-level simulation orchestration
- ✅ **Stats Tests** (13): Statistics collection, export, and analysis
- ✅ **Target Tests** (11): Multi-port target management and rotation
- ✅ **Validation Tests** (10): Security validation and safety checks
- ✅ **Worker Tests** (6): Worker thread management and rate limiting

**Coverage Areas:**
- 🔧 Configuration parsing and validation (YAML and CLI)
- 🛡️ Security validation (IP ranges, safety limits, privilege checks)
- 📦 Multi-protocol packet generation (UDP, TCP, ICMP, IPv6, ARP)
- 📊 Statistics collection and export (JSON, CSV formats)
- 🔄 Concurrent worker management and rate limiting
- 🌐 Network interface discovery and management
- 📝 Audit logging and session tracking
- ❌ Error handling and graceful degradation
- 🧪 Integration scenarios and edge cases

### Debugging and Development

**Enable detailed logging**:
```bash
RUST_LOG=debug ./target/release/router-flood --dry-run --target 192.168.1.1 --ports 80
```

**Trace-level debugging**:
```bash
RUST_LOG=trace ./target/release/router-flood --dry-run --target 192.168.1.1 --ports 80
```

## 🔍 Troubleshooting

### Common Issues

**Permission Errors**
```
Error: This program requires root privileges for raw socket access
```
**Solution**: Run with `sudo` or use `--dry-run` for testing

**Network Interface Issues**
```
Error: Network interface not found
```
**Solutions**:
- Use `--list-interfaces` to see available interfaces
- Specify interface manually: `--interface eth0`
- Check interface is up: `ip link show`

**Target Validation Failures**
```
Error: Target IP must be in private range for safety
```
**Solutions**:
- Use private IPs: 192.168.x.x, 10.x.x.x, or 172.16-31.x.x
- For testing: use `192.168.1.1` or configure in YAML

**High Resource Usage**
```
Warning: High CPU usage detected
```
**Solutions**:
- Reduce thread count: `--threads 4`
- Lower packet rate: `--rate 100`
- Enable timing jitter: `randomize_timing: true`

### Performance Optimization

**System Tuning**:
```bash
# Increase file descriptor limits
ulimit -n 65536

# Increase network buffer sizes
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Monitoring System Impact**:
```bash
# Monitor CPU usage
htop

# Monitor network interfaces
watch -n 1 'cat /proc/net/dev'

# Check memory usage
free -h
```

### Validation Checklist

Before running tests, ensure:
- ☐ Target IP is in private range
- ☐ Network interface is available and up
- ☐ Sufficient system resources (CPU, memory, file descriptors)
- ☐ Root privileges (unless using dry-run)
- ☐ Firewall allows raw socket access
- ☐ No conflicting network tools running

### Getting Help

1. **Check logs**: Enable debug logging with `RUST_LOG=debug`
2. **Validate configuration**: Use `--dry-run` to test without impact
3. **Check system resources**: Monitor CPU, memory, and network usage
4. **Review audit logs**: Check `router_flood_audit.log` for session details
5. **Consult documentation**: Review configuration examples and error messages

For persistent issues, please open an issue on GitHub with:
- System information (OS, Rust version)
- Complete command line used
- Configuration file (if applicable)
- Error messages and logs
- Steps to reproduce

## Safety and Ethical Considerations

- **🏠 Private Networks Only**: Targets are validated against RFC 1918 private ranges
- **⏱️ Built-in Limits**: Hard-coded caps on threads and rates to prevent system overwhelm
- **🧪 Safe Testing**: Dry-run mode for configuration validation without network impact
- **📋 Audit Trail**: Comprehensive logging for accountability and forensic analysis
- **🛡️ Ethical Usage**: Tool designed with safety mechanisms to prevent misuse

**Remember**: This tool is designed for educational purposes and authorized testing only. Always obtain explicit permission before testing any network infrastructure.

If you encounter issues or need to report misuse, open an issue on GitHub.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit changes (`git commit -m 'Add YourFeature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a Pull Request.

Ensure code follows Rust idioms and includes tests where possible.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
