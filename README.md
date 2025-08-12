# Router Flood

![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)
![Version](https://img.shields.io/badge/Version-2.0.0-green)

**Router Flood** is an educational tool designed for simulating DDoS attacks in controlled local network environments. It helps network administrators and security researchers understand router behavior under stress, identify potential vulnerabilities, and test mitigation strategies. This tool implements multiple protocols, safety checks, and monitoring features to ensure responsible usage.

> ## Disclaimer
>
> - The software is for educational and authorized testing purposes only.
> - Unauthorized use (especially against systems you don't own or lack explicit permission to test) is strictly prohibited and may be illegal.

## Features

- **Multi-Protocol Support**: Simulates traffic using UDP, TCP (SYN/ACK), ICMP, IPv6 (UDP/TCP/ICMP), and ARP protocols with configurable ratios.
- **Safety Mechanisms**:
  - Validates targets against private IP ranges only.
  - Enforces thread and packet rate limits (max 100 threads, 10,000 PPS).
  - Comprehensive audit logging for all sessions.
  - System requirement checks (e.g., root privileges for raw sockets).
- **Performance Monitoring**: Real-time statistics, system resource tracking (CPU, memory), and optional exports to JSON/CSV.
- **Configuration Flexibility**: YAML-based config file for easy customization, with CLI overrides.
- **Dry-Run Mode**: Simulate attacks without sending packets for safe configuration testing.
- **Burst Patterns**: Supports sustained, burst, or ramp-up traffic patterns.
- **Graceful Shutdown**: Handles Ctrl+C and duration limits with final stats reporting.

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

The tool relies on the following crates (managed via Cargo.toml):

- `pnet`: For low-level packet crafting and sending.
- `rand`: Random number generation for packet variation.
- `clap`: Command-line argument parsing.
- `tokio`: Asynchronous runtime for concurrent tasks.
- `serde` & `serde_yaml`: Configuration serialization.
- `log` & `env_logger`: Logging.
- `chrono`: Timestamp handling.
- `csv`: CSV export.
- `sysinfo`: System monitoring.
- `tracing`: Enhanced logging.
- `config`: Configuration management.
- `uuid`: Session ID generation.

For development: `tokio-test`, `tempfile`.

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
  ports: [80, 443]
  protocol_mix:
    udp_ratio: 0.6
    tcp_syn_ratio: 0.25
    tcp_ack_ratio: 0.05
    icmp_ratio: 0.05
    ipv6_ratio: 0.03
    arp_ratio: 0.02
  interface: "eth0"

attack:
  threads: 4
  packet_rate: 100
  duration: 300
  packet_size_range: [20, 1400]
  burst_pattern:
    Sustained:
      rate: 100
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
  export_interval: 60
  performance_tracking: true

export:
  enabled: true
  format: Json
  filename_pattern: "router_flood"
  include_system_stats: true
```

## Output and Monitoring

- **Real-Time Stats**: Printed every 5 seconds (configurable), including packets sent, failed, rate (PPS/Mbps), and protocol breakdown.
- **System Stats**: CPU and memory usage (if enabled).
- **Exports**: Saved to `exports/` directory as JSON/CSV files with session details.
- **Audit Logs**: JSON entries appended to `router_flood_audit.log` for each session.

## Safety and Ethical Considerations

- **Private Networks Only**: Targets are validated against RFC 1918 private ranges.
- **Limits**: Hard-coded caps on threads and rates to prevent overwhelming systems.
- **Dry-Run**: Ideal for validating configs without risk.
- **Logging**: All actions are audited for accountability.

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
