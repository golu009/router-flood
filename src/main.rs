//! Router Flood - Enhanced Educational DDoS Simulation Tool
//! 
//! This tool is designed for educational purposes and authorized security testing only.
//! It implements multiple safety mechanisms to prevent misuse:
//! - Private IP validation (only allows 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
//! - Rate limiting and thread count restrictions
//! - Comprehensive audit logging
//! - System requirement validation
//! - Network interface validation
//! 
//! WARNING: Only use on networks you own or have explicit permission to test.
//! Unauthorized use is illegal and unethical.

use clap::{Arg, Command};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::icmp::{MutableIcmpPacket, IcmpTypes};
use pnet::packet::arp::{MutableArpPacket, ArpOperations, ArpHardwareTypes};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet::packet::MutablePacket;
use pnet::transport::{self};
use pnet::util::MacAddr;
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::Mutex;
use tokio::time;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::fs::OpenOptions;
use std::io::Write;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug, trace};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use sysinfo::System;
use csv::Writer;
use uuid::Uuid;
use std::path::Path;
use std::collections::HashMap;

// Enhanced security configuration
const MAX_THREADS: usize = 100;
const MAX_PACKET_RATE: u64 = 10000;
const DEFAULT_BURST_SIZE: usize = 10;
const MAX_PAYLOAD_SIZE: usize = 1400;
const MIN_PAYLOAD_SIZE: usize = 20;
const AUDIT_LOG_FILE: &str = "router_flood_audit.log";
const CONFIG_FILE: &str = "router_flood_config.yaml";
const STATS_EXPORT_DIR: &str = "exports";

// Private IP ranges for validation (network, mask)
const PRIVATE_RANGES: &[(u32, u32)] = &[
    (0xC0A80000, 0xFFFF0000), // 192.168.0.0/16
    (0x0A000000, 0xFF000000), // 10.0.0.0/8
    (0xAC100000, 0xFFF00000), // 172.16.0.0/12
];

/// Configuration structures for YAML config file support
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub target: TargetConfig,
    pub attack: AttackConfig,
    pub safety: SafetyConfig,
    pub monitoring: MonitoringConfig,
    pub export: ExportConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TargetConfig {
    pub ip: String,
    pub ports: Vec<u16>,
    pub protocol_mix: ProtocolMix,
    pub interface: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtocolMix {
    pub udp_ratio: f64,
    pub tcp_syn_ratio: f64,
    pub tcp_ack_ratio: f64,
    pub icmp_ratio: f64,
    pub ipv6_ratio: f64,
    pub arp_ratio: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttackConfig {
    pub threads: usize,
    pub packet_rate: u64,
    pub duration: Option<u64>,
    pub packet_size_range: (usize, usize),
    pub burst_pattern: BurstPattern,
    pub randomize_timing: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SafetyConfig {
    pub max_threads: usize,
    pub max_packet_rate: u64,
    pub require_private_ranges: bool,
    pub enable_monitoring: bool,
    pub audit_logging: bool,
    pub dry_run: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitoringConfig {
    pub stats_interval: u64,
    pub system_monitoring: bool,
    pub export_interval: Option<u64>,
    pub performance_tracking: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportConfig {
    pub enabled: bool,
    pub format: ExportFormat,
    pub filename_pattern: String,
    pub include_system_stats: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ExportFormat {
    Json,
    Csv,
    Both,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum BurstPattern {
    Sustained { rate: u64 },
    Bursts { burst_size: usize, burst_interval_ms: u64 },
    Ramp { start_rate: u64, end_rate: u64, ramp_duration: u64 },
}

/// Enhanced statistics tracking with export capabilities
#[derive(Default)]
pub struct FloodStats {
    packets_sent: AtomicU64,
    packets_failed: AtomicU64,
    bytes_sent: AtomicU64,
    start_time: Option<Instant>,
    session_id: String,
    protocol_stats: HashMap<String, AtomicU64>,
    export_config: Option<ExportConfig>,
}

#[derive(Debug, Serialize)]
pub struct SessionStats {
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub packets_sent: u64,
    pub packets_failed: u64,
    pub bytes_sent: u64,
    pub duration_secs: f64,
    pub packets_per_second: f64,
    pub megabits_per_second: f64,
    pub protocol_breakdown: HashMap<String, u64>,
    pub system_stats: Option<SystemStats>,
}

#[derive(Debug, Serialize, Clone)]
pub struct SystemStats {
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub memory_total: u64,
    pub network_sent: u64,
    pub network_received: u64,
}

impl FloodStats {
    fn new(export_config: Option<ExportConfig>) -> Self {
        let mut protocol_stats = HashMap::new();
        protocol_stats.insert("UDP".to_string(), AtomicU64::new(0));
        protocol_stats.insert("TCP".to_string(), AtomicU64::new(0));
        protocol_stats.insert("ICMP".to_string(), AtomicU64::new(0));
        protocol_stats.insert("IPv6".to_string(), AtomicU64::new(0));
        protocol_stats.insert("ARP".to_string(), AtomicU64::new(0));
        
        Self {
            start_time: Some(Instant::now()),
            session_id: Uuid::new_v4().to_string(),
            protocol_stats,
            export_config,
            ..Default::default()
        }
    }

    fn increment_sent(&self, bytes: u64, protocol: &str) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        
        if let Some(counter) = self.protocol_stats.get(protocol) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn increment_failed(&self) {
        self.packets_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn print_stats(&self, system_stats: Option<&SystemStats>) {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let failed = self.packets_failed.load(Ordering::Relaxed);
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        
        if let Some(start) = &self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            let pps = sent as f64 / elapsed;
            let mbps = (bytes as f64 * 8.0) / (elapsed * 1_000_000.0);
            
            println!("📊 Stats - Sent: {}, Failed: {}, Rate: {:.1} pps, {:.2} Mbps", 
                     sent, failed, pps, mbps);
            
            // Protocol breakdown
            for (protocol, counter) in &self.protocol_stats {
                let count = counter.load(Ordering::Relaxed);
                if count > 0 {
                    println!("   {}: {} packets", protocol, count);
                }
            }
            
            // System stats if available
            if let Some(sys_stats) = system_stats {
                println!("   System: CPU {:.1}%, Memory: {:.1} MB", 
                         sys_stats.cpu_usage, 
                         sys_stats.memory_usage / 1024 / 1024);
            }
        }
    }

    async fn export_stats(&self, system_stats: Option<&SystemStats>) -> Result<(), String> {
        if let Some(export_config) = &self.export_config {
            if !export_config.enabled {
                return Ok(());
            }

            let stats = self.get_session_stats(system_stats);
            
            // Ensure export directory exists
            std::fs::create_dir_all(STATS_EXPORT_DIR).map_err(|e| format!("Failed to create export directory: {}", e))?;
            
            match export_config.format {
                ExportFormat::Json => {
                    self.export_json(&stats, export_config).await?;
                }
                ExportFormat::Csv => {
                    self.export_csv(&stats, export_config).await?;
                }
                ExportFormat::Both => {
                    self.export_json(&stats, export_config).await?;
                    self.export_csv(&stats, export_config).await?;
                }
            }
        }
        Ok(())
    }

    fn get_session_stats(&self, system_stats: Option<&SystemStats>) -> SessionStats {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let failed = self.packets_failed.load(Ordering::Relaxed);
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        
        let (duration, pps, mbps) = if let Some(start) = &self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            let pps = sent as f64 / elapsed;
            let mbps = (bytes as f64 * 8.0) / (elapsed * 1_000_000.0);
            (elapsed, pps, mbps)
        } else {
            (0.0, 0.0, 0.0)
        };

        let protocol_breakdown: HashMap<String, u64> = self.protocol_stats
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        SessionStats {
            session_id: self.session_id.clone(),
            timestamp: Utc::now(),
            packets_sent: sent,
            packets_failed: failed,
            bytes_sent: bytes,
            duration_secs: duration,
            packets_per_second: pps,
            megabits_per_second: mbps,
            protocol_breakdown,
            system_stats: system_stats.cloned(),
        }
    }

    async fn export_json(&self, stats: &SessionStats, config: &ExportConfig) -> Result<(), String> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("{}/{}_stats_{}.json", STATS_EXPORT_DIR, config.filename_pattern, timestamp);
        
        let json = serde_json::to_string_pretty(stats)
            .map_err(|e| format!("Failed to serialize stats: {}", e))?;
            
        tokio::fs::write(&filename, json)
            .await
            .map_err(|e| format!("Failed to write JSON stats: {}", e))?;
            
        info!("Stats exported to {}", filename);
        Ok(())
    }

    async fn export_csv(&self, stats: &SessionStats, config: &ExportConfig) -> Result<(), String> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("{}/{}_stats_{}.csv", STATS_EXPORT_DIR, config.filename_pattern, timestamp);
        
        let file = std::fs::File::create(&filename)
            .map_err(|e| format!("Failed to create CSV file: {}", e))?;
            
        let mut writer = Writer::from_writer(file);
        
        // Write header
        writer.write_record(&[
            "session_id", "timestamp", "packets_sent", "packets_failed", "bytes_sent",
            "duration_secs", "packets_per_second", "megabits_per_second",
            "udp_packets", "tcp_packets", "icmp_packets", "ipv6_packets", "arp_packets"
        ]).map_err(|e| format!("Failed to write CSV header: {}", e))?;
        
        // Write data
        writer.write_record(&[
            &stats.session_id,
            &stats.timestamp.to_rfc3339(),
            &stats.packets_sent.to_string(),
            &stats.packets_failed.to_string(),
            &stats.bytes_sent.to_string(),
            &stats.duration_secs.to_string(),
            &stats.packets_per_second.to_string(),
            &stats.megabits_per_second.to_string(),
            &stats.protocol_breakdown.get("UDP").unwrap_or(&0).to_string(),
            &stats.protocol_breakdown.get("TCP").unwrap_or(&0).to_string(),
            &stats.protocol_breakdown.get("ICMP").unwrap_or(&0).to_string(),
            &stats.protocol_breakdown.get("IPv6").unwrap_or(&0).to_string(),
            &stats.protocol_breakdown.get("ARP").unwrap_or(&0).to_string(),
        ]).map_err(|e| format!("Failed to write CSV data: {}", e))?;
        
        writer.flush().map_err(|e| format!("Failed to flush CSV: {}", e))?;
        info!("Stats exported to {}", filename);
        Ok(())
    }
}

/// Supported packet types for enhanced flood simulation
#[derive(Debug, Clone, Copy)]
pub enum PacketType {
    Udp,
    TcpSyn,
    TcpAck,
    Icmp,
    Ipv6Udp,
    Ipv6Tcp,
    Ipv6Icmp,
    Arp,
}

/// Enhanced packet builder with multiple protocol support and realistic traffic patterns
pub struct PacketBuilder {
    rng: StdRng,
    source_ip: Ipv4Addr,
    source_ipv6: Ipv6Addr,
    source_mac: MacAddr,
    burst_counter: usize,
    last_protocol: u8,
    packet_size_range: (usize, usize),
    protocol_mix: ProtocolMix,
}

impl PacketBuilder {
    fn new(packet_size_range: (usize, usize), protocol_mix: ProtocolMix) -> Self {
        let mut rng = StdRng::from_entropy();
        let source_ip = Ipv4Addr::new(192, 168, 1, rng.gen_range(2..254));
        let source_ipv6 = Ipv6Addr::new(
            0xfe80, 0, 0, 0,
            rng.gen(), rng.gen(), rng.gen(), rng.gen()
        );
        let source_mac = MacAddr::new(
            0x02, rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen()
        );
        
        Self { 
            rng, 
            source_ip,
            source_ipv6,
            source_mac,
            burst_counter: 0,
            last_protocol: 0,
            packet_size_range,
            protocol_mix,
        }
    }

    fn next_packet_type(&mut self) -> PacketType {
        let rand_val = self.rng.gen::<f64>();
        let mut cumulative = 0.0;
        
        cumulative += self.protocol_mix.udp_ratio;
        if rand_val < cumulative { return PacketType::Udp; }
        
        cumulative += self.protocol_mix.tcp_syn_ratio;
        if rand_val < cumulative { return PacketType::TcpSyn; }
        
        cumulative += self.protocol_mix.tcp_ack_ratio;
        if rand_val < cumulative { return PacketType::TcpAck; }
        
        cumulative += self.protocol_mix.icmp_ratio;
        if rand_val < cumulative { return PacketType::Icmp; }
        
        cumulative += self.protocol_mix.ipv6_ratio;
        if rand_val < cumulative {
            match self.rng.gen_range(0..3) {
                0 => return PacketType::Ipv6Udp,
                1 => return PacketType::Ipv6Tcp,
                _ => return PacketType::Ipv6Icmp,
            }
        }
        
        PacketType::Arp
    }

    fn random_payload_size(&mut self) -> usize {
        // More realistic payload size distribution
        match self.rng.gen_range(0..100) {
            0..=40 => self.rng.gen_range(self.packet_size_range.0..=200),  // Small packets
            41..=80 => self.rng.gen_range(200..=800),                      // Medium packets
            _ => self.rng.gen_range(800..=self.packet_size_range.1),       // Large packets
        }
    }

    fn build_packet(&mut self, packet_type: PacketType, target_ip: IpAddr, target_port: u16) -> Result<(Vec<u8>, &'static str), String> {
        match packet_type {
            PacketType::Udp => {
                if let IpAddr::V4(ipv4) = target_ip {
                    Ok((self.build_udp_packet(ipv4, target_port)?, "UDP"))
                } else {
                    Err("UDP packet requires IPv4 target".to_string())
                }
            },
            PacketType::TcpSyn => {
                if let IpAddr::V4(ipv4) = target_ip {
                    Ok((self.build_tcp_packet(ipv4, target_port, TcpFlags::SYN)?, "TCP"))
                } else {
                    Err("TCP SYN packet requires IPv4 target".to_string())
                }
            },
            PacketType::TcpAck => {
                if let IpAddr::V4(ipv4) = target_ip {
                    Ok((self.build_tcp_packet(ipv4, target_port, TcpFlags::ACK)?, "TCP"))
                } else {
                    Err("TCP ACK packet requires IPv4 target".to_string())
                }
            },
            PacketType::Icmp => {
                if let IpAddr::V4(ipv4) = target_ip {
                    Ok((self.build_icmp_packet(ipv4)?, "ICMP"))
                } else {
                    Err("ICMP packet requires IPv4 target".to_string())
                }
            },
            PacketType::Ipv6Udp => {
                if let IpAddr::V6(ipv6) = target_ip {
                    Ok((self.build_ipv6_udp_packet(ipv6, target_port)?, "IPv6"))
                } else {
                    Err("IPv6 UDP packet requires IPv6 target".to_string())
                }
            },
            PacketType::Ipv6Tcp => {
                if let IpAddr::V6(ipv6) = target_ip {
                    Ok((self.build_ipv6_tcp_packet(ipv6, target_port)?, "IPv6"))
                } else {
                    Err("IPv6 TCP packet requires IPv6 target".to_string())
                }
            },
            PacketType::Ipv6Icmp => {
                if let IpAddr::V6(ipv6) = target_ip {
                    Ok((self.build_ipv6_icmp_packet(ipv6)?, "IPv6"))
                } else {
                    Err("IPv6 ICMP packet requires IPv6 target".to_string())
                }
            },
            PacketType::Arp => {
                if let IpAddr::V4(ipv4) = target_ip {
                    Ok((self.build_arp_packet(ipv4)?, "ARP"))
                } else {
                    Err("ARP packet requires IPv4 target".to_string())
                }
            },
        }
    }

    fn build_udp_packet(&mut self, target_ip: Ipv4Addr, target_port: u16) -> Result<Vec<u8>, String> {
        let payload_size = self.random_payload_size();
        let total_len = 20 + 8 + payload_size; // IP + UDP + payload
        let mut packet_buf = vec![0u8; total_len];

        // Build IP header
        let mut ip_packet = MutableIpv4Packet::new(&mut packet_buf).unwrap();
        self.setup_ip_header(&mut ip_packet, total_len, IpNextHeaderProtocols::Udp, target_ip);

        // Build UDP header + payload
        let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut()).unwrap();
        udp_packet.set_source(self.rng.gen_range(1024..65535));
        udp_packet.set_destination(target_port);
        udp_packet.set_length((8 + payload_size) as u16);
        
        let payload: Vec<u8> = (0..payload_size).map(|_| self.rng.gen()).collect();
        udp_packet.set_payload(&payload);
        udp_packet.set_checksum(pnet::packet::udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            &self.source_ip,
            &target_ip,
        ));

        // Set IP checksum last
        ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
        Ok(packet_buf)
    }

    fn build_tcp_packet(&mut self, target_ip: Ipv4Addr, target_port: u16, flags: u8) -> Result<Vec<u8>, String> {
        let total_len = 20 + 20; // IP + TCP (no payload for SYN/ACK)
        let mut packet_buf = vec![0u8; total_len];

        // Build IP header
        let mut ip_packet = MutableIpv4Packet::new(&mut packet_buf).unwrap();
        self.setup_ip_header(&mut ip_packet, total_len, IpNextHeaderProtocols::Tcp, target_ip);

        // Build TCP packet
        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_source(self.rng.gen_range(1024..65535));
        tcp_packet.set_destination(target_port);
        tcp_packet.set_sequence(self.rng.gen());
        tcp_packet.set_acknowledgement(if flags == TcpFlags::ACK { self.rng.gen() } else { 0 });
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(self.rng.gen_range(1024..65535));
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_checksum(pnet::packet::tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &self.source_ip,
            &target_ip,
        ));

        // Set IP checksum last
        ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
        Ok(packet_buf)
    }

    fn build_icmp_packet(&mut self, target_ip: Ipv4Addr) -> Result<Vec<u8>, String> {
        let payload_size = self.rng.gen_range(8..=56); // Standard ping sizes
        let total_len = 20 + 8 + payload_size; // IP + ICMP + payload
        let mut packet_buf = vec![0u8; total_len];

        // Build IP header
        let mut ip_packet = MutableIpv4Packet::new(&mut packet_buf).unwrap();
        self.setup_ip_header(&mut ip_packet, total_len, IpNextHeaderProtocols::Icmp, target_ip);

        // Build ICMP packet
        let mut icmp_packet = MutableIcmpPacket::new(ip_packet.payload_mut()).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
        icmp_packet.set_checksum(0);
        
        // Add payload
        let payload: Vec<u8> = (0..payload_size).map(|_| self.rng.gen()).collect();
        icmp_packet.set_payload(&payload);
        
        // Calculate and set ICMP checksum
        let checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
        icmp_packet.set_checksum(checksum);

        // Set IP checksum last
        ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
        Ok(packet_buf)
    }

    fn build_ipv6_udp_packet(&mut self, target_ip: Ipv6Addr, target_port: u16) -> Result<Vec<u8>, String> {
        let payload_size = self.random_payload_size();
        let total_len = 40 + 8 + payload_size; // IPv6 + UDP + payload
        let mut packet_buf = vec![0u8; total_len];

        // Build IPv6 header
        let mut ip_packet = MutableIpv6Packet::new(&mut packet_buf).unwrap();
        ip_packet.set_version(6);
        ip_packet.set_traffic_class(0);
        ip_packet.set_flow_label(self.rng.gen::<u32>() & 0xFFFFF);
        ip_packet.set_payload_length((8 + payload_size) as u16);
        ip_packet.set_next_header(IpNextHeaderProtocols::Udp);
        ip_packet.set_hop_limit(self.rng.gen_range(32..128));
        ip_packet.set_source(self.source_ipv6);
        ip_packet.set_destination(target_ip);

        // Build UDP header + payload
        let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut()).unwrap();
        udp_packet.set_source(self.rng.gen_range(1024..65535));
        udp_packet.set_destination(target_port);
        udp_packet.set_length((8 + payload_size) as u16);
        
        let payload: Vec<u8> = (0..payload_size).map(|_| self.rng.gen()).collect();
        udp_packet.set_payload(&payload);
        udp_packet.set_checksum(pnet::packet::udp::ipv6_checksum(
            &udp_packet.to_immutable(),
            &self.source_ipv6,
            &target_ip,
        ));

        Ok(packet_buf)
    }

    fn build_ipv6_tcp_packet(&mut self, target_ip: Ipv6Addr, target_port: u16) -> Result<Vec<u8>, String> {
        let total_len = 40 + 20; // IPv6 + TCP
        let mut packet_buf = vec![0u8; total_len];

        // Build IPv6 header
        let mut ip_packet = MutableIpv6Packet::new(&mut packet_buf).unwrap();
        ip_packet.set_version(6);
        ip_packet.set_traffic_class(0);
        ip_packet.set_flow_label(self.rng.gen::<u32>() & 0xFFFFF);
        ip_packet.set_payload_length(20);
        ip_packet.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_packet.set_hop_limit(self.rng.gen_range(32..128));
        ip_packet.set_source(self.source_ipv6);
        ip_packet.set_destination(target_ip);

        // Build TCP packet
        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_source(self.rng.gen_range(1024..65535));
        tcp_packet.set_destination(target_port);
        tcp_packet.set_sequence(self.rng.gen());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(self.rng.gen_range(1024..65535));
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_checksum(pnet::packet::tcp::ipv6_checksum(
            &tcp_packet.to_immutable(),
            &self.source_ipv6,
            &target_ip,
        ));

        Ok(packet_buf)
    }

    fn build_ipv6_icmp_packet(&mut self, target_ip: Ipv6Addr) -> Result<Vec<u8>, String> {
        let payload_size = self.rng.gen_range(8..=56);
        let total_len = 40 + 8 + payload_size; // IPv6 + ICMPv6 + payload
        let mut packet_buf = vec![0u8; total_len];

        // Build IPv6 header
        let mut ip_packet = MutableIpv6Packet::new(&mut packet_buf).unwrap();
        ip_packet.set_version(6);
        ip_packet.set_traffic_class(0);
        ip_packet.set_flow_label(self.rng.gen::<u32>() & 0xFFFFF);
        ip_packet.set_payload_length((8 + payload_size) as u16);
        ip_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ip_packet.set_hop_limit(self.rng.gen_range(32..128));
        ip_packet.set_source(self.source_ipv6);
        ip_packet.set_destination(target_ip);

        // Build ICMPv6 packet (simplified - using ICMP structure)
        let mut icmp_packet = MutableIcmpPacket::new(ip_packet.payload_mut()).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
        icmp_packet.set_checksum(0);
        
        let payload: Vec<u8> = (0..payload_size).map(|_| self.rng.gen()).collect();
        icmp_packet.set_payload(&payload);
        
        // ICMPv6 checksum calculation would be more complex in real implementation
        let checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
        icmp_packet.set_checksum(checksum);

        Ok(packet_buf)
    }

    fn build_arp_packet(&mut self, target_ip: Ipv4Addr) -> Result<Vec<u8>, String> {
        let total_len = 14 + 28; // Ethernet + ARP
        let mut packet_buf = vec![0u8; total_len];

        // Build Ethernet header
        let mut ethernet_packet = MutableEthernetPacket::new(&mut packet_buf).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(self.source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        // Build ARP packet
        let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(self.source_mac);
        arp_packet.set_sender_proto_addr(self.source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        Ok(packet_buf)
    }

    fn setup_ip_header(&mut self, ip_packet: &mut MutableIpv4Packet, total_len: usize, 
                      protocol: pnet::packet::ip::IpNextHeaderProtocol, target_ip: Ipv4Addr) {
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(total_len as u16);
        ip_packet.set_ttl(self.rng.gen_range(32..128));
        ip_packet.set_next_level_protocol(protocol);
        ip_packet.set_source(self.source_ip);
        ip_packet.set_destination(target_ip);
        ip_packet.set_identification(self.rng.gen());
        
        // Occasionally set fragmentation flags
        if self.rng.gen_bool(0.1) {
            ip_packet.set_flags(2); // Don't fragment
        }
    }
}

/// System monitoring for performance tracking
pub struct SystemMonitor {
    system: Arc<Mutex<System>>,
    monitoring_enabled: bool,
}

impl SystemMonitor {
    fn new(monitoring_enabled: bool) -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        
        Self {
            system: Arc::new(Mutex::new(system)),
            monitoring_enabled,
        }
    }

    async fn get_system_stats(&self) -> Option<SystemStats> {
        if !self.monitoring_enabled {
            return None;
        }

        let mut system = self.system.lock().await;
        system.refresh_all();

        Some(SystemStats {
            cpu_usage: system.global_cpu_usage(),
            memory_usage: system.used_memory(),
            memory_total: system.total_memory(),
            network_sent: 0, // Would need more complex implementation
            network_received: 0,
        })
    }
}

/// Multi-port target manager
pub struct MultiPortTarget {
    ports: Vec<u16>,
    current_index: Arc<std::sync::atomic::AtomicUsize>,
}

impl MultiPortTarget {
    fn new(ports: Vec<u16>) -> Self {
        Self {
            ports,
            current_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn next_port(&self) -> u16 {
        let index = self.current_index.fetch_add(1, Ordering::Relaxed) % self.ports.len();
        self.ports[index]
    }

    fn get_ports(&self) -> &[u16] {
        &self.ports
    }
}

/// Network interface management
pub fn list_network_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
}

pub fn find_interface_by_name(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().find(|iface| iface.name == name)
}

pub fn get_default_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
}

/// Enhanced safety validation functions
fn validate_target_ip(ip: &IpAddr) -> Result<(), String> {
    match ip {
        IpAddr::V4(ipv4) => {
            let ip_u32 = u32::from(*ipv4);
            
            // Check against defined private ranges using bitwise operations
            let is_private = PRIVATE_RANGES.iter().any(|(network, mask)| {
                (ip_u32 & mask) == *network
            });
            
            if is_private {
                info!("Target IP {} validated as private range", ip);
                Ok(())
            } else {
                let error_msg = format!("Target IP {} is not in private range. This tool should only target local networks.", ip);
                error!("{}", error_msg);
                Err(error_msg)
            }
        },
        IpAddr::V6(ipv6) => {
            // Check for IPv6 private ranges (link-local, unique local)
            if ipv6.is_loopback() {
                return Err("Cannot target IPv6 loopback address".to_string());
            }
            
            // Link-local (fe80::/10) or unique local (fc00::/7)
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 || (segments[0] & 0xfe00) == 0xfc00 {
                info!("Target IPv6 {} validated as private range", ip);
                Ok(())
            } else {
                let error_msg = format!("Target IPv6 {} is not in private range", ip);
                error!("{}", error_msg);
                Err(error_msg)
            }
        }
    }
}

fn is_loopback_or_multicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_multicast() || ipv4.is_broadcast(),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_multicast(),
    }
}

fn validate_comprehensive_security(ip: &IpAddr, ports: &[u16], threads: usize, rate: u64) -> Result<(), String> {
    // Check if targeting loopback or multicast
    if is_loopback_or_multicast(ip) {
        return Err("Cannot target loopback, multicast, or broadcast addresses".to_string());
    }
    
    // Validate private IP
    validate_target_ip(ip)?;
    
    // Check thread limits
    if threads > MAX_THREADS {
        return Err(format!("Thread count {} exceeds maximum: {}", threads, MAX_THREADS));
    }
    
    // Check rate limits
    if rate > MAX_PACKET_RATE {
        return Err(format!("Packet rate {} exceeds maximum: {}", rate, MAX_PACKET_RATE));
    }
    
    // Check for common service ports that shouldn't be flooded
    for &port in ports {
        match port {
            22 => warn!("Targeting SSH port {} - ensure this is intentional", port),
            53 => warn!("Targeting DNS port {} - ensure this is intentional", port),
            443 => warn!("Targeting HTTPS port {} - ensure this is intentional", port),
            _ => {}
        }
    }
    
    Ok(())
}

/// Audit logging entry creation
#[derive(Debug, Serialize, Deserialize)]
struct AuditEntry {
    timestamp: DateTime<Utc>,
    event_type: String,
    target_ip: String,
    target_ports: Vec<u16>,
    threads: usize,
    packet_rate: u64,
    duration: Option<u64>,
    user: String,
    interface: Option<String>,
    session_id: String,
}

fn create_audit_entry(target_ip: &IpAddr, target_ports: &[u16], threads: usize, 
                      packet_rate: u64, duration: Option<u64>, interface: Option<&str>,
                      session_id: &str) -> Result<(), String> {
    let entry = AuditEntry {
        timestamp: Utc::now(),
        event_type: "flood_simulation_start".to_string(),
        target_ip: target_ip.to_string(),
        target_ports: target_ports.to_vec(),
        threads,
        packet_rate,
        duration,
        user: std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()),
        interface: interface.map(|s| s.to_string()),
        session_id: session_id.to_string(),
    };
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG_FILE)
        .map_err(|e| format!("Failed to open audit log: {}", e))?;
        
    let log_line = format!("{}\n", serde_json::to_string(&entry)
        .map_err(|e| format!("Failed to serialize audit entry: {}", e))?);
        
    file.write_all(log_line.as_bytes())
        .map_err(|e| format!("Failed to write audit entry: {}", e))?;
        
    info!("Audit entry created for session {}", session_id);
    Ok(())
}

fn validate_system_requirements(dry_run: bool) -> Result<(), String> {
    // Check if running as root (required for raw sockets, but not for dry-run)
    if !dry_run && unsafe { libc::geteuid() } != 0 {
        return Err("This program requires root privileges for raw socket access. Use --dry-run for testing without root.".to_string());
    }
    
    if dry_run {
        info!("Dry-run mode: Skipping root privilege check");
    }
    
    // Check system limits
    let max_files = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if max_files < 1024 {
        warn!("Low file descriptor limit detected: {}", max_files);
    }
    
    Ok(())
}

/// Load configuration from YAML file
fn load_config(config_path: Option<&str>) -> Result<Config, String> {
    let config_file = config_path.unwrap_or(CONFIG_FILE);
    
    if !Path::new(config_file).exists() {
        info!("Config file {} not found, using defaults", config_file);
        return Ok(get_default_config());
    }
    
    let config_str = std::fs::read_to_string(config_file)
        .map_err(|e| format!("Failed to read config file: {}", e))?;
        
    serde_yaml::from_str(&config_str)
        .map_err(|e| format!("Failed to parse config file: {}", e))
}

fn get_default_config() -> Config {
    Config {
        target: TargetConfig {
            ip: "192.168.1.1".to_string(),
            ports: vec![80],
            protocol_mix: ProtocolMix {
                udp_ratio: 0.6,
                tcp_syn_ratio: 0.25,
                tcp_ack_ratio: 0.05,
                icmp_ratio: 0.05,
                ipv6_ratio: 0.03,
                arp_ratio: 0.02,
            },
            interface: None,
        },
        attack: AttackConfig {
            threads: 4,
            packet_rate: 100,
            duration: None,
            packet_size_range: (MIN_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE),
            burst_pattern: BurstPattern::Sustained { rate: 100 },
            randomize_timing: true,
        },
        safety: SafetyConfig {
            max_threads: MAX_THREADS,
            max_packet_rate: MAX_PACKET_RATE,
            require_private_ranges: true,
            enable_monitoring: true,
            audit_logging: true,
            dry_run: false,
        },
        monitoring: MonitoringConfig {
            stats_interval: 5,
            system_monitoring: true,
            export_interval: Some(60),
            performance_tracking: true,
        },
        export: ExportConfig {
            enabled: false,
            format: ExportFormat::Json,
            filename_pattern: "router_flood".to_string(),
            include_system_stats: true,
        },
    }
}

#[tokio::main]
async fn main() {
    // Initialize enhanced logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    let matches = Command::new("Router Flood - Enhanced Network Stress Tester")
        .version(env!("CARGO_PKG_VERSION"))  // Dynamically pulls from Cargo.toml
        .about("Educational DDoS simulation for local network testing with multi-protocol support")
        .arg(
            Arg::new("target")
                .long("target")
                .short('t')
                .value_name("IP")
                .help("Target router IP (must be private range)")
                .required_unless_present_any(&["config", "list-interfaces"]),
        )
        .arg(
            Arg::new("ports")
                .long("ports")
                .short('p')
                .value_name("PORTS")
                .help("Target ports (comma-separated, e.g., 80,443,22)")
                .required_unless_present_any(&["config", "list-interfaces"]),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .value_name("NUM")
                .help(&format!("Number of async tasks (default: 4, max: {})", MAX_THREADS))
                .default_value("4"),
        )
        .arg(
            Arg::new("rate")
                .long("rate")
                .value_name("PPS")
                .help("Packets per second per thread (default: 100)")
                .default_value("100"),
        )
        .arg(
            Arg::new("duration")
                .long("duration")
                .short('d')
                .value_name("SECONDS")
                .help("Test duration in seconds (default: unlimited)"),
        )
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .value_name("FILE")
                .help("YAML configuration file path"),
        )
        .arg(
            Arg::new("interface")
                .long("interface")
                .short('i')
                .value_name("NAME")
                .help("Network interface to use (default: auto-detect)"),
        )
        .arg(
            Arg::new("export")
                .long("export")
                .value_name("FORMAT")
                .help("Export statistics (json, csv, both)")
                .value_parser(["json", "csv", "both"]),
        )
        .arg(
            Arg::new("list-interfaces")
                .long("list-interfaces")
                .help("List available network interfaces")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Simulate the attack without sending actual packets (safe testing)")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    // List interfaces if requested
    if matches.get_flag("list-interfaces") {
        println!("Available network interfaces:");
        for iface in list_network_interfaces() {
            println!("  {} - {} (Up: {}, IPs: {:?})", 
                     iface.name, 
                     iface.description,
                     iface.is_up(),
                     iface.ips);
        }
        return;
    }

    // Load configuration
    let mut config = if let Some(config_path) = matches.get_one::<String>("config") {
        match load_config(Some(config_path)) {
            Ok(config) => config,
            Err(e) => {
                error!("Failed to load config: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        get_default_config()
    };

    // Override config with command line arguments
    if let Some(target) = matches.get_one::<String>("target") {
        config.target.ip = target.clone();
    }
    
    if let Some(ports_str) = matches.get_one::<String>("ports") {
        config.target.ports = ports_str
            .split(',')
            .map(|s| s.trim().parse().expect("Invalid port number"))
            .collect();
    }
    
    if let Some(threads) = matches.get_one::<String>("threads") {
        config.attack.threads = threads.parse().expect("Invalid thread count");
    }
    
    if let Some(rate) = matches.get_one::<String>("rate") {
        config.attack.packet_rate = rate.parse().expect("Invalid packet rate");
    }
    
    if let Some(duration) = matches.get_one::<String>("duration") {
        config.attack.duration = Some(duration.parse().expect("Invalid duration"));
    }
    
    if let Some(interface) = matches.get_one::<String>("interface") {
        config.target.interface = Some(interface.clone());
    }
    
    if let Some(export_format) = matches.get_one::<String>("export") {
        config.export.enabled = true;
        config.export.format = match export_format.as_str() {
            "json" => ExportFormat::Json,
            "csv" => ExportFormat::Csv,
            "both" => ExportFormat::Both,
            _ => ExportFormat::Json,
        };
    }
    
    // Check for dry-run mode (CLI flag or config file)
    let cli_dry_run = matches.get_flag("dry-run");
    let dry_run = cli_dry_run || config.safety.dry_run;
    if dry_run {
        config.safety.dry_run = true;
        if cli_dry_run {
            info!("🔍 DRY-RUN MODE ENABLED (CLI) - No packets will be sent");
        } else {
            info!("🔍 DRY-RUN MODE ENABLED (CONFIG) - No packets will be sent");
        }
    }

    // Parse and validate target IP
    let target_ip: IpAddr = config.target.ip.parse()
        .expect("Invalid IP format");
        
    // Enhanced validation
    if let Err(e) = validate_comprehensive_security(&target_ip, &config.target.ports, 
                                                    config.attack.threads, config.attack.packet_rate) {
        error!("Security Validation Error: {}", e);
        std::process::exit(1);
    }
    
    if let Err(e) = validate_system_requirements(dry_run) {
        error!("System Requirements Error: {}", e);
        std::process::exit(1);
    }

    // Validate network interface
    let selected_interface = if let Some(iface_name) = &config.target.interface {
        match find_interface_by_name(iface_name) {
            Some(iface) => {
                info!("Using specified interface: {}", iface.name);
                Some(iface)
            },
            None => {
                error!("Interface '{}' not found", iface_name);
                std::process::exit(1);
            }
        }
    } else {
        match get_default_interface() {
            Some(iface) => {
                info!("Using default interface: {}", iface.name);
                Some(iface)
            },
            None => {
                warn!("No suitable network interface found");
                None
            }
        }
    };

    // Initialize system monitoring
    let system_monitor = SystemMonitor::new(config.monitoring.system_monitoring);
    
    // Initialize statistics with export config
    let export_config = if config.export.enabled {
        Some(config.export.clone())
    } else {
        None
    };
    let stats = Arc::new(FloodStats::new(export_config));
    
    // Create audit log entry
    if config.safety.audit_logging {
        if let Err(e) = create_audit_entry(&target_ip, &config.target.ports, 
                                          config.attack.threads, config.attack.packet_rate, 
                                          config.attack.duration, 
                                          selected_interface.as_ref().map(|i| i.name.as_str()),
                                          &stats.session_id) {
            error!("Audit Log Error: {}", e);
            std::process::exit(1);
        }
    }

    // Create transport channel for IP packets (skip in dry-run mode)
    let tx = if !dry_run {
        let protocol = transport::TransportChannelType::Layer3(pnet::packet::ip::IpNextHeaderProtocols::Ipv4);
        let (tx, _) = transport::transport_channel(4096, protocol)
            .expect("Failed to create transport channel - are you running as root?");
        Some(Arc::new(Mutex::new(tx)))
    } else {
        info!("Dry-run mode: Skipping transport channel creation");
        None
    };
    let running = Arc::new(AtomicBool::new(true));
    let multi_port_target = Arc::new(MultiPortTarget::new(config.target.ports.clone()));

    if dry_run {
        info!("🔍 Starting Enhanced Router Flood SIMULATION v3.0 (DRY-RUN)");
        info!("   ⚠️  DRY-RUN MODE: No actual packets will be sent!");
    } else {
        info!("🚀 Starting Enhanced Router Flood Simulation v3.0");
    }
    info!("   Session ID: {}", stats.session_id);
    info!("   Target: {} (Ports: {:?})", target_ip, config.target.ports);
    info!("   Threads: {}, Rate: {} pps/thread", config.attack.threads, config.attack.packet_rate);
    if let Some(d) = config.attack.duration {
        info!("   Duration: {} seconds", d);
    }
    if let Some(iface) = &selected_interface {
        info!("   Interface: {}", iface.name);
    }
    info!("   Protocols: UDP({:.0}%), TCP-SYN({:.0}%), TCP-ACK({:.0}%), ICMP({:.0}%), IPv6({:.0}%), ARP({:.0}%)", 
          config.target.protocol_mix.udp_ratio * 100.0,
          config.target.protocol_mix.tcp_syn_ratio * 100.0,
          config.target.protocol_mix.tcp_ack_ratio * 100.0,
          config.target.protocol_mix.icmp_ratio * 100.0,
          config.target.protocol_mix.ipv6_ratio * 100.0,
          config.target.protocol_mix.arp_ratio * 100.0);
    if dry_run {
        info!("   📋 Mode: SIMULATION ONLY - Safe for testing configurations");
    }
    info!("   Press Ctrl+C to stop gracefully");
    println!();

    // Spawn statistics reporter with system monitoring
    let stats_clone = stats.clone();
    let running_clone = running.clone();
    let system_monitor_clone = system_monitor;
    let stats_interval = config.monitoring.stats_interval;
    tokio::spawn(async move {
        while running_clone.load(Ordering::Relaxed) {
            time::sleep(StdDuration::from_secs(stats_interval)).await;
            let sys_stats = system_monitor_clone.get_system_stats().await;
            stats_clone.print_stats(sys_stats.as_ref());
        }
    });

    // Spawn export task if enabled
    if config.export.enabled {
        if let Some(export_interval) = config.monitoring.export_interval {
            let stats_clone = stats.clone();
            let running_clone = running.clone();
            tokio::spawn(async move {
                while running_clone.load(Ordering::Relaxed) {
                    time::sleep(StdDuration::from_secs(export_interval)).await;
                    if let Err(e) = stats_clone.export_stats(None).await {
                        error!("Failed to export stats: {}", e);
                    }
                }
            });
        }
    }

    // Set duration timer if specified
    if let Some(duration_secs) = config.attack.duration {
        let running_clone = running.clone();
        tokio::spawn(async move {
            time::sleep(StdDuration::from_secs(duration_secs)).await;
            running_clone.store(false, Ordering::Relaxed);
            info!("⏰ Duration reached, stopping...");
        });
    }

    // Spawn flood tasks
    let mut handles = vec![];
    for task_id in 0..config.attack.threads {
        let tx_clone = tx.clone();
        let stats_clone = stats.clone();
        let running_clone = running.clone();
        let multi_port_target_clone = multi_port_target.clone();
        let packet_rate = config.attack.packet_rate;
        let packet_size_range = config.attack.packet_size_range;
        let protocol_mix = config.target.protocol_mix.clone();
        let randomize_timing = config.attack.randomize_timing;
        let dry_run_mode = dry_run;
        
        let handle = tokio::spawn(async move {
            let mut packet_builder = PacketBuilder::new(packet_size_range, protocol_mix);
            let base_delay = StdDuration::from_nanos(1_000_000_000 / packet_rate);
            
            while running_clone.load(Ordering::Relaxed) {
                let current_port = multi_port_target_clone.next_port();
                let packet_type = packet_builder.next_packet_type();
                
                let packet_result = packet_builder.build_packet(packet_type, target_ip, current_port);
                
                let (packet_data, protocol_name) = match packet_result {
                    Ok(data) => data,
                    Err(e) => {
                        if task_id == 0 {
                            debug!("Failed to build packet: {}", e);
                        }
                        stats_clone.increment_failed();
                        continue;
                    }
                };

                // Send packet (or simulate in dry-run mode)
                if dry_run_mode {
                    // Simulate packet sending with artificial success/failure rate
                    let simulate_success = packet_builder.rng.gen_bool(0.98); // 98% success rate simulation
                    if simulate_success {
                        stats_clone.increment_sent(packet_data.len() as u64, protocol_name);
                        if task_id == 0 && stats_clone.packets_sent.load(Ordering::Relaxed) % 1000 == 0 {
                            trace!("[DRY-RUN] Simulated {} packet to {}:{} (size: {} bytes)", 
                                  protocol_name, target_ip, current_port, packet_data.len());
                        }
                    } else {
                        stats_clone.increment_failed();
                    }
                } else {
                    // Real packet sending
                    if let Some(ref tx_ref) = tx_clone {
                        let mut tx_guard = tx_ref.lock().await;
                        match tx_guard.send_to(pnet::packet::ipv4::Ipv4Packet::new(&packet_data).unwrap(), target_ip) {
                            Ok(_) => {
                                stats_clone.increment_sent(packet_data.len() as u64, protocol_name);
                            },
                            Err(e) => {
                                if task_id == 0 {
                                    trace!("Failed to send packet: {}", e);
                                }
                                stats_clone.increment_failed();
                            }
                        }
                        drop(tx_guard);
                    }
                }

                // Randomized timing if enabled
                let delay = if randomize_timing {
                    let jitter = packet_builder.rng.gen_range(0.8..1.2);
                    StdDuration::from_nanos((base_delay.as_nanos() as f64 * jitter) as u64)
                } else {
                    base_delay
                };
                
                time::sleep(delay).await;
            }
        });
        handles.push(handle);
    }

    // Set up graceful shutdown
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Received Ctrl+C, shutting down gracefully...");
            running.store(false, Ordering::Relaxed);
        }
        _ = async {
            for handle in handles {
                handle.await.unwrap();
            }
        } => {}
    }

    // Final statistics and export
    time::sleep(StdDuration::from_millis(100)).await;
    if dry_run {
        info!("📈 Final Simulation Statistics (DRY-RUN):");
    } else {
        info!("📈 Final Statistics:");
    }
    stats.print_stats(None);
    
    // Final export if enabled
    if config.export.enabled {
        if let Err(e) = stats.export_stats(None).await {
            error!("Failed to export final stats: {}", e);
        }
    }
    
    if dry_run {
        info!("✅ Simulation completed successfully (NO PACKETS SENT)");
        info!("📋 Dry-run mode: Configuration validated, packet generation tested");
    } else {
        info!("✅ Simulation completed successfully");
    }
}