//! Worker thread management and packet sending logic
//!
//! This module handles the spawning and management of worker threads
//! that generate and send packets according to the configured parameters.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{debug, trace};

use crate::config::{Config, ProtocolMix};
use crate::constants::{stats, timing, NANOSECONDS_PER_SECOND};
use crate::error::{NetworkError, Result};
use crate::packet::{PacketBuilder, PacketType};
use crate::stats::FloodStats;
use crate::target::MultiPortTarget;

/// Manages the lifecycle of worker threads
pub struct WorkerManager {
    handles: Vec<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl WorkerManager {
    /// Create a new worker manager and spawn worker threads
    pub fn new(
        config: &Config,
        stats: Arc<FloodStats>,
        multi_port_target: Arc<MultiPortTarget>,
        target_ip: IpAddr,
        tx_ipv4: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
        tx_ipv6: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
        tx_l2: Option<Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>>,
        dry_run: bool,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let handles = Self::spawn_workers(
            config,
            stats,
            running.clone(),
            multi_port_target,
            target_ip,
            tx_ipv4,
            tx_ipv6,
            tx_l2,
            dry_run,
        );

        Self { handles, running }
    }

    /// Spawn worker threads based on configuration
    fn spawn_workers(
        config: &Config,
        stats: Arc<FloodStats>,
        running: Arc<AtomicBool>,
        multi_port_target: Arc<MultiPortTarget>,
        target_ip: IpAddr,
        tx_ipv4: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
        tx_ipv6: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
        tx_l2: Option<Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>>,
        dry_run: bool,
    ) -> Vec<JoinHandle<()>> {
        let mut handles = Vec::with_capacity(config.attack.threads);

        for task_id in 0..config.attack.threads {
            let worker = Worker::new(
                task_id,
                stats.clone(),
                running.clone(),
                multi_port_target.clone(),
                target_ip,
                tx_ipv4.clone(),
                tx_ipv6.clone(),
                tx_l2.clone(),
                config.attack.packet_rate,
                config.attack.packet_size_range,
                config.target.protocol_mix.clone(),
                config.attack.randomize_timing,
                dry_run,
            );

            let handle = tokio::spawn(async move {
                worker.run().await;
            });

            handles.push(handle);
        }

        handles
    }

    /// Stop all worker threads gracefully
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Wait for all worker threads to complete
    pub async fn join_all(self) -> Result<()> {
        for handle in self.handles {
            handle.await.map_err(|e| NetworkError::PacketSend(format!("Worker join error: {}", e)))?;
        }
        Ok(())
    }

    /// Check if workers are still running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

/// Individual worker thread that sends packets
struct Worker {
    task_id: usize,
    stats: Arc<FloodStats>,
    running: Arc<AtomicBool>,
    multi_port_target: Arc<MultiPortTarget>,
    target_ip: IpAddr,
    tx_ipv4: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
    tx_ipv6: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
    tx_l2: Option<Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>>,
    packet_builder: PacketBuilder,
    base_delay: StdDuration,
    randomize_timing: bool,
    dry_run: bool,
}

impl Worker {
    #[allow(clippy::too_many_arguments)]
    fn new(
        task_id: usize,
        stats: Arc<FloodStats>,
        running: Arc<AtomicBool>,
        multi_port_target: Arc<MultiPortTarget>,
        target_ip: IpAddr,
        tx_ipv4: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
        tx_ipv6: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
        tx_l2: Option<Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>>,
        packet_rate: u64,
        packet_size_range: (usize, usize),
        protocol_mix: ProtocolMix,
        randomize_timing: bool,
        dry_run: bool,
    ) -> Self {
        let packet_builder = PacketBuilder::new(packet_size_range, protocol_mix);
        let base_delay = StdDuration::from_nanos(NANOSECONDS_PER_SECOND / packet_rate);

        Self {
            task_id,
            stats,
            running,
            multi_port_target,
            target_ip,
            tx_ipv4,
            tx_ipv6,
            tx_l2,
            packet_builder,
            base_delay,
            randomize_timing,
            dry_run,
        }
    }

    /// Main worker loop
    async fn run(mut self) {
        while self.running.load(Ordering::Relaxed) {
            if let Err(e) = self.process_single_packet().await {
                if self.task_id == 0 {
                    debug!("Packet processing error: {}", e);
                }
                self.stats.increment_failed();
            }

            self.apply_rate_limiting().await;
        }
    }

    /// Process a single packet (build and send)
    async fn process_single_packet(&mut self) -> Result<()> {
        let current_port = self.multi_port_target.next_port();
        let packet_type = self.packet_builder.next_packet_type();

        let (packet_data, protocol_name) = self.packet_builder
            .build_packet(packet_type, self.target_ip, current_port)
            .map_err(|e| NetworkError::PacketSend(format!("Packet build failed: {}", e)))?;

        if self.dry_run {
            self.simulate_packet_send(&packet_data, protocol_name).await;
        } else {
            self.send_packet(packet_type, &packet_data, protocol_name).await?;
        }

        Ok(())
    }

    /// Simulate packet sending in dry-run mode
    async fn simulate_packet_send(&mut self, packet_data: &[u8], protocol_name: &str) {
        let simulate_success = self.packet_builder.rng_gen_bool(stats::SUCCESS_RATE_SIMULATION);
        
        if simulate_success {
            self.stats.increment_sent(packet_data.len() as u64, protocol_name);
            if self.task_id == 0 && self.stats.packets_sent.load(Ordering::Relaxed) % stats::LOG_FREQUENCY == 0 {
                trace!(
                    "[DRY-RUN] Simulated {} packet to {}:{} (size: {} bytes)",
                    protocol_name, self.target_ip, self.multi_port_target.next_port(), packet_data.len()
                );
            }
        } else {
            self.stats.increment_failed();
        }
    }

    /// Send packet via appropriate transport channel
    async fn send_packet(
        &self,
        packet_type: PacketType,
        packet_data: &[u8],
        protocol_name: &str,
    ) -> Result<()> {
        match packet_type {
            PacketType::Udp | PacketType::TcpSyn | PacketType::TcpAck | PacketType::Icmp => {
                self.send_ipv4_packet(packet_data, protocol_name).await
            }
            PacketType::Ipv6Udp | PacketType::Ipv6Tcp | PacketType::Ipv6Icmp => {
                self.send_ipv6_packet(packet_data, protocol_name).await
            }
            PacketType::Arp => {
                self.send_l2_packet(packet_data, protocol_name).await
            }
        }
    }

    /// Send IPv4 packet
    async fn send_ipv4_packet(&self, packet_data: &[u8], protocol_name: &str) -> Result<()> {
        if let Some(ref tx_ref) = self.tx_ipv4 {
            let mut tx_guard = tx_ref.lock().await;
            let packet = pnet::packet::ipv4::Ipv4Packet::new(packet_data)
                .ok_or_else(|| NetworkError::PacketSend("Invalid IPv4 packet data".to_string()))?;

            match tx_guard.send_to(packet, self.target_ip) {
                Ok(_) => {
                    self.stats.increment_sent(packet_data.len() as u64, protocol_name);
                    Ok(())
                }
                Err(e) => {
                    if self.task_id == 0 {
                        trace!("Failed to send IPv4 packet: {}", e);
                    }
                    self.stats.increment_failed();
                    Err(NetworkError::PacketSend(format!("IPv4 send failed: {}", e)).into())
                }
            }
        } else {
            Err(NetworkError::PacketSend("IPv4 transport channel not available".to_string()).into())
        }
    }

    /// Send IPv6 packet
    async fn send_ipv6_packet(&self, packet_data: &[u8], protocol_name: &str) -> Result<()> {
        if let Some(ref tx_ref) = self.tx_ipv6 {
            let mut tx_guard = tx_ref.lock().await;
            let packet = pnet::packet::ipv6::Ipv6Packet::new(packet_data)
                .ok_or_else(|| NetworkError::PacketSend("Invalid IPv6 packet data".to_string()))?;

            match tx_guard.send_to(packet, self.target_ip) {
                Ok(_) => {
                    self.stats.increment_sent(packet_data.len() as u64, protocol_name);
                    Ok(())
                }
                Err(e) => {
                    if self.task_id == 0 {
                        trace!("Failed to send IPv6 packet: {}", e);
                    }
                    self.stats.increment_failed();
                    Err(NetworkError::PacketSend(format!("IPv6 send failed: {}", e)).into())
                }
            }
        } else {
            Err(NetworkError::PacketSend("IPv6 transport channel not available".to_string()).into())
        }
    }

    /// Send Layer 2 packet (ARP)
    async fn send_l2_packet(&self, packet_data: &[u8], protocol_name: &str) -> Result<()> {
        if let Some(ref tx_ref) = self.tx_l2 {
            let mut tx_guard = tx_ref.lock().await;

            match tx_guard.send_to(packet_data, None) {
                Some(Ok(_)) => {
                    self.stats.increment_sent(packet_data.len() as u64, protocol_name);
                    Ok(())
                }
                Some(Err(e)) => {
                    if self.task_id == 0 {
                        trace!("Failed to send L2 packet: {}", e);
                    }
                    self.stats.increment_failed();
                    Err(NetworkError::PacketSend(format!("L2 send failed: {}", e)).into())
                }
                None => {
                    if self.task_id == 0 {
                        trace!("Failed to send L2 packet: No sender available");
                    }
                    self.stats.increment_failed();
                    Err(NetworkError::PacketSend("L2 sender not available".to_string()).into())
                }
            }
        } else {
            Err(NetworkError::PacketSend("L2 transport channel not available".to_string()).into())
        }
    }

    /// Apply rate limiting with optional timing randomization
    async fn apply_rate_limiting(&mut self) {
        let delay = if self.randomize_timing {
            let jitter = self.packet_builder.rng_gen_range(timing::JITTER_MIN..timing::JITTER_MAX);
            StdDuration::from_nanos((self.base_delay.as_nanos() as f64 * jitter) as u64)
        } else {
            self.base_delay
        };

        time::sleep(delay).await;
    }
}
