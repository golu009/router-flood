//! Simulation orchestration and lifecycle management
//!
//! This module handles the high-level simulation flow, including setup,
//! monitoring, and graceful shutdown coordination.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::Mutex;
use tokio::time;
use tracing::{error, info, warn};

use crate::audit::create_audit_entry;
use crate::config::Config;
use crate::constants::GRACEFUL_SHUTDOWN_TIMEOUT;
use crate::error::{NetworkError, Result};
use crate::monitor::SystemMonitor;
use crate::network::{find_interface_by_name, get_default_interface};
use crate::stats::FloodStats;
use crate::target::MultiPortTarget;
use crate::worker::WorkerManager;

/// High-level simulation controller
pub struct Simulation {
    config: Config,
    target_ip: IpAddr,
    selected_interface: Option<pnet::datalink::NetworkInterface>,
    stats: Arc<FloodStats>,
    running: Arc<AtomicBool>,
    system_monitor: Arc<SystemMonitor>,
}

impl Simulation {
    /// Create a new simulation with validated configuration
    pub fn new(
        config: Config,
        target_ip: IpAddr,
        selected_interface: Option<pnet::datalink::NetworkInterface>,
    ) -> Self {
        let stats = Arc::new(FloodStats::new(
            config.export.enabled.then_some(config.export.clone()),
        ));
        let running = Arc::new(AtomicBool::new(true));
        let system_monitor = Arc::new(SystemMonitor::new(config.monitoring.system_monitoring));

        Self {
            config,
            target_ip,
            selected_interface,
            stats,
            running,
            system_monitor,
        }
    }

    /// Run the complete simulation
    pub async fn run(self) -> Result<()> {
        self.setup_audit_logging()?;
        self.spawn_monitoring_tasks();
        self.print_simulation_info();

        let channels = self.setup_transport_channels()?;
        let multi_port_target = Arc::new(MultiPortTarget::new(self.config.target.ports.clone()));

        let worker_manager = WorkerManager::new(
            &self.config,
            self.stats.clone(),
            multi_port_target,
            self.target_ip,
            channels.0,
            channels.1,
            channels.2,
            self.config.safety.dry_run,
        );

        // Wait for completion or interruption
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("🛑 Received Ctrl+C, shutting down gracefully...");
                self.running.store(false, Ordering::Relaxed);
            }
            result = worker_manager.join_all() => {
                if let Err(e) = result {
                    error!("Worker error: {}", e);
                }
            }
        }

        self.finalize_simulation().await?;
        Ok(())
    }

    /// Set up audit logging if enabled
    fn setup_audit_logging(&self) -> Result<()> {
        if self.config.safety.audit_logging {
            create_audit_entry(
                &self.target_ip,
                &self.config.target.ports,
                self.config.attack.threads,
                self.config.attack.packet_rate,
                self.config.attack.duration,
                self.selected_interface.as_ref().map(|i| i.name.as_str()),
                &self.stats.session_id,
            ).map_err(|e| NetworkError::PacketSend(format!("Audit setup failed: {}", e)))?;
        }
        Ok(())
    }

    /// Set up transport channels based on configuration
    fn setup_transport_channels(
        &self,
    ) -> Result<(
        Option<Arc<Mutex<pnet::transport::TransportSender>>>,
        Option<Arc<Mutex<pnet::transport::TransportSender>>>,
        Option<Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>>,
    )> {
        if self.config.safety.dry_run {
            info!("Dry-run mode: Skipping transport channel creation");
            return Ok((None, None, None));
        }

        let tx_ipv4 = self.create_ipv4_channel()?;
        let tx_ipv6 = self.create_ipv6_channel()?;
        let tx_l2 = self.create_l2_channel()?;

        Ok((tx_ipv4, tx_ipv6, tx_l2))
    }

    /// Create IPv4 transport channel
    fn create_ipv4_channel(&self) -> Result<Option<Arc<Mutex<pnet::transport::TransportSender>>>> {
        use pnet::transport::{transport_channel, TransportChannelType};
        
        match transport_channel(
            crate::constants::TRANSPORT_BUFFER_SIZE,
            TransportChannelType::Layer3(pnet::packet::ip::IpNextHeaderProtocols::Ipv4),
        ) {
            Ok((tx, _)) => Ok(Some(Arc::new(Mutex::new(tx)))),
            Err(e) => Err(NetworkError::ChannelCreation(format!("IPv4 channel: {}", e)).into()),
        }
    }

    /// Create IPv6 transport channel
    fn create_ipv6_channel(&self) -> Result<Option<Arc<Mutex<pnet::transport::TransportSender>>>> {
        use pnet::transport::{transport_channel, TransportChannelType};
        
        match transport_channel(
            crate::constants::TRANSPORT_BUFFER_SIZE,
            TransportChannelType::Layer3(pnet::packet::ip::IpNextHeaderProtocols::Ipv6),
        ) {
            Ok((tx, _)) => Ok(Some(Arc::new(Mutex::new(tx)))),
            Err(e) => Err(NetworkError::ChannelCreation(format!("IPv6 channel: {}", e)).into()),
        }
    }

    /// Create Layer 2 transport channel for ARP
    fn create_l2_channel(&self) -> Result<Option<Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>>> {
        if let Some(ref iface) = self.selected_interface {
            match pnet::datalink::channel(iface, Default::default()) {
                Ok(pnet::datalink::Channel::Ethernet(tx, _)) => {
                    Ok(Some(Arc::new(Mutex::new(tx))))
                }
                Ok(_) => Err(NetworkError::ChannelCreation("Unknown L2 channel type".to_string()).into()),
                Err(e) => Err(NetworkError::ChannelCreation(format!("L2 channel: {}", e)).into()),
            }
        } else {
            Ok(None)
        }
    }

    /// Spawn background monitoring tasks
    fn spawn_monitoring_tasks(&self) {
        self.spawn_stats_reporter();
        self.spawn_export_task();
        self.spawn_duration_timer();
    }

    /// Spawn statistics reporting task
    fn spawn_stats_reporter(&self) {
        let stats = self.stats.clone();
        let running = self.running.clone();
        let system_monitor = self.system_monitor.clone();
        let stats_interval = self.config.monitoring.stats_interval;

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                time::sleep(StdDuration::from_secs(stats_interval)).await;
                let sys_stats = system_monitor.get_system_stats().await;
                stats.print_stats(sys_stats.as_ref());
            }
        });
    }

    /// Spawn export task if enabled
    fn spawn_export_task(&self) {
        if let Some(export_interval) = self.config.monitoring.export_interval {
            if self.config.export.enabled {
                let stats = self.stats.clone();
                let running = self.running.clone();

                tokio::spawn(async move {
                    while running.load(Ordering::Relaxed) {
                        time::sleep(StdDuration::from_secs(export_interval)).await;
                        if let Err(e) = stats.export_stats(None).await {
                            error!("Failed to export stats: {}", e);
                        }
                    }
                });
            }
        }
    }

    /// Spawn duration timer if specified
    fn spawn_duration_timer(&self) {
        if let Some(duration_secs) = self.config.attack.duration {
            let running = self.running.clone();
            tokio::spawn(async move {
                time::sleep(StdDuration::from_secs(duration_secs)).await;
                running.store(false, Ordering::Relaxed);
                info!("⏰ Duration reached, stopping...");
            });
        }
    }

    /// Print simulation start information
    fn print_simulation_info(&self) {
        let version = env!("CARGO_PKG_VERSION");
        
        if self.config.safety.dry_run {
            info!("🔍 Starting Enhanced Router Flood SIMULATION v{} (DRY-RUN)", version);
            info!("   ⚠️  DRY-RUN MODE: No actual packets will be sent!");
        } else {
            info!("🚀 Starting Enhanced Router Flood Simulation v{}", version);
        }

        info!("   Session ID: {}", self.stats.session_id);
        info!("   Target: {} (Ports: {:?})", self.target_ip, self.config.target.ports);
        info!("   Threads: {}, Rate: {} pps/thread", 
            self.config.attack.threads, self.config.attack.packet_rate);

        if let Some(d) = self.config.attack.duration {
            info!("   Duration: {} seconds", d);
        }

        if let Some(ref iface) = self.selected_interface {
            info!("   Interface: {}", iface.name);
        }

        let mix = &self.config.target.protocol_mix;
        info!(
            "   Protocols: UDP({:.0}%), TCP-SYN({:.0}%), TCP-ACK({:.0}%), ICMP({:.0}%), IPv6({:.0}%), ARP({:.0}%)",
            mix.udp_ratio * 100.0,
            mix.tcp_syn_ratio * 100.0,
            mix.tcp_ack_ratio * 100.0,
            mix.icmp_ratio * 100.0,
            mix.ipv6_ratio * 100.0,
            mix.arp_ratio * 100.0
        );

        if self.config.safety.dry_run {
            info!("   📋 Mode: SIMULATION ONLY - Safe for testing configurations");
        }

        info!("   Press Ctrl+C to stop gracefully");
        println!();
    }

    /// Finalize simulation and export final stats
    async fn finalize_simulation(&self) -> Result<()> {
        time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT).await;

        if self.config.safety.dry_run {
            info!("📈 Final Simulation Statistics (DRY-RUN):");
        } else {
            info!("📈 Final Statistics:");
        }

        self.stats.print_stats(None);

        if self.config.export.enabled {
            if let Err(e) = self.stats.export_stats(None).await {
                error!("Failed to export final stats: {}", e);
            }
        }

        if self.config.safety.dry_run {
            info!("✅ Simulation completed successfully (NO PACKETS SENT)");
            info!("📋 Dry-run mode: Configuration validated, packet generation tested");
        } else {
            info!("✅ Simulation completed successfully");
        }

        Ok(())
    }
}

/// Set up network interface based on configuration
pub fn setup_network_interface(config: &Config) -> Result<Option<pnet::datalink::NetworkInterface>> {
    if let Some(iface_name) = &config.target.interface {
        match find_interface_by_name(iface_name) {
            Some(iface) => {
                info!("Using specified interface: {}", iface.name);
                Ok(Some(iface))
            }
            None => Err(NetworkError::InterfaceNotFound(iface_name.clone()).into()),
        }
    } else {
        match get_default_interface() {
            Some(iface) => {
                info!("Using default interface: {}", iface.name);
                Ok(Some(iface))
            }
            None => {
                warn!("No suitable network interface found");
                Ok(None)
            }
        }
    }
}

