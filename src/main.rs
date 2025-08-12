//! # Router Flood - Main Application Entry Point
//!
//! # Disclaimer
//!
//! - The software is for educational and authorized testing purposes only.
//! - Unauthorized use (especially against systems you don't own or lack explicit permission to test) is strictly prohibited and may be illegal.

use std::net::IpAddr;
use std::process;
use tracing::error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use router_flood::cli::{handle_pre_execution_commands, parse_arguments, process_cli_config};
use router_flood::config::{get_default_config, load_config};
use router_flood::constants::error_messages;
use router_flood::error::Result;
use router_flood::simulation::{setup_network_interface, Simulation};
use router_flood::validation::{validate_comprehensive_security, validate_system_requirements};

fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn initialize_configuration(matches: &clap::ArgMatches) -> Result<router_flood::config::Config> {
    let base_config = if let Some(config_path) = matches.get_one::<String>("config") {
        load_config(Some(config_path))?
    } else {
        get_default_config()
    };

    process_cli_config(matches, base_config)
}

fn parse_target_ip(config: &router_flood::config::Config) -> Result<IpAddr> {
    config.target.ip.parse()
        .map_err(|_| router_flood::error::ValidationError::InvalidIpRange {
            ip: config.target.ip.clone(),
            reason: error_messages::INVALID_IP_FORMAT.to_string(),
        }.into())
}

fn perform_validations(config: &router_flood::config::Config, target_ip: &IpAddr) -> Result<()> {
    validate_comprehensive_security(
        target_ip,
        &config.target.ports,
        config.attack.threads,
        config.attack.packet_rate,
    )?;
    
    validate_system_requirements(config.safety.dry_run)?;
    Ok(())
}

async fn run_application() -> Result<()> {
    setup_logging();
    let matches = parse_arguments();

    // Handle pre-execution commands (like --list-interfaces)
    if handle_pre_execution_commands(&matches) {
        return Ok(());
    }

    // Initialize and validate configuration
    let config = initialize_configuration(&matches)?;
    let target_ip = parse_target_ip(&config)?;

    // Perform all validation checks
    perform_validations(&config, &target_ip)?;

    // Set up network interface
    let selected_interface = setup_network_interface(&config)?;

    // Create and run simulation
    let simulation = Simulation::new(config, target_ip, selected_interface);
    simulation.run().await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run_application().await {
        error!("Application error: {}", e);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_target_ip_valid() {
        let mut config = get_default_config();
        config.target.ip = "192.168.1.1".to_string();
        
        let result = parse_target_ip(&config);
        assert!(result.is_ok());
        
        if let Ok(IpAddr::V4(ipv4)) = result {
            assert_eq!(ipv4, Ipv4Addr::new(192, 168, 1, 1));
        }
    }

    #[test]
    fn test_parse_target_ip_invalid() {
        let mut config = get_default_config();
        config.target.ip = "invalid.ip.address".to_string();
        
        let result = parse_target_ip(&config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_setup_logging() {
        // This test just ensures setup_logging doesn't panic
        setup_logging();
    }
}