//! Command-line interface handling
//!
//! This module handles all CLI argument parsing, validation, and help text
//! generation, keeping main.rs focused on orchestration.

use clap::{Arg, ArgMatches, Command};
use std::str::FromStr;
use tracing::info;

use crate::constants::{defaults, MAX_THREADS};
use crate::error::{ConfigError, Result, RouterFloodError};
use crate::config::{Config, ExportFormat};

/// Parse command line arguments and return matches
pub fn parse_arguments() -> ArgMatches {
    Command::new("Router Flood - Enhanced Network Stress Tester")
        .version(env!("CARGO_PKG_VERSION"))
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
                .help(&format!("Number of async tasks (default: {}, max: {})", 
                    defaults::THREAD_COUNT, MAX_THREADS))
                .default_value("4"),
        )
        .arg(
            Arg::new("rate")
                .long("rate")
                .value_name("PPS")
                .help(&format!("Packets per second per thread (default: {})", 
                    defaults::PACKET_RATE))
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
        .get_matches()
}

/// Process CLI arguments and merge with config
pub fn process_cli_config(matches: &ArgMatches, mut config: Config) -> Result<Config> {
    // Override config with CLI arguments
    if let Some(target) = matches.get_one::<String>("target") {
        config.target.ip = target.clone();
    }

    if let Some(ports_str) = matches.get_one::<String>("ports") {
        config.target.ports = parse_ports(ports_str)?;
    }

    if let Some(threads_str) = matches.get_one::<String>("threads") {
        config.attack.threads = parse_positive_number(threads_str, "threads")?;
    }

    if let Some(rate_str) = matches.get_one::<String>("rate") {
        config.attack.packet_rate = parse_positive_number(rate_str, "rate")?;
    }

    if let Some(duration_str) = matches.get_one::<String>("duration") {
        config.attack.duration = Some(parse_positive_number(duration_str, "duration")?);
    }

    if let Some(interface) = matches.get_one::<String>("interface") {
        config.target.interface = Some(interface.clone());
    }

    if let Some(export_format) = matches.get_one::<String>("export") {
        config.export.enabled = true;
        config.export.format = parse_export_format(export_format)?;
    }

    // Handle dry-run flag
    let cli_dry_run = matches.get_flag("dry-run");
    if cli_dry_run || config.safety.dry_run {
        config.safety.dry_run = true;
        if cli_dry_run {
            info!("🔍 DRY-RUN MODE ENABLED (CLI) - No packets will be sent");
        } else {
            info!("🔍 DRY-RUN MODE ENABLED (CONFIG) - No packets will be sent");
        }
    }

    Ok(config)
}

/// Check if any pre-execution commands were requested
pub fn handle_pre_execution_commands(matches: &ArgMatches) -> bool {
    if matches.get_flag("list-interfaces") {
        list_network_interfaces();
        return true;
    }
    false
}

/// Parse comma-separated ports
pub fn parse_ports(ports_str: &str) -> Result<Vec<u16>> {
    ports_str
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<u16>()
                .map_err(|_| ConfigError::InvalidValue {
                    field: "ports".to_string(),
                    value: s.trim().to_string(),
                    reason: "must be a valid port number (1-65535)".to_string(),
                })
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(RouterFloodError::from)
}

/// Parse positive numbers with field context
pub fn parse_positive_number<T>(value_str: &str, field: &str) -> Result<T>
where
    T: FromStr + PartialOrd + Default,
    T::Err: std::fmt::Display,
{
    let value = value_str.parse::<T>().map_err(|e| ConfigError::InvalidValue {
        field: field.to_string(),
        value: value_str.to_string(),
        reason: e.to_string(),
    })?;

    if value <= T::default() {
        return Err(ConfigError::InvalidValue {
            field: field.to_string(),
            value: value_str.to_string(),
            reason: "must be greater than 0".to_string(),
        }.into());
    }

    Ok(value)
}

/// Parse export format string
pub fn parse_export_format(format_str: &str) -> Result<ExportFormat> {
    match format_str.to_lowercase().as_str() {
        "json" => Ok(ExportFormat::Json),
        "csv" => Ok(ExportFormat::Csv),
        "both" => Ok(ExportFormat::Both),
        _ => Err(ConfigError::InvalidValue {
            field: "export".to_string(),
            value: format_str.to_string(),
            reason: "must be 'json', 'csv', or 'both'".to_string(),
        }.into()),
    }
}

/// List available network interfaces
fn list_network_interfaces() {
    use crate::network::list_network_interfaces as list_interfaces;
    
    println!("Available network interfaces:");
    for iface in list_interfaces() {
        println!(
            "  {} - {} (Up: {}, IPs: {:?})",
            iface.name,
            iface.description,
            iface.is_up(),
            iface.ips
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_valid() {
        let ports = parse_ports("80,443,22").unwrap();
        assert_eq!(ports, vec![80, 443, 22]);
    }

    #[test]
    fn test_parse_ports_invalid() {
        let result = parse_ports("80,invalid,22");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_positive_number() {
        let result: Result<u32> = parse_positive_number("100", "test_field");
        assert_eq!(result.unwrap(), 100);
        
        let result: Result<u32> = parse_positive_number("0", "test_field");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_export_format() {
        assert!(matches!(parse_export_format("json").unwrap(), ExportFormat::Json));
        assert!(matches!(parse_export_format("csv").unwrap(), ExportFormat::Csv));
        assert!(matches!(parse_export_format("both").unwrap(), ExportFormat::Both));
        assert!(parse_export_format("invalid").is_err());
    }
}