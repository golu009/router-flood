//! Integration tests for router-flood
//!
//! These tests verify the proper functioning of the refactored modules
//! and their interactions.

use router_flood::config::{get_default_config, load_config};
use router_flood::validation::{validate_system_requirements, validate_target_ip};
use router_flood::error::RouterFloodError;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_default_config_creation() {
    let config = get_default_config();
    
    assert_eq!(config.target.ip, "192.168.1.1");
    assert_eq!(config.target.ports, vec![80]);
    assert_eq!(config.attack.threads, 4);
    assert_eq!(config.attack.packet_rate, 100);
    assert!(config.safety.require_private_ranges);
    assert!(config.safety.audit_logging);
}

#[test]
fn test_config_loading_nonexistent_file() {
    let result = load_config(Some("nonexistent_file.yaml"));
    
    // Should return default config when file doesn't exist
    assert!(result.is_ok());
    let config = result.unwrap();
    assert_eq!(config.target.ip, "192.168.1.1");
}

#[test]
fn test_private_ip_validation_valid() {
    let private_ips = vec![
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
    ];
    
    for ip in private_ips {
        let result = validate_target_ip(&ip);
        assert!(result.is_ok(), "Expected {} to be valid private IP", ip);
    }
}

#[test]
fn test_private_ip_validation_invalid() {
    let public_ips = vec![
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),        // Google DNS
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),        // Cloudflare DNS
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),    // TEST-NET-3
    ];
    
    for ip in public_ips {
        let result = validate_target_ip(&ip);
        assert!(result.is_err(), "Expected {} to be invalid public IP", ip);
        
        if let Err(RouterFloodError::Validation(_)) = result {
            // Expected validation error
        } else {
            panic!("Expected ValidationError for IP {}", ip);
        }
    }
}

#[test]
fn test_system_requirements_dry_run() {
    // Dry run should always pass validation regardless of privileges
    let result = validate_system_requirements(true);
    assert!(result.is_ok());
}

#[test]
fn test_loopback_validation() {
    let loopback_ips = vec![
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ];
    
    for ip in loopback_ips {
        let result = validate_target_ip(&ip);
        assert!(result.is_err(), "Expected {} to be rejected as loopback", ip);
    }
}

#[cfg(test)]
mod cli_tests {
    use router_flood::cli::{parse_positive_number, parse_export_format};
    use router_flood::config::ExportFormat;
    
    #[test]
    fn test_parse_positive_number() {
        let result: Result<u32, _> = parse_positive_number("100", "test_field");
        assert_eq!(result.unwrap(), 100);
        
        let result: Result<u32, _> = parse_positive_number("0", "test_field");
        assert!(result.is_err());
        
        let result: Result<u32, _> = parse_positive_number("invalid", "test_field");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_export_format_parsing() {
        assert!(matches!(parse_export_format("json").unwrap(), ExportFormat::Json));
        assert!(matches!(parse_export_format("csv").unwrap(), ExportFormat::Csv));
        assert!(matches!(parse_export_format("both").unwrap(), ExportFormat::Both));
        assert!(parse_export_format("invalid").is_err());
    }
}

#[cfg(test)]
mod stats_tests {
    use router_flood::stats::FloodStats;
    use std::sync::atomic::Ordering;
    
    #[test]
    fn test_stats_initialization() {
        let stats = FloodStats::default();
        
        assert_eq!(stats.packets_sent.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_failed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 0);
        assert!(!stats.session_id.is_empty());
    }
    
    #[test]
    fn test_stats_increment() {
        let stats = FloodStats::default();
        
        stats.increment_sent(100, "UDP");
        stats.increment_failed();
        
        assert_eq!(stats.packets_sent.load(Ordering::Relaxed), 1);
        assert_eq!(stats.packets_failed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 100);
    }
}

#[cfg(test)]
mod error_tests {
    use router_flood::error::{ConfigError, NetworkError, RouterFloodError};
    
    #[test]
    fn test_error_display() {
        let config_error = ConfigError::FileNotFound("test.yaml".to_string());
        let router_error = RouterFloodError::Config(config_error);
        
        let error_string = format!("{}", router_error);
        assert!(error_string.contains("Configuration error"));
        assert!(error_string.contains("test.yaml"));
    }
    
    #[test]
    fn test_error_conversion() {
        let network_error = NetworkError::InterfaceNotFound("eth0".to_string());
        let router_error: RouterFloodError = network_error.into();
        
        if let RouterFloodError::Network(_) = router_error {
            // Expected
        } else {
            panic!("Expected NetworkError to convert to RouterFloodError::Network");
        }
    }
}