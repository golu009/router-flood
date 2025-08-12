//! CLI module tests
//!
//! Tests for command-line interface parsing, validation, and configuration processing.

use router_flood::cli::{parse_ports, parse_positive_number, parse_export_format};
use router_flood::config::ExportFormat;
use router_flood::error::Result;

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
fn test_parse_ports_empty() {
    let result = parse_ports("");
    assert!(result.is_err());
}

#[test]
fn test_parse_ports_single() {
    let ports = parse_ports("8080").unwrap();
    assert_eq!(ports, vec![8080]);
}

#[test]
fn test_parse_ports_with_spaces() {
    let ports = parse_ports(" 80 , 443 , 22 ").unwrap();
    assert_eq!(ports, vec![80, 443, 22]);
}

#[test]
fn test_parse_positive_number() {
    let result: Result<u32> = parse_positive_number("100", "test_field");
    assert_eq!(result.unwrap(), 100);
    
    let result: Result<u32> = parse_positive_number("0", "test_field");
    assert!(result.is_err());
    
    let result: Result<u32> = parse_positive_number("invalid", "test_field");
    assert!(result.is_err());
}

#[test]
fn test_parse_positive_number_types() {
    // Test different numeric types
    let result: Result<u64> = parse_positive_number("1000", "test_field");
    assert_eq!(result.unwrap(), 1000u64);
    
    let result: Result<usize> = parse_positive_number("50", "test_field");
    assert_eq!(result.unwrap(), 50usize);
}

#[test]
fn test_parse_export_format() {
    assert!(matches!(parse_export_format("json").unwrap(), ExportFormat::Json));
    assert!(matches!(parse_export_format("csv").unwrap(), ExportFormat::Csv));
    assert!(matches!(parse_export_format("both").unwrap(), ExportFormat::Both));
    assert!(parse_export_format("invalid").is_err());
}

#[test]
fn test_parse_export_format_case_insensitive() {
    assert!(matches!(parse_export_format("JSON").unwrap(), ExportFormat::Json));
    assert!(matches!(parse_export_format("CSV").unwrap(), ExportFormat::Csv));
    assert!(matches!(parse_export_format("Both").unwrap(), ExportFormat::Both));
    assert!(matches!(parse_export_format("BOTH").unwrap(), ExportFormat::Both));
}