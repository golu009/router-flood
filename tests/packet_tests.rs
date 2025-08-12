//! Basic packet module tests
//!
//! Tests for packet type definitions and basic functionality.

use router_flood::packet::*;

#[test]
fn test_packet_type_display() {
    // Test that PacketType enum variants can be created and displayed
    assert_eq!(PacketType::Udp.to_string(), "UDP");
    assert_eq!(PacketType::TcpSyn.to_string(), "TCP-SYN");
    assert_eq!(PacketType::TcpAck.to_string(), "TCP-ACK");
    assert_eq!(PacketType::Icmp.to_string(), "ICMP");
    assert_eq!(PacketType::Ipv6.to_string(), "IPv6");
    assert_eq!(PacketType::Arp.to_string(), "ARP");
}

#[test]
fn test_packet_builder_creation() {
    use router_flood::config::ProtocolMix;
    
    let protocol_mix = ProtocolMix {
        udp_ratio: 0.6,
        tcp_syn_ratio: 0.25,
        tcp_ack_ratio: 0.05,
        icmp_ratio: 0.05,
        ipv6_ratio: 0.03,
        arp_ratio: 0.02,
    };
    
    // Test that PacketBuilder can be created
    let builder = PacketBuilder::new((64, 1500), protocol_mix);
    
    // Should not panic during creation
}

#[test]
fn test_packet_builder_packet_generation() {
    use router_flood::config::ProtocolMix;
    
    let protocol_mix = ProtocolMix {
        udp_ratio: 1.0, // Only UDP for predictable testing
        tcp_syn_ratio: 0.0,
        tcp_ack_ratio: 0.0,
        icmp_ratio: 0.0,
        ipv6_ratio: 0.0,
        arp_ratio: 0.0,
    };
    
    let mut builder = PacketBuilder::new((64, 1500), protocol_mix);
    
    // Test that we can generate packet types
    for _ in 0..10 {
        let packet_type = builder.next_packet_type();
        // With 100% UDP ratio, should always return UDP
        assert_eq!(packet_type, PacketType::Udp);
    }
}