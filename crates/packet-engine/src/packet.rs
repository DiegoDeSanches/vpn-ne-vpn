//! Checked IPv4/IPv6 packet parsing and synthetic packet construction.

use std::net::Ipv4Addr;

/// Packet parsing failure. Variants deliberately contain no packet bytes or addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    /// Packet is empty or shorter than its mandatory header.
    Truncated,
    /// IP version is unsupported or internally inconsistent.
    InvalidVersion,
    /// A header length or total length is invalid.
    InvalidLength,
    /// IPv4 header checksum is invalid.
    InvalidIpv4Checksum,
    /// TCP/UDP checksum is invalid.
    InvalidTransportChecksum,
    /// Fragmented traffic is unsupported by the MVP.
    Fragmented,
    /// A required source or destination port is zero.
    InvalidPort,
}

/// Coarse IP next-header classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpProtocolClass {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Internet Control Message Protocol.
    Icmp,
    /// Any unsupported or unknown IP protocol.
    Other(u8),
}

/// TCP control flags used by the bounded flow state machine.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpFlags {
    /// FIN flag.
    pub fin: bool,
    /// SYN flag.
    pub syn: bool,
    /// RST flag.
    pub rst: bool,
    /// PSH flag.
    pub psh: bool,
    /// ACK flag.
    pub ack: bool,
}

impl TcpFlags {
    /// Creates a SYN-ACK flag set.
    pub const fn syn_ack() -> Self {
        Self {
            syn: true,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
        }
    }

    /// Creates an ACK-only flag set.
    pub const fn ack() -> Self {
        Self {
            ack: true,
            fin: false,
            syn: false,
            rst: false,
            psh: false,
        }
    }

    /// Creates a FIN-ACK flag set.
    pub const fn fin_ack() -> Self {
        Self {
            fin: true,
            ack: true,
            syn: false,
            rst: false,
            psh: false,
        }
    }

    /// Creates a RST-ACK flag set.
    pub const fn rst_ack() -> Self {
        Self {
            rst: true,
            ack: true,
            fin: false,
            syn: false,
            psh: false,
        }
    }

    fn bits(self) -> u8 {
        u8::from(self.fin)
            | (u8::from(self.syn) << 1)
            | (u8::from(self.rst) << 2)
            | (u8::from(self.psh) << 3)
            | (u8::from(self.ack) << 4)
    }
}

/// Borrowed, validated IPv4 TCP segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegment<'a> {
    /// Source address.
    pub source: Ipv4Addr,
    /// Destination address.
    pub destination: Ipv4Addr,
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// TCP sequence number.
    pub sequence: u32,
    /// TCP acknowledgement number.
    pub acknowledgement: u32,
    /// Advertised receive window.
    pub window: u16,
    /// Parsed control flags.
    pub flags: TcpFlags,
    /// TCP payload without header/options.
    pub payload: &'a [u8],
}

/// Borrowed, validated IPv4 UDP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpDatagram<'a> {
    /// Source address.
    pub source: Ipv4Addr,
    /// Destination address.
    pub destination: Ipv4Addr,
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// UDP payload.
    pub payload: &'a [u8],
}

/// Minimal ICMP packet metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpPacket {
    /// Source address.
    pub source: Ipv4Addr,
    /// Destination address.
    pub destination: Ipv4Addr,
    /// ICMP type.
    pub message_type: u8,
    /// ICMP code.
    pub code: u8,
}

/// Result of checked packet classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassifiedPacket<'a> {
    /// Supported IPv4 TCP segment.
    Tcp(TcpSegment<'a>),
    /// IPv4 UDP datagram, accepted only by local DNS interception.
    Udp(UdpDatagram<'a>),
    /// IPv4 ICMP packet handled locally and minimally.
    Icmp(IcmpPacket),
    /// IPv6 packet, which is blocked by the MVP.
    Ipv6,
    /// IPv4 packet with another protocol number.
    Other(IpProtocolClass),
}

/// Validates and classifies one complete IP packet.
pub fn classify(packet: &[u8]) -> Result<ClassifiedPacket<'_>, PacketError> {
    let version = packet.first().ok_or(PacketError::Truncated)? >> 4;
    match version {
        4 => classify_ipv4(packet),
        6 => {
            if packet.len() < 40 {
                return Err(PacketError::Truncated);
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if 40usize.saturating_add(payload_len) > packet.len() {
                return Err(PacketError::InvalidLength);
            }
            Ok(ClassifiedPacket::Ipv6)
        }
        _ => Err(PacketError::InvalidVersion),
    }
}

fn classify_ipv4(packet: &[u8]) -> Result<ClassifiedPacket<'_>, PacketError> {
    if packet.len() < 20 {
        return Err(PacketError::Truncated);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < 20 || total_len < header_len || total_len > packet.len() {
        return Err(PacketError::InvalidLength);
    }
    if checksum(&packet[..header_len]) != 0 {
        return Err(PacketError::InvalidIpv4Checksum);
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return Err(PacketError::Fragmented);
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let payload = &packet[header_len..total_len];
    match packet[9] {
        6 => parse_tcp(source, destination, payload).map(ClassifiedPacket::Tcp),
        17 => parse_udp(source, destination, payload).map(ClassifiedPacket::Udp),
        1 => {
            if payload.len() < 4 {
                return Err(PacketError::Truncated);
            }
            Ok(ClassifiedPacket::Icmp(IcmpPacket {
                source,
                destination,
                message_type: payload[0],
                code: payload[1],
            }))
        }
        value => Ok(ClassifiedPacket::Other(IpProtocolClass::Other(value))),
    }
}

fn parse_tcp(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    bytes: &[u8],
) -> Result<TcpSegment<'_>, PacketError> {
    if bytes.len() < 20 {
        return Err(PacketError::Truncated);
    }
    let header_len = usize::from(bytes[12] >> 4) * 4;
    if header_len < 20 || header_len > bytes.len() {
        return Err(PacketError::InvalidLength);
    }
    let source_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let destination_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    if source_port == 0 || destination_port == 0 {
        return Err(PacketError::InvalidPort);
    }
    if transport_checksum(source, destination, 6, bytes) != 0 {
        return Err(PacketError::InvalidTransportChecksum);
    }
    let flags = bytes[13];
    Ok(TcpSegment {
        source,
        destination,
        source_port,
        destination_port,
        sequence: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        acknowledgement: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        window: u16::from_be_bytes([bytes[14], bytes[15]]),
        flags: TcpFlags {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
        },
        payload: &bytes[header_len..],
    })
}

fn parse_udp(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    bytes: &[u8],
) -> Result<UdpDatagram<'_>, PacketError> {
    if bytes.len() < 8 {
        return Err(PacketError::Truncated);
    }
    let source_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let destination_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if source_port == 0 || destination_port == 0 {
        return Err(PacketError::InvalidPort);
    }
    if length < 8 || length > bytes.len() {
        return Err(PacketError::InvalidLength);
    }
    let supplied_checksum = u16::from_be_bytes([bytes[6], bytes[7]]);
    if supplied_checksum != 0 && transport_checksum(source, destination, 17, &bytes[..length]) != 0
    {
        return Err(PacketError::InvalidTransportChecksum);
    }
    Ok(UdpDatagram {
        source,
        destination,
        source_port,
        destination_port,
        payload: &bytes[8..length],
    })
}

/// Builds a minimal valid IPv4 TCP packet.
///
/// This writer emits no TCP options and is intended only for responses injected
/// into the local packet tunnel.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 40usize.saturating_add(payload.len());
    if total_len > usize::from(u16::MAX) {
        return Vec::new();
    }
    let mut output = vec![0u8; total_len];
    output[0] = 0x45;
    output[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    output[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    output[8] = 64;
    output[9] = 6;
    output[12..16].copy_from_slice(&source.octets());
    output[16..20].copy_from_slice(&destination.octets());
    output[20..22].copy_from_slice(&source_port.to_be_bytes());
    output[22..24].copy_from_slice(&destination_port.to_be_bytes());
    output[24..28].copy_from_slice(&sequence.to_be_bytes());
    output[28..32].copy_from_slice(&acknowledgement.to_be_bytes());
    output[32] = 5 << 4;
    output[33] = flags.bits();
    output[34..36].copy_from_slice(&window.to_be_bytes());
    output[40..].copy_from_slice(payload);
    let tcp_checksum = transport_checksum(source, destination, 6, &output[20..]);
    output[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
    let ip_checksum = checksum(&output[..20]);
    output[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    output
}

/// Builds a valid IPv4 UDP packet for a locally synthesized DNS response.
pub fn build_udp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8usize.saturating_add(payload.len());
    let total_len = 20usize.saturating_add(udp_len);
    if total_len > usize::from(u16::MAX) {
        return Vec::new();
    }
    let mut output = vec![0u8; total_len];
    output[0] = 0x45;
    output[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    output[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    output[8] = 64;
    output[9] = 17;
    output[12..16].copy_from_slice(&source.octets());
    output[16..20].copy_from_slice(&destination.octets());
    output[20..22].copy_from_slice(&source_port.to_be_bytes());
    output[22..24].copy_from_slice(&destination_port.to_be_bytes());
    output[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    output[28..].copy_from_slice(payload);
    let udp_checksum = transport_checksum(source, destination, 17, &output[20..]);
    output[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    let ip_checksum = checksum(&output[..20]);
    output[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    output
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(*byte) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn transport_checksum(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, bytes: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + bytes.len() + (bytes.len() % 2));
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(bytes);
    checksum(&pseudo)
}
