use std::net::Ipv4Addr;
use tracing::warn;

// TCP flags
const TCP_ACK: u8 = 0x10;
const TCP_PSH: u8 = 0x08;
const TCP_AP: u8 = TCP_ACK | TCP_PSH;

// TCP options: MSS(1280), NOP, WScale(8), SAckOK, NOP, NOP
const TCP_OPTIONS: [u8; 12] = [
    0x02, 0x04, 0x05, 0x00, // MSS = 1280
    0x01,                   // NOP (padding)
    0x03, 0x03, 0x08,       // Window Scale = 8
    0x04, 0x02,             // SACK Permitted
    0x01, 0x01,             // NOP, NOP (padding to 4-byte boundary)
];

const IP_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20 + TCP_OPTIONS.len(); // 32 bytes

#[derive(Debug)]
pub struct ParsedPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub payload: Vec<u8>,
}

/// Build a raw IP+TCP violation packet with ACK|PSH flags and custom TCP options.
pub fn build_violation_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = IP_HEADER_LEN + TCP_HEADER_LEN + payload.len();
    let mut pkt = vec![0u8; total_len];

    // === IP Header (20 bytes) ===
    pkt[0] = 0x45; // Version=4, IHL=5
    // pkt[1] = 0x00; // DSCP/ECN
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    // pkt[4..6] = identification (kernel fills if 0)
    // pkt[6..8] = flags + fragment offset = 0 (no DF, matching scapy default)
    pkt[8] = 64; // TTL
    pkt[9] = 6;  // Protocol: TCP
    // pkt[10..12] = checksum (kernel computes when 0)
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // === TCP Header (32 bytes with options) ===
    let t = IP_HEADER_LEN;
    pkt[t..t + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[t + 2..t + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[t + 4..t + 8].copy_from_slice(&1u32.to_be_bytes()); // Seq = 1
    // pkt[t+8..t+12] = Ack = 0
    pkt[t + 12] = ((TCP_HEADER_LEN / 4) as u8) << 4; // Data offset
    pkt[t + 13] = TCP_AP; // Flags: ACK | PSH
    pkt[t + 14..t + 16].copy_from_slice(&65535u16.to_be_bytes()); // Window
    // pkt[t+16..t+18] = checksum (computed below)
    // pkt[t+18..t+20] = urgent pointer = 0

    // TCP Options
    pkt[t + 20..t + 32].copy_from_slice(&TCP_OPTIONS);

    // Payload
    if !payload.is_empty() {
        pkt[t + TCP_HEADER_LEN..].copy_from_slice(payload);
    }

    // Compute TCP checksum
    let tcp_total = TCP_HEADER_LEN + payload.len();
    let checksum = tcp_checksum(&src_ip.octets(), &dst_ip.octets(), &pkt[t..t + tcp_total]);
    pkt[t + 16..t + 18].copy_from_slice(&checksum.to_be_bytes());

    pkt
}

/// Compute TCP checksum over pseudo-header + TCP segment.
fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // Protocol: TCP
    sum += tcp_segment.len() as u32;

    // TCP segment (16-bit words)
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    // Handle odd byte
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }

    // Fold carry bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Parse a raw IP packet (no ethernet header) into structured fields.
/// Returns None if not a TCP packet or if parsing fails.
pub fn parse_ip_tcp(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 40 {
        return None; // Too short for IP(20) + TCP(20)
    }

    // Check IP version
    if (data[0] >> 4) != 4 {
        return None;
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }

    // Check protocol is TCP
    if data[9] != 6 {
        return None;
    }

    let ip_total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    // TCP header
    if data.len() < ihl + 20 {
        return None;
    }
    let t = ihl;
    let src_port = u16::from_be_bytes([data[t], data[t + 1]]);
    let dst_port = u16::from_be_bytes([data[t + 2], data[t + 3]]);
    let data_offset = ((data[t + 12] >> 4) as usize) * 4;
    let flags = data[t + 13];

    let payload_start = t + data_offset;
    let payload_end = ip_total_len.min(data.len());

    let payload = if payload_start < payload_end {
        data[payload_start..payload_end].to_vec()
    } else {
        Vec::new()
    };

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        flags,
        payload,
    })
}

/// Check if TCP flags are exactly ACK|PSH.
pub fn is_ap_flags(flags: u8) -> bool {
    flags & TCP_AP == TCP_AP
}

/// Create a raw sender socket (AF_INET, SOCK_RAW, IPPROTO_RAW).
/// Requires root privileges.
pub fn create_sender_socket() -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let fd = unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Create a raw sniffer socket (AF_PACKET, SOCK_DGRAM, ETH_P_IP).
/// Captures all IP packets before iptables processing.
/// Requires root privileges.
pub fn create_sniffer_socket() -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    const ETH_P_IP: u16 = 0x0800;
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM,
            (ETH_P_IP).to_be() as libc::c_int,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Send a raw IP packet via the sender socket. Returns bytes sent or -1 on error.
pub fn send_raw_packet(fd: std::os::fd::BorrowedFd<'_>, packet: &[u8], dst_ip: Ipv4Addr) -> isize {
    use std::os::fd::AsRawFd;
    let dst_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst_ip).to_be(),
        },
        sin_zero: [0; 8],
    };
    let ret = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            packet.as_ptr() as *const _,
            packet.len(),
            0,
            &dst_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        warn!("sendto failed: {} (packet_len={}, dst={})", err, packet.len(), dst_ip);
    }
    ret
}

/// Determine the local IP address used to reach a given target IP.
/// Uses a connected UDP socket trick (no actual packets sent).
pub fn get_local_ip(target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(std::net::SocketAddr::new(target.into(), 80))?;
    match socket.local_addr()?.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        _ => Err(std::io::Error::new(std::io::ErrorKind::Other, "not IPv4")),
    }
}

/// Receive a raw IP packet from the sniffer socket.
/// Returns the number of bytes read, or 0 on error.
pub fn recv_raw_packet(fd: std::os::fd::BorrowedFd<'_>, buf: &mut [u8]) -> usize {
    use std::os::fd::AsRawFd;
    let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len(), 0) };
    if n < 0 {
        0
    } else {
        n as usize
    }
}
