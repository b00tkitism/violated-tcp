use crate::config::Config;
use crate::packet;
use anyhow::Result;
use quinn::crypto::rustls::QuicServerConfig;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

const BUF_SIZE: usize = 65536;

fn pack_addr(ip: Ipv4Addr, port: u16) -> u64 {
    ((u32::from(ip) as u64) << 16) | (port as u64)
}

fn unpack_addr(val: u64) -> (Ipv4Addr, u16) {
    let port = (val & 0xFFFF) as u16;
    let ip = ((val >> 16) & 0xFFFFFFFF) as u32;
    (Ipv4Addr::from(ip), port)
}

/// Data sniffed from a violation TCP packet (server side).
struct SniffedData {
    payload: Vec<u8>,
    client_ip: Ipv4Addr,
    client_port: u16,
}

pub async fn run(config: Arc<Config>) -> Result<()> {
    // Channel: sniffer -> vio_to_quic forwarder
    let (sniff_tx, sniff_rx) = mpsc::channel::<SniffedData>(4096);

    // Start the packet sniffer in a dedicated thread
    let vps_ip: Ipv4Addr = config.general.vps_ip.parse()?;
    let vio_tcp_server_port = config.violation.tcp_server_port;
    start_sniffer(sniff_tx, vps_ip, vio_tcp_server_port);

    // Start violation UDP bridge and QUIC server concurrently
    let config2 = config.clone();
    tokio::try_join!(
        run_violation_bridge(config.clone(), sniff_rx, vps_ip),
        run_quic_server(config2),
    )?;

    Ok(())
}

/// Sniffer thread: captures all TCP packets, filters for violation AP packets
/// destined for our server port, and sends them to the async world via channel.
fn start_sniffer(tx: mpsc::Sender<SniffedData>, vps_ip: Ipv4Addr, vio_port: u16) {
    std::thread::spawn(move || {
        let fd = match packet::create_sniffer_socket() {
            Ok(fd) => fd,
            Err(e) => {
                error!("Failed to create sniffer socket (need root): {}", e);
                return;
            }
        };
        // BPF filter: only deliver packets to vps_ip:vio_port with AP flags
        if let Err(e) = packet::attach_sniffer_filter(fd.as_fd(), vps_ip, vio_port, false) {
            warn!("Failed to attach BPF filter: {} (falling back to userspace filter)", e);
        }
        info!("Server sniffer started on violation port {}", vio_port);
        let mut buf = [0u8; 65535];
        loop {
            let n = packet::recv_raw_packet(fd.as_fd(), &mut buf);
            if n == 0 {
                continue;
            }
            if let Some(parsed) = packet::parse_ip_tcp(&buf[..n]) {
                // Filter: dst is us, dst port is violation port, flags are AP
                if parsed.dst_ip == vps_ip
                    && parsed.dst_port == vio_port
                    && packet::is_ap_flags(parsed.flags)
                    && !parsed.payload.is_empty()
                {
                    let data = SniffedData {
                        payload: parsed.payload.clone(),
                        client_ip: parsed.src_ip,
                        client_port: parsed.src_port,
                    };
                    tracing::debug!("SNIFF: {} bytes from {}:{}", parsed.payload.len(), parsed.src_ip, parsed.src_port);
                    if tx.blocking_send(data).is_err() {
                        break; // Channel closed
                    }
                }
            }
        }
    });
}

/// Violation bridge: connects the raw packet layer to the QUIC layer via UDP loopback.
async fn run_violation_bridge(
    config: Arc<Config>,
    mut sniff_rx: mpsc::Receiver<SniffedData>,
    vps_ip: Ipv4Addr,
) -> Result<()> {
    let vio_tcp_server_port = config.violation.tcp_server_port;
    let quic_addr: SocketAddr = format!("{}:{}", config.quic.local_ip, config.quic.server_port).parse()?;

    // Create raw sender socket
    let sender_fd = packet::create_sender_socket()?;

    // Lock-free client address tracking (same pattern as client.rs)
    let client_addr = Arc::new(AtomicU64::new(pack_addr(Ipv4Addr::new(1, 1, 1, 1), 443)));

    info!(
        "VIO bridge: violated tcp:{} -> quic {}",
        vio_tcp_server_port, quic_addr
    );

    // Bind UDP socket for communication with QUIC server
    let udp = UdpSocket::bind(format!("{}:{}", config.quic.local_ip, config.violation.udp_server_port)).await?;
    udp.connect(&quic_addr).await?;
    let udp = Arc::new(udp);

    let udp_send = udp.clone();
    let udp_recv = udp.clone();
    let addr_writer = client_addr.clone();
    let addr_reader = client_addr.clone();

    // Create a new sender FD reference for the response task
    let sender_fd2 = packet::create_sender_socket()?;

    // Task 1: Forward sniffed violation packets -> QUIC (via UDP)
    let vio_to_quic = tokio::spawn(async move {
        while let Some(data) = sniff_rx.recv().await {
            // Update latest client address (lock-free)
            addr_writer.store(pack_addr(data.client_ip, data.client_port), Ordering::Relaxed);
            if let Err(e) = udp_send.send(&data.payload).await {
                warn!("Failed to send to QUIC: {}", e);
                break;
            }
        }
    });

    // Task 2: Forward QUIC responses (via UDP) -> violation TCP
    let vio_srv_port = vio_tcp_server_port;
    let quic_to_vio = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            match udp_recv.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    let (cip, cport) = unpack_addr(addr_reader.load(Ordering::Relaxed));
                    let pkt = packet::build_violation_packet(
                        vps_ip,
                        cip,
                        vio_srv_port,
                        cport,
                        &buf[..n],
                    );
                    packet::send_raw_packet(sender_fd2.as_fd(), &pkt, cip);
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("UDP recv error: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = vio_to_quic => { warn!("vio_to_quic task ended"); }
        _ = quic_to_vio => { warn!("quic_to_vio task ended"); }
    }

    let _ = sender_fd;
    Ok(())
}

/// QUIC tunnel server: accepts QUIC connections and proxies streams to backend services.
async fn run_quic_server(config: Arc<Config>) -> Result<()> {
    let server_config = build_server_config(&config)?;
    let bind_addr: SocketAddr = format!("{}:{}", config.quic.local_ip, config.quic.server_port).parse()?;
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    warn!("QUIC server listening on {}", bind_addr);

    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    info!("QUIC connection established from {:?}", connection.remote_address());
                    handle_connection(connection, config).await;
                }
                Err(e) => {
                    error!("QUIC connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}

/// Handle a single QUIC connection: accept streams and proxy to backends.
async fn handle_connection(connection: quinn::Connection, config: Arc<Config>) {
    // Track active UDP connections for cleanup
    let udp_last_activity: Arc<tokio::sync::Mutex<HashMap<u64, Instant>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Spawn UDP cleanup task
    let activity_clone = udp_last_activity.clone();
    let timeout = config.quic.udp_timeout_secs;
    tokio::spawn(async move {
        let check_interval = timeout.min(60);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(check_interval)).await;
            let mut map = activity_clone.lock().await;
            let stale: Vec<u64> = map
                .iter()
                .filter(|(_, last)| last.elapsed().as_secs() > timeout)
                .map(|(id, _)| *id)
                .collect();
            for id in stale {
                info!("UDP stream {} timed out", id);
                map.remove(&id);
            }
        }
    });

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let config = config.clone();
                let activity = udp_last_activity.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv, config, activity).await {
                        info!("Stream error: {}", e);
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                info!("QUIC connection closed by client");
                break;
            }
            Err(e) => {
                error!("Failed to accept stream: {}", e);
                break;
            }
        }
    }
}

/// Handle a single QUIC stream: read handshake, connect to backend, proxy data.
async fn handle_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    config: Arc<Config>,
    udp_activity: Arc<tokio::sync::Mutex<HashMap<u64, Instant>>>,
) -> Result<()> {
    let stream_id = send.id().index();

    // Read handshake: {auth_code}connect,{tcp|udp},{port},!###!
    let mut handshake_buf = Vec::with_capacity(256);
    let delimiter = b",!###!";
    let mut tmp = [0u8; 256];
    loop {
        match recv.read(&mut tmp).await? {
            Some(n) => {
                handshake_buf.extend_from_slice(&tmp[..n]);
                if handshake_buf
                    .windows(delimiter.len())
                    .any(|w| w == delimiter)
                {
                    break;
                }
                if handshake_buf.len() > 1024 {
                    anyhow::bail!("Handshake too long");
                }
            }
            None => anyhow::bail!("Stream closed during handshake"),
        }
    }

    let handshake = String::from_utf8_lossy(&handshake_buf);
    let prefix = format!("{}connect,", config.quic.auth_code);

    if !handshake.starts_with(&prefix) {
        anyhow::bail!("Invalid auth or handshake: {}", handshake);
    }

    // Parse: connect,{tcp|udp},{port},!###!
    let after_prefix = &handshake[prefix.len()..];
    let parts: Vec<&str> = after_prefix.splitn(3, ',').collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid handshake format");
    }

    let proto = parts[0];
    let port_str = parts[1].trim_end_matches(",!###!");
    let port: u16 = port_str.parse().map_err(|_| anyhow::anyhow!("Invalid port: {}", port_str))?;

    info!("Stream {}: connect {} to port {}", stream_id, proto, port);

    match proto {
        "tcp" => handle_tcp_proxy(send, recv, &config, port).await,
        "udp" => handle_udp_proxy(send, recv, &config, port, stream_id as u64, udp_activity).await,
        _ => anyhow::bail!("Unknown protocol: {}", proto),
    }
}

/// Proxy a TCP connection: QUIC stream <-> TCP socket to backend.
async fn handle_tcp_proxy(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    config: &Config,
    target_port: u16,
) -> Result<()> {
    // Connect to backend
    let backend = tokio::net::TcpStream::connect(format!(
        "{}:{}",
        config.general.xray_server_ip, target_port
    ))
    .await?;
    backend.set_nodelay(true)?;
    info!("TCP connected to backend {}:{}", config.general.xray_server_ip, target_port);

    let (mut tcp_read, mut tcp_write) = backend.into_split();

    // Send ready response
    let ready = format!("{}i am ready,!###!", config.quic.auth_code);
    send.write_all(ready.as_bytes()).await?;

    // Bidirectional forwarding with proper half-close.
    // Using join! instead of select! so one direction finishing doesn't
    // kill the other — critical for long-lived connections like SSH.
    let quic_to_tcp = async {
        let mut buf = [0u8; BUF_SIZE];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if tcp_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    let tcp_to_quic = async {
        let mut buf = [0u8; BUF_SIZE];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = send.finish();
    };

    tokio::join!(quic_to_tcp, tcp_to_quic);
    info!("TCP proxy stream closed");
    Ok(())
}

/// Proxy a UDP connection: QUIC stream <-> UDP socket to backend.
async fn handle_udp_proxy(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    config: &Config,
    target_port: u16,
    stream_id: u64,
    activity: Arc<tokio::sync::Mutex<HashMap<u64, Instant>>>,
) -> Result<()> {
    // Create UDP socket to backend
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(format!("{}:{}", config.general.xray_server_ip, target_port)).await?;
    info!("UDP connected to backend {}:{}", config.general.xray_server_ip, target_port);

    activity.lock().await.insert(stream_id, Instant::now());
    let udp = Arc::new(udp);

    // Send ready response
    let ready = format!("{}i am ready,!###!", config.quic.auth_code);
    send.write_all(ready.as_bytes()).await?;

    let udp_send = udp.clone();
    let udp_recv = udp.clone();
    let activity2 = activity.clone();

    // QUIC -> UDP: read length-prefixed datagrams from QUIC, send to backend
    let quic_to_udp = async move {
        let mut len_buf = [0u8; 2];
        loop {
            match recv.read_exact(&mut len_buf).await {
                Ok(()) => {}
                Err(_) => break,
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut data = vec![0u8; len];
            match recv.read_exact(&mut data).await {
                Ok(()) => {}
                Err(_) => break,
            }
            if udp_send.send(&data).await.is_err() {
                break;
            }
            activity2.lock().await.insert(stream_id, Instant::now());
        }
    };

    // UDP -> QUIC: receive from backend, send length-prefixed to QUIC
    let tcp_to_quic = async move {
        let mut buf = [0u8; 65535];
        loop {
            match udp_recv.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    let len_bytes = (n as u16).to_be_bytes();
                    if send.write_all(&len_bytes).await.is_err() {
                        break;
                    }
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    };

    tokio::select! {
        _ = quic_to_udp => {}
        _ = tcp_to_quic => {}
    }

    activity.lock().await.remove(&stream_id);
    info!("UDP proxy stream {} closed", stream_id);
    Ok(())
}

/// Build Quinn server configuration with TLS certificate.
fn build_server_config(config: &Config) -> Result<quinn::ServerConfig> {
    let cert_pem = std::fs::read(&config.quic.cert_path)?;
    let key_pem = std::fs::read(&config.quic.key_path)?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..])
            .filter_map(|r| r.ok())
            .collect();
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", config.quic.cert_path);
    }

    let key = rustls_pemfile::private_key(&mut &key_pem[..])?.ok_or_else(|| {
        anyhow::anyhow!("No private key found in {}", config.quic.key_path)
    })?;

    let crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())?;

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(config.quic.idle_timeout_secs))?,
    ));
    transport.initial_mtu(config.quic.mtu);
    transport.mtu_discovery_config(None);
    transport.initial_rtt(std::time::Duration::from_millis(config.quic.initial_rtt_ms));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));

    let max_data = quinn::VarInt::from_u64(config.quic.max_data)
        .unwrap_or(quinn::VarInt::from_u32(1_073_741_824));
    let max_stream = quinn::VarInt::from_u64(config.quic.max_stream_data)
        .unwrap_or(quinn::VarInt::from_u32(1_073_741_824));
    transport.receive_window(max_data);
    transport.stream_receive_window(max_stream);
    transport.send_window(config.quic.max_data);

    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}
