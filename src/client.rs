use crate::config::Config;
use crate::packet;
use anyhow::Result;
use quinn::crypto::rustls::QuicClientConfig;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

const QUIC_CONNECT_TIMEOUT_SECS: u64 = 30;

pub async fn run(config: Arc<Config>) -> Result<()> {
    loop {
        info!("Starting client...");
        match run_inner(config.clone()).await {
            Ok(()) => {
                info!("Client exited normally");
            }
            Err(e) => {
                error!("Client error: {}. Restarting in 1s...", e);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn run_inner(config: Arc<Config>) -> Result<()> {
    let vps_ip: Ipv4Addr = config.general.vps_ip.parse()?;

    // Resolve local IP used to reach VPS (needed for correct TCP checksum)
    let local_ip = packet::get_local_ip(vps_ip)?;
    warn!("Local IP for violation packets: {}", local_ip);

    // Channel: sniffer -> async world
    let (sniff_tx, sniff_rx) = mpsc::channel::<Vec<u8>>(4096);

    // Start packet sniffer in dedicated thread
    start_sniffer(sniff_tx, vps_ip, config.violation.tcp_server_port);

    // Start violation bridge tasks (returns handles for cleanup)
    let (vio_handle1, vio_handle2) =
        start_violation_bridge(config.clone(), sniff_rx, vps_ip, local_ip).await?;

    // Run QUIC client (blocks until connection fails or forwarders stop)
    let result = run_quic_client(config.clone()).await;

    // Abort bridge tasks so ports are released for restart
    vio_handle1.abort();
    vio_handle2.abort();

    result
}

/// Sniffer thread: captures TCP packets from VPS with AP flags.
fn start_sniffer(tx: mpsc::Sender<Vec<u8>>, vps_ip: Ipv4Addr, vio_server_port: u16) {
    std::thread::spawn(move || {
        let fd = match packet::create_sniffer_socket() {
            Ok(fd) => fd,
            Err(e) => {
                error!("Failed to create sniffer socket (need root): {}", e);
                return;
            }
        };
        info!("Client sniffer started, watching for packets from {}", vps_ip);
        let mut buf = [0u8; 65535];
        loop {
            let n = packet::recv_raw_packet(fd.as_fd(), &mut buf);
            if n == 0 {
                continue;
            }
            if let Some(parsed) = packet::parse_ip_tcp(&buf[..n]) {
                // Filter: from VPS, from violation server port, AP flags
                if parsed.src_ip == vps_ip
                    && parsed.src_port == vio_server_port
                    && packet::is_ap_flags(parsed.flags)
                    && !parsed.payload.is_empty()
                {
                    if tx.blocking_send(parsed.payload).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

/// Start violation bridge tasks. Returns JoinHandles so caller can abort on cleanup.
async fn start_violation_bridge(
    config: Arc<Config>,
    sniff_rx: mpsc::Receiver<Vec<u8>>,
    vps_ip: Ipv4Addr,
    local_ip: Ipv4Addr,
) -> Result<(JoinHandle<()>, JoinHandle<()>)> {
    let quic_addr: SocketAddr =
        format!("{}:{}", config.quic.local_ip, config.quic.client_port).parse()?;
    let vio_tcp_client_port = config.violation.tcp_client_port;
    let vio_tcp_server_port = config.violation.tcp_server_port;

    // Create raw sender socket
    let sender_fd = packet::create_sender_socket()?;

    info!(
        "VIO bridge: quic:{} -> violated tcp:{}",
        config.violation.udp_client_port, vio_tcp_server_port
    );

    // Bind UDP socket on loopback - Quinn connects to 127.0.0.1:udp_client_port,
    // so responses must come FROM 127.0.0.1 to match the expected server address.
    let udp = UdpSocket::bind(format!("{}:{}", config.quic.local_ip, config.violation.udp_client_port)).await?;
    let udp = Arc::new(udp);

    let udp_send = udp.clone();
    let udp_recv = udp.clone();

    // Track the QUIC client's actual source address dynamically.
    // Quinn may send from different local IPs via PKTINFO, so we must
    // send responses back to whatever address it actually used.
    let quic_client_addr = Arc::new(tokio::sync::Mutex::new(quic_addr));
    let addr_writer = quic_client_addr.clone();
    let addr_reader = quic_client_addr.clone();

    // Task 1: Sniffed violation responses -> QUIC client (via UDP)
    let vio_to_quic = tokio::spawn(async move {
        let mut recv_count: u64 = 0;
        let mut sniff_rx = sniff_rx;
        while let Some(payload) = sniff_rx.recv().await {
            let target = *addr_reader.lock().await;
            recv_count += 1;
            if recv_count <= 5 {
                info!("VIO: sniffed response #{} ({} bytes) -> UDP to QUIC at {}", recv_count, payload.len(), target);
            }
            if let Err(e) = udp_send.send_to(&payload, &target).await {
                warn!("Failed to forward to QUIC client: {}", e);
                break;
            }
        }
    });

    // Task 2: QUIC client packets (via UDP) -> violation raw TCP
    let quic_to_vio = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        let mut pkt_count: u64 = 0;
        loop {
            match udp_recv.recv_from(&mut buf).await {
                Ok((n, from_addr)) if n > 0 => {
                    // Update the QUIC client's address from the actual source
                    *addr_writer.lock().await = from_addr;
                    pkt_count += 1;
                    if pkt_count <= 5 {
                        info!("VIO: UDP packet #{} from {} ({} bytes) -> raw TCP to {}", pkt_count, from_addr, n, vps_ip);
                    }
                    let pkt = packet::build_violation_packet(
                        local_ip,
                        vps_ip,
                        vio_tcp_client_port,
                        vio_tcp_server_port,
                        &buf[..n],
                    );
                    packet::send_raw_packet(sender_fd.as_fd(), &pkt, vps_ip);
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("UDP recv error: {}", e);
                    break;
                }
            }
        }
    });

    Ok((vio_to_quic, quic_to_vio))
}

/// QUIC tunnel client: connects through the violation layer and provides port forwarding.
async fn run_quic_client(config: Arc<Config>) -> Result<()> {
    let client_config = build_client_config(&config)?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", config.quic.client_port).parse()?;
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let server_addr: SocketAddr =
        format!("{}:{}", config.quic.local_ip, config.violation.udp_client_port).parse()?;

    warn!("Connecting to QUIC server via violation layer...");
    let connecting = endpoint.connect(server_addr, "proxy")?;
    let connection = tokio::time::timeout(
        std::time::Duration::from_secs(QUIC_CONNECT_TIMEOUT_SECS),
        connecting,
    )
    .await
    .map_err(|_| anyhow::anyhow!("QUIC connection timed out after {}s", QUIC_CONNECT_TIMEOUT_SECS))??;
    warn!("QUIC connection established!");

    let connection = Arc::new(connection);

    // Start TCP port forwarding servers
    let mut tasks = Vec::new();
    for (&local_port, &target_port) in &config.ports.tcp_mapping {
        let conn = connection.clone();
        let auth = config.quic.auth_code.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = run_tcp_forwarder(conn, local_port, target_port, auth).await {
                error!("TCP forwarder {}:{} error: {}", local_port, target_port, e);
            }
        }));
    }

    // Start UDP port forwarding servers
    for (&local_port, &target_port) in &config.ports.udp_mapping {
        let conn = connection.clone();
        let auth = config.quic.auth_code.clone();
        let timeout = config.quic.udp_timeout_secs;
        tasks.push(tokio::spawn(async move {
            if let Err(e) = run_udp_forwarder(conn, local_port, target_port, auth, timeout).await {
                error!("UDP forwarder {}:{} error: {}", local_port, target_port, e);
            }
        }));
    }

    // Wait for connection to close or all tasks to finish
    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

/// TCP port forwarder: listens on local_port, proxies to remote target_port via QUIC.
async fn run_tcp_forwarder(
    connection: Arc<quinn::Connection>,
    local_port: u16,
    target_port: u16,
    auth_code: String,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", local_port)).await?;
    warn!("TCP forwarder: listen {} -> remote {}", local_port, target_port);

    loop {
        let (stream, addr) = listener.accept().await?;
        info!("TCP connection from {} on port {}", addr, local_port);
        let conn = connection.clone();
        let auth = auth_code.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_client(stream, conn, target_port, auth).await {
                info!("TCP client {} error: {}", addr, e);
            }
        });
    }
}

/// Handle a single TCP client connection: open QUIC stream, handshake, proxy.
async fn handle_tcp_client(
    tcp_stream: tokio::net::TcpStream,
    connection: Arc<quinn::Connection>,
    target_port: u16,
    auth_code: String,
) -> Result<()> {
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send handshake
    let req = format!("{}connect,tcp,{},!###!", auth_code, target_port);
    send.write_all(req.as_bytes()).await?;

    // Wait for ready response
    let expected = format!("{}i am ready,!###!", auth_code);
    let mut resp_buf = Vec::with_capacity(expected.len() + 16);
    let mut tmp = [0u8; 256];
    loop {
        match recv.read(&mut tmp).await? {
            Some(n) => {
                resp_buf.extend_from_slice(&tmp[..n]);
                if resp_buf.len() >= expected.len() {
                    break;
                }
            }
            None => anyhow::bail!("Stream closed waiting for ready"),
        }
    }

    let resp = String::from_utf8_lossy(&resp_buf);
    if !resp.starts_with(&expected) {
        anyhow::bail!("Unexpected response: {}", resp);
    }

    // Check if there's extra data after the handshake response
    let extra_data = if resp_buf.len() > expected.len() {
        Some(resp_buf[expected.len()..].to_vec())
    } else {
        None
    };

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Write any extra data that came with the handshake response
    if let Some(extra) = extra_data {
        tcp_write.write_all(&extra).await?;
    }

    // Bidirectional forwarding
    let quic_to_tcp = async {
        let mut buf = [0u8; 4096];
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
    };

    let tcp_to_quic = async {
        let mut buf = [0u8; 4096];
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
    };

    tokio::select! {
        _ = quic_to_tcp => {}
        _ = tcp_to_quic => {}
    }

    let _ = send.finish();
    Ok(())
}

/// UDP port forwarder: listens on local_port, proxies to remote target_port via QUIC.
async fn run_udp_forwarder(
    connection: Arc<quinn::Connection>,
    local_port: u16,
    target_port: u16,
    auth_code: String,
    udp_timeout: u64,
) -> Result<()> {
    let udp = UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?;
    warn!("UDP forwarder: listen {} -> remote {}", local_port, target_port);

    let udp = Arc::new(udp);

    // Track addr -> stream mapping
    let addr_to_stream: Arc<tokio::sync::Mutex<HashMap<SocketAddr, StreamHandle>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let mut buf = [0u8; 65535];
    loop {
        let (n, addr) = udp.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();

        let mut map = addr_to_stream.lock().await;
        if let Some(handle) = map.get(&addr) {
            // Send on existing stream
            if handle.tx.send(data).await.is_err() {
                map.remove(&addr);
            }
        } else {
            // Create new QUIC stream for this UDP address
            let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
            let conn = connection.clone();
            let auth = auth_code.clone();
            let udp2 = udp.clone();
            let map2 = addr_to_stream.clone();

            let handle = StreamHandle { tx };
            if handle.tx.send(data).await.is_ok() {
                map.insert(addr, handle);
            }

            tokio::spawn(async move {
                if let Err(e) =
                    handle_udp_stream(conn, rx, udp2, addr, target_port, auth, udp_timeout).await
                {
                    info!("UDP stream for {} error: {}", addr, e);
                }
                map2.lock().await.remove(&addr);
            });
        }
    }
}

struct StreamHandle {
    tx: mpsc::Sender<Vec<u8>>,
}

/// Handle a single UDP stream: open QUIC stream, handshake, proxy datagrams.
async fn handle_udp_stream(
    connection: Arc<quinn::Connection>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    udp: Arc<UdpSocket>,
    client_addr: SocketAddr,
    target_port: u16,
    auth_code: String,
    timeout_secs: u64,
) -> Result<()> {
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send handshake
    let req = format!("{}connect,udp,{},!###!", auth_code, target_port);
    send.write_all(req.as_bytes()).await?;

    // Wait for ready response
    let expected = format!("{}i am ready,!###!", auth_code);
    let mut resp_buf = Vec::with_capacity(expected.len() + 16);
    let mut tmp = [0u8; 256];
    loop {
        match recv.read(&mut tmp).await? {
            Some(n) => {
                resp_buf.extend_from_slice(&tmp[..n]);
                if resp_buf.len() >= expected.len() {
                    break;
                }
            }
            None => anyhow::bail!("Stream closed waiting for ready"),
        }
    }

    let last_activity = Arc::new(tokio::sync::Mutex::new(Instant::now()));

    // Local -> QUIC: send length-prefixed datagrams
    let la1 = last_activity.clone();
    let local_to_quic = async move {
        while let Some(data) = rx.recv().await {
            let len = (data.len() as u16).to_be_bytes();
            if send.write_all(&len).await.is_err() {
                break;
            }
            if send.write_all(&data).await.is_err() {
                break;
            }
            *la1.lock().await = Instant::now();
        }
    };

    // QUIC -> Local: receive length-prefixed datagrams
    let la2 = last_activity.clone();
    let quic_to_local = async move {
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
            if udp.send_to(&data, &client_addr).await.is_err() {
                break;
            }
            *la2.lock().await = Instant::now();
        }
    };

    // Timeout checker
    let la3 = last_activity.clone();
    let timeout_check = async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(timeout_secs.min(60))).await;
            if la3.lock().await.elapsed().as_secs() > timeout_secs {
                info!("UDP stream for {} timed out", client_addr);
                break;
            }
        }
    };

    tokio::select! {
        _ = local_to_quic => {}
        _ = quic_to_local => {}
        _ = timeout_check => {}
    }

    Ok(())
}

/// Build Quinn client configuration.
fn build_client_config(config: &Config) -> Result<quinn::ClientConfig> {
    let crypto = if config.quic.verify_cert {
        // Load cert.pem as trusted root for verification
        let cert_pem = std::fs::read(&config.quic.cert_path)?;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .filter_map(|r| r.ok())
                .collect();
        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert)?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerification))
            .with_no_client_auth()
    };

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(config.quic.idle_timeout_secs))?,
    ));
    transport.initial_mtu(config.quic.mtu);

    let max_data = quinn::VarInt::from_u64(config.quic.max_data)
        .unwrap_or(quinn::VarInt::from_u32(1_073_741_824));
    let max_stream = quinn::VarInt::from_u64(config.quic.max_stream_data)
        .unwrap_or(quinn::VarInt::from_u32(1_073_741_824));
    transport.receive_window(max_data);
    transport.stream_receive_window(max_stream);
    transport.send_window(config.quic.max_data);

    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

/// Certificate verifier that skips all verification (for self-signed certs).
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
