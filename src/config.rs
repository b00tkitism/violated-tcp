use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub general: General,
    pub ports: Ports,
    pub violation: Violation,
    pub quic: Quic,
}

#[derive(Debug, Deserialize)]
pub struct General {
    pub vps_ip: String,
    #[serde(default = "default_xray_ip")]
    pub xray_server_ip: String,
}

fn default_xray_ip() -> String {
    "127.0.0.1".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Ports {
    #[serde(default)]
    pub tcp_mapping: HashMap<u16, u16>,
    #[serde(default)]
    pub udp_mapping: HashMap<u16, u16>,
}

#[derive(Debug, Deserialize)]
pub struct Violation {
    #[serde(default = "default_vio_tcp_server_port")]
    pub tcp_server_port: u16,
    #[serde(default = "default_vio_tcp_client_port")]
    pub tcp_client_port: u16,
    #[serde(default = "default_vio_udp_server_port")]
    pub udp_server_port: u16,
    #[serde(default = "default_vio_udp_client_port")]
    pub udp_client_port: u16,
}

fn default_vio_tcp_server_port() -> u16 { 45000 }
fn default_vio_tcp_client_port() -> u16 { 40000 }
fn default_vio_udp_server_port() -> u16 { 35000 }
fn default_vio_udp_client_port() -> u16 { 30000 }

#[derive(Debug, Deserialize)]
pub struct Quic {
    #[serde(default = "default_quic_server_port")]
    pub server_port: u16,
    #[serde(default = "default_quic_client_port")]
    pub client_port: u16,
    #[serde(default = "default_quic_local_ip")]
    pub local_ip: String,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout_secs: u64,
    #[serde(default)]
    pub verify_cert: bool,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default = "default_cert_path")]
    pub cert_path: String,
    #[serde(default = "default_key_path")]
    pub key_path: String,
    #[serde(default = "default_max_data")]
    pub max_data: u64,
    #[serde(default = "default_max_stream_data")]
    pub max_stream_data: u64,
    #[serde(default = "default_auth_code")]
    pub auth_code: String,
}

fn default_quic_server_port() -> u16 { 25000 }
fn default_quic_client_port() -> u16 { 20000 }
fn default_quic_local_ip() -> String { "127.0.0.1".to_string() }
fn default_idle_timeout() -> u64 { 86400 }
fn default_udp_timeout() -> u64 { 300 }
fn default_mtu() -> u16 { 1420 }
fn default_cert_path() -> String { "cert.pem".to_string() }
fn default_key_path() -> String { "key.pem".to_string() }
fn default_max_data() -> u64 { 1_073_741_824 }
fn default_max_stream_data() -> u64 { 1_073_741_824 }
fn default_auth_code() -> String { "jd!gn0s4".to_string() }

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
