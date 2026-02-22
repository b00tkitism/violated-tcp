#!/bin/bash
set -e

echo "========================================="
echo "  GFW-Resist Proxy - Server Setup"
echo "========================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root (required for raw sockets and firewall)"
    exit 1
fi

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "[*] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "[+] Rust installed"
else
    echo "[+] Rust already installed"
fi

# Build the project
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[*] Building project (release mode)..."
cd "$SCRIPT_DIR"
cargo build --release
echo "[+] Build complete: target/release/gfw-resist-proxy"

# Generate TLS certificates
if [ ! -f cert.pem ] || [ ! -f key.pem ]; then
    echo "[*] Generating self-signed TLS certificate..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout key.pem -out cert.pem -days 3650 -nodes \
        -subj "/CN=proxy" 2>/dev/null
    echo "[+] Certificate generated: cert.pem, key.pem"
    echo "[!] Copy cert.pem to the client machine"
else
    echo "[+] Certificates already exist"
fi

# Create config if not exists
if [ ! -f config.toml ]; then
    echo ""
    read -p "Enter this server's public IP: " VPS_IP
    read -p "Backend service IP [127.0.0.1]: " XRAY_IP
    XRAY_IP=${XRAY_IP:-127.0.0.1}
    read -p "Violation TCP server port [45000]: " VIO_PORT
    VIO_PORT=${VIO_PORT:-45000}
    read -p "QUIC auth code [jd!gn0s4]: " AUTH_CODE
    AUTH_CODE=${AUTH_CODE:-"jd!gn0s4"}

    cat > config.toml << CONF
[general]
vps_ip = "$VPS_IP"
xray_server_ip = "$XRAY_IP"

[ports.tcp_mapping]
14000 = 443
15000 = 2096
16000 = 10809

[ports.udp_mapping]
17000 = 945
18000 = 1014

[violation]
tcp_server_port = $VIO_PORT
tcp_client_port = 40000
udp_server_port = 35000
udp_client_port = 30000

[quic]
server_port = 25000
client_port = 20000
local_ip = "127.0.0.1"
idle_timeout_secs = 86400
udp_timeout_secs = 300
verify_cert = false
mtu = 1420
cert_path = "cert.pem"
key_path = "key.pem"
max_data = 1073741824
max_stream_data = 1073741824
auth_code = "$AUTH_CODE"
CONF
    echo "[+] Config created: config.toml"
else
    echo "[+] Config already exists"
    # Read VIO_PORT from existing config
    VIO_PORT=$(grep 'tcp_server_port' config.toml | head -1 | awk '{print $3}')
    VIO_PORT=${VIO_PORT:-45000}
fi

# Setup firewall rules
echo "[*] Setting up firewall rules..."
if command -v ufw &> /dev/null; then
    ufw deny "$VIO_PORT"/tcp > /dev/null 2>&1 || true
    echo "[+] ufw: denied TCP port $VIO_PORT"
elif command -v iptables &> /dev/null; then
    iptables -C INPUT -p tcp --dport "$VIO_PORT" -j DROP 2>/dev/null || \
        iptables -A INPUT -p tcp --dport "$VIO_PORT" -j DROP
    echo "[+] iptables: DROP TCP port $VIO_PORT"
fi

# Create systemd service
cat > /etc/systemd/system/gfw-resist-server.service << EOF
[Unit]
Description=GFW-Resist TCP Violation Proxy (Server)
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPT_DIR/target/release/gfw-resist-proxy -c $SCRIPT_DIR/config.toml server
WorkingDirectory=$SCRIPT_DIR
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "[+] Systemd service created: gfw-resist-server"

echo ""
echo "========================================="
echo "  Setup Complete!"
echo "========================================="
echo ""
echo "  Start:   systemctl start gfw-resist-server"
echo "  Stop:    systemctl stop gfw-resist-server"
echo "  Status:  systemctl status gfw-resist-server"
echo "  Logs:    journalctl -u gfw-resist-server -f"
echo "  Enable:  systemctl enable gfw-resist-server"
echo ""
echo "  Or run manually:"
echo "  ./target/release/gfw-resist-proxy -c config.toml server"
echo ""
echo "  [!] Remember to copy cert.pem to the client machine"
echo ""
