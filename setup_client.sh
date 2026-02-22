#!/bin/bash
set -e

echo "========================================="
echo "  GFW-Resist Proxy - Client Setup"
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

# Create config if not exists
if [ ! -f config.toml ]; then
    echo ""
    read -p "Enter VPS IP (the blocked server): " VPS_IP

    if [ -z "$VPS_IP" ]; then
        echo "[!] VPS IP is required"
        exit 1
    fi

    read -p "Violation TCP client port [40000]: " VIO_CLIENT_PORT
    VIO_CLIENT_PORT=${VIO_CLIENT_PORT:-40000}
    read -p "Violation TCP server port [45000]: " VIO_SERVER_PORT
    VIO_SERVER_PORT=${VIO_SERVER_PORT:-45000}
    read -p "QUIC auth code [jd!gn0s4]: " AUTH_CODE
    AUTH_CODE=${AUTH_CODE:-"jd!gn0s4"}

    echo ""
    echo "Port mapping (local_port -> remote_port):"
    echo "  Default: 14000->443, 15000->2096, 16000->10809"
    read -p "Use defaults? [Y/n]: " USE_DEFAULTS
    USE_DEFAULTS=${USE_DEFAULTS:-Y}

    if [[ "$USE_DEFAULTS" =~ ^[Yy] ]]; then
        TCP_MAPPING='14000 = 443
15000 = 2096
16000 = 10809'
        UDP_MAPPING='17000 = 945
18000 = 1014'
    else
        TCP_MAPPING=""
        echo "Enter TCP port mappings (empty line to stop):"
        while true; do
            read -p "  local_port:remote_port (e.g., 14000:443): " MAPPING
            [ -z "$MAPPING" ] && break
            LOCAL=$(echo "$MAPPING" | cut -d: -f1)
            REMOTE=$(echo "$MAPPING" | cut -d: -f2)
            TCP_MAPPING+="$LOCAL = $REMOTE"$'\n'
        done

        UDP_MAPPING=""
        echo "Enter UDP port mappings (empty line to stop):"
        while true; do
            read -p "  local_port:remote_port (e.g., 17000:945): " MAPPING
            [ -z "$MAPPING" ] && break
            LOCAL=$(echo "$MAPPING" | cut -d: -f1)
            REMOTE=$(echo "$MAPPING" | cut -d: -f2)
            UDP_MAPPING+="$LOCAL = $REMOTE"$'\n'
        done
    fi

    cat > config.toml << CONF
[general]
vps_ip = "$VPS_IP"
xray_server_ip = "127.0.0.1"

[ports.tcp_mapping]
$TCP_MAPPING

[ports.udp_mapping]
$UDP_MAPPING

[violation]
tcp_server_port = $VIO_SERVER_PORT
tcp_client_port = $VIO_CLIENT_PORT
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
    VIO_CLIENT_PORT=$(grep 'tcp_client_port' config.toml | head -1 | awk '{print $3}')
    VIO_CLIENT_PORT=${VIO_CLIENT_PORT:-40000}
fi

# Check for certificate
if [ ! -f cert.pem ]; then
    echo ""
    echo "[!] cert.pem not found!"
    echo "    Copy cert.pem from the server to this directory:"
    echo "    scp root@your-server:$SCRIPT_DIR/cert.pem $SCRIPT_DIR/"
    echo ""
fi

# Setup firewall rules
echo "[*] Setting up firewall rules..."
if command -v ufw &> /dev/null; then
    ufw deny "$VIO_CLIENT_PORT"/tcp > /dev/null 2>&1 || true
    echo "[+] ufw: denied TCP port $VIO_CLIENT_PORT"
elif command -v iptables &> /dev/null; then
    iptables -C INPUT -p tcp --dport "$VIO_CLIENT_PORT" -j DROP 2>/dev/null || \
        iptables -A INPUT -p tcp --dport "$VIO_CLIENT_PORT" -j DROP
    echo "[+] iptables: DROP TCP port $VIO_CLIENT_PORT"
fi

# Create systemd service
cat > /etc/systemd/system/gfw-resist-client.service << EOF
[Unit]
Description=GFW-Resist TCP Violation Proxy (Client)
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPT_DIR/target/release/gfw-resist-proxy -c $SCRIPT_DIR/config.toml client
WorkingDirectory=$SCRIPT_DIR
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "[+] Systemd service created: gfw-resist-client"

echo ""
echo "========================================="
echo "  Setup Complete!"
echo "========================================="
echo ""
echo "  Start:   systemctl start gfw-resist-client"
echo "  Stop:    systemctl stop gfw-resist-client"
echo "  Status:  systemctl status gfw-resist-client"
echo "  Logs:    journalctl -u gfw-resist-client -f"
echo "  Enable:  systemctl enable gfw-resist-client"
echo ""
echo "  Or run manually:"
echo "  sudo ./target/release/gfw-resist-proxy -c config.toml client"
echo ""
echo "  Local TCP ports forwarded to VPS:"
for port in 14000 15000 16000; do
    echo "    127.0.0.1:$port -> VPS"
done
echo ""
