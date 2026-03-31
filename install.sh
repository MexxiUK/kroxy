#!/bin/bash

# Kroxy Installation Script
# Self-hosted reverse proxy with WAF and OIDC - Free alternative to BunkerWeb

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                         KROXY                                 ║"
echo "║       Self-hosted reverse proxy with WAF and OIDC            ║"
echo "║              Free alternative to BunkerWeb                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Note: Running without root. Some features may require sudo.${NC}"
fi

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux*)
        OS="linux"
        ;;
    Darwin*)
        OS="darwin"
        ;;
    *)
        echo -e "${RED}Unsupported OS: $OS${NC}"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo "Detected: $OS $ARCH"

# Version
VERSION="${KROXY_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${DATA_DIR:-/var/lib/kroxy}"
CONFIG_DIR="${CONFIG_DIR:-/etc/kroxy}"

# Download binary
echo -e "${GREEN}Downloading Kroxy...${NC}"
if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/kroxy/kroxy/releases/latest/download/kroxy-$OS-$ARCH"
else
    DOWNLOAD_URL="https://github.com/kroxy/kroxy/releases/download/$VERSION/kroxy-$OS-$ARCH"
fi

curl -fsSL "$DOWNLOAD_URL" -o /tmp/kroxy || {
    echo -e "${RED}Failed to download Kroxy${NC}"
    exit 1
}

chmod +x /tmp/kroxy

# Install binary
echo -e "${GREEN}Installing Kroxy to $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"
mv /tmp/kroxy "$INSTALL_DIR/kroxy"

# Create directories
mkdir -p "$DATA_DIR"
mkdir -p "$CONFIG_DIR"

# Create systemd service (Linux only)
if [ "$OS" = "linux" ] && [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}Creating systemd service...${NC}"
    cat > /etc/systemd/system/kroxy.service << 'EOF'
[Unit]
Description=Kroxy - Self-hosted reverse proxy with WAF and OIDC
Documentation=https://github.com/kroxy/kroxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=notify
User=kroxy
Group=kroxy
ExecStart=/usr/local/bin/kroxy
WorkingDirectory=/var/lib/kroxy
Environment=KROXY_DB=/var/lib/kroxy/kroxy.db
Environment=KROXY_LISTEN=:443
Environment=KROXY_ADMIN=:8080
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/kroxy

[Install]
WantedBy=multi-user.target
EOF

    # Create kroxy user
    if ! id -u kroxy &>/dev/null; then
        useradd -r -s /bin/false -d /var/lib/kroxy kroxy
    fi

    chown -R kroxy:kroxy "$DATA_DIR"
    chown -R kroxy:kroxy "$CONFIG_DIR"

    systemctl daemon-reload
    systemctl enable kroxy
fi

# Create default config
echo -e "${GREEN}Creating default configuration...${NC}"
cat > "$CONFIG_DIR/kroxy.env" << 'EOF'
# Kroxy Configuration
# See https://github.com/kroxy/kroxy for documentation

# Network
KROXY_LISTEN=:443
KROXY_ADMIN=:8080
KROXY_PROXY=:443

# Database
KROXY_DB=/var/lib/kroxy/kroxy.db

# WAF (OWASP Core Rule Set)
KROXY_WAF_ENABLED=true
KROXY_WAF_MODE=block

# Logging
KROXY_LOG_LEVEL=info
EOF

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                  Installation Complete!                      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Kroxy has been installed to: $INSTALL_DIR/kroxy"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo ""
if [ "$OS" = "linux" ]; then
    echo "  sudo systemctl start kroxy"
    echo "  sudo systemctl status kroxy"
else
    echo "  kroxy"
fi
echo ""
echo "Then open http://localhost:8080 to access the admin UI."
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  Config file: $CONFIG_DIR/kroxy.env"
echo "  Data directory: $DATA_DIR"
echo ""
echo -e "${YELLOW}Documentation:${NC}"
echo "  https://github.com/kroxy/kroxy"
echo ""
echo -e "${GREEN}Thank you for choosing Kroxy!${NC}"