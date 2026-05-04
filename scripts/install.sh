#!/bin/bash
# Kroxy Installation Script
# Self-hosted reverse proxy with WAF and OIDC - Free alternative to BunkerWeb

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Version
VERSION="0.2.0"
BINARY_NAME="kroxy"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/kroxy"
DATA_DIR="/var/lib/kroxy"

print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║   ██╗  ██╗██████╗ ███████╗██╗   ██╗                      ║"
    echo "║   ██║ ██╔╝██╔══██╗██╔════╝██║   ██║                      ║"
    echo "║   █████╔╝ ██████╔╝█████╗  ██║   ██║                      ║"
    echo "║   ██╔═██╗ ██╔══██╗██╔══╝  ██║   ██║                      ║"
    echo "║   ██║  ██╗██║  ██║███████╗╚██████╔╝                      ║"
    echo "║   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝                       ║"
    echo "║                                                           ║"
    echo "║   Self-hosted reverse proxy with WAF and OIDC             ║"
    echo "║   Free alternative to BunkerWeb                           ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"

    if ! command -v go &> /dev/null; then
        echo -e "${RED}Go is not installed. Please install Go 1.22+ first.${NC}"
        echo -e "  ${BLUE}https://go.dev/doc/install${NC}"
        exit 1
    fi

    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo -e "${GREEN}✓${NC} Go $GO_VERSION detected"
}

install_binary() {
    echo -e "${YELLOW}Installing Kroxy binary...${NC}"

    # Build from source
    echo -e "  Building from source..."
    go build -ldflags="-s -w" -o "$BINARY_NAME" ./cmd/kroxy

    # Install binary
    echo -e "  Installing to $INSTALL_DIR..."
    sudo cp "$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"

    echo -e "${GREEN}✓${NC} Binary installed to $INSTALL_DIR/$BINARY_NAME"
}

create_directories() {
    echo -e "${YELLOW}Creating directories...${NC}"

    sudo mkdir -p "$CONFIG_DIR"
    sudo mkdir -p "$DATA_DIR"
    sudo mkdir -p "$DATA_DIR/certs"

    echo -e "${GREEN}✓${NC} Directories created"
}

install_systemd() {
    echo -e "${YELLOW}Installing systemd service...${NC}"

    cat << EOF | sudo tee /etc/systemd/system/kroxy.service > /dev/null
[Unit]
Description=Kroxy - Self-hosted reverse proxy with WAF and OIDC
Documentation=https://github.com/kroxy/kroxy
After=network.target

[Service]
Type=simple
User=kroxy
Group=kroxy
WorkingDirectory=$DATA_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Environment
Environment=KROXY_LISTEN=:443
Environment=KROXY_ADMIN=:8080
Environment=KROXY_DB=$DATA_DIR/kroxy.db

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

    # Create kroxy user if not exists
    if ! id -u kroxy &>/dev/null; then
        sudo useradd -r -s /bin/false -d "$DATA_DIR" kroxy
    fi

    sudo chown -R kroxy:kroxy "$DATA_DIR"
    sudo chmod -R 755 "$DATA_DIR"

    echo -e "${GREEN}✓${NC} Systemd service installed"
}

enable_service() {
    echo -e "${YELLOW}Enabling Kroxy service...${NC}"

    sudo systemctl daemon-reload
    sudo systemctl enable kroxy
    sudo systemctl start kroxy

    echo -e "${GREEN}✓${NC} Service started"
    echo -e ""
    echo -e "  ${BLUE}Status:${NC} sudo systemctl status kroxy"
    echo -e "  ${BLUE}Logs:${NC}   sudo journalctl -u kroxy -f"
}

create_default_config() {
    echo -e "${YELLOW}Creating default configuration...${NC}"

    if [ ! -f "$CONFIG_DIR/kroxy.env" ]; then
        cat << EOF | sudo tee "$CONFIG_DIR/kroxy.env" > /dev/null
# Kroxy Configuration
# See https://github.com/kroxy/kroxy for documentation

# Network
KROXY_LISTEN=:443
KROXY_ADMIN=:8080

# Database
KROXY_DB=$DATA_DIR/kroxy.db

# Logging
KROXY_LOG_LEVEL=info

# WAF (OWASP Core Rule Set enabled by default)
KROXY_WAF_ENABLED=true
KROXY_WAF_MODE=block

# OIDC (configure your providers via API)
# KROXY_OIDC_GOOGLE_CLIENT_ID=your-client-id
# KROXY_OIDC_GOOGLE_CLIENT_SECRET=your-client-secret
EOF
        echo -e "${GREEN}✓${NC} Default configuration created at $CONFIG_DIR/kroxy.env"
    else
        echo -e "${GREEN}✓${NC} Configuration already exists"
    fi
}

print_success() {
    echo -e ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Installation Complete                   ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "  ${BLUE}Web UI:${NC}      http://localhost:8080"
    echo -e "  ${BLUE}API:${NC}         http://localhost:8080/api"
    echo -e "  ${BLUE}Config:${NC}     $CONFIG_DIR/kroxy.env"
    echo -e "  ${BLUE}Database:${NC}   $DATA_DIR/kroxy.db"
    echo -e ""
    echo -e "  ${YELLOW}Quick Start:${NC}"
    echo -e "    1. Add a route:"
    echo -e "       curl -X POST http://localhost:8080/api/routes \\"
    echo -e "         -H 'Content-Type: application/json' \\"
    echo -e "         -d '{\"domain\":\"app.example.com\",\"backend\":\"http://localhost:3000\"}'"
    echo -e ""
    echo -e "    2. Configure OIDC:"
    echo -e "       curl -X POST http://localhost:8080/api/oidc \\"
    echo -e "         -H 'Content-Type: application/json' \\"
    echo -e "         -d '{\"name\":\"google\",\"client_id\":\"YOUR_ID\",\"client_secret\":\"YOUR_SECRET\"}'"
    echo -e ""
    echo -e "  ${BLUE}Documentation:${NC} https://github.com/kroxy/kroxy"
    echo -e ""
}

# Main
print_banner
check_dependencies
install_binary
create_directories
create_default_config
install_systemd
enable_service
print_success