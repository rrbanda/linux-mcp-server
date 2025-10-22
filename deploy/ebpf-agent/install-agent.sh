#!/bin/bash
#
# install-agent.sh - Automated eBPF Network Agent Deployment Script
#
# This script installs and configures the eBPF network monitoring agent
# as a systemd service on RHEL 8+ systems.
#
# USAGE: sudo ./install-agent.sh
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
AGENT_DIR="/opt/network-agent"
LOG_FILE="/var/log/network-events.jsonl"
SERVICE_FILE="/etc/systemd/system/network-agent.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}eBPF Network Agent Installer${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check if running on RHEL/CentOS
if [ ! -f /etc/redhat-release ]; then
    echo -e "${YELLOW}WARNING: This script is designed for RHEL/CentOS systems${NC}"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Step 1: Check prerequisites
echo -e "${YELLOW}[1/7] Checking prerequisites...${NC}"

# Check for required packages
MISSING_PACKAGES=""

if ! rpm -q bcc &>/dev/null; then
    MISSING_PACKAGES="$MISSING_PACKAGES bcc"
fi

if ! rpm -q bcc-tools &>/dev/null; then
    MISSING_PACKAGES="$MISSING_PACKAGES bcc-tools"
fi

if ! rpm -q python3 &>/dev/null; then
    MISSING_PACKAGES="$MISSING_PACKAGES python3"
fi

if ! rpm -q kernel-devel-$(uname -r) &>/dev/null; then
    MISSING_PACKAGES="$MISSING_PACKAGES kernel-devel-$(uname -r)"
fi

if [ -n "$MISSING_PACKAGES" ]; then
    echo -e "${RED}ERROR: Missing required packages:${NC}$MISSING_PACKAGES"
    echo ""
    echo "Install them with:"
    echo "  sudo dnf install -y bcc bcc-tools kernel-devel-\$(uname -r) python3"
    exit 1
fi

echo -e "${GREEN}✓ All prerequisites installed${NC}"

# Step 2: Create agent directory
echo -e "${YELLOW}[2/7] Creating agent directory...${NC}"

if [ -d "$AGENT_DIR" ]; then
    echo -e "${YELLOW}WARNING: Directory $AGENT_DIR already exists${NC}"
    read -p "Overwrite existing installation? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    rm -rf "$AGENT_DIR"
fi

mkdir -p "$AGENT_DIR"
echo -e "${GREEN}✓ Created $AGENT_DIR${NC}"

# Step 3: Copy agent files
echo -e "${YELLOW}[3/7] Copying agent files...${NC}"

if [ ! -f "$SCRIPT_DIR/agent.py" ]; then
    echo -e "${RED}ERROR: agent.py not found in $SCRIPT_DIR${NC}"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/protocols.py" ]; then
    echo -e "${RED}ERROR: protocols.py not found in $SCRIPT_DIR${NC}"
    exit 1
fi

cp "$SCRIPT_DIR/agent.py" "$AGENT_DIR/"
cp "$SCRIPT_DIR/protocols.py" "$AGENT_DIR/"

chmod 755 "$AGENT_DIR/agent.py"
chmod 644 "$AGENT_DIR/protocols.py"

echo -e "${GREEN}✓ Copied agent files${NC}"

# Step 4: Create log file with proper permissions
echo -e "${YELLOW}[4/7] Setting up log file...${NC}"

touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

echo -e "${GREEN}✓ Created log file: $LOG_FILE${NC}"

# Step 5: Install systemd service
echo -e "${YELLOW}[5/7] Installing systemd service...${NC}"

if [ ! -f "$SCRIPT_DIR/network-agent.service" ]; then
    echo -e "${RED}ERROR: network-agent.service not found in $SCRIPT_DIR${NC}"
    exit 1
fi

cp "$SCRIPT_DIR/network-agent.service" "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"

echo -e "${GREEN}✓ Installed systemd service${NC}"

# Step 6: Enable and start service
echo -e "${YELLOW}[6/7] Enabling and starting service...${NC}"

systemctl daemon-reload
systemctl enable network-agent.service
systemctl start network-agent.service

echo -e "${GREEN}✓ Service enabled and started${NC}"

# Step 7: Verify installation
echo -e "${YELLOW}[7/7] Verifying installation...${NC}"

sleep 2  # Give the service a moment to start

if systemctl is-active --quiet network-agent.service; then
    echo -e "${GREEN}✓ Service is running${NC}"
else
    echo -e "${RED}ERROR: Service failed to start${NC}"
    echo "Check logs with: journalctl -u network-agent.service -n 50"
    exit 1
fi

# Final summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Service Status:"
systemctl status network-agent.service --no-pager -l | head -n 10
echo ""
echo "Useful Commands:"
echo "  View service status:   systemctl status network-agent.service"
echo "  View service logs:     journalctl -u network-agent.service -f"
echo "  View network events:   tail -f $LOG_FILE"
echo "  Stop service:          systemctl stop network-agent.service"
echo "  Start service:         systemctl start network-agent.service"
echo "  Restart service:       systemctl restart network-agent.service"
echo ""
echo -e "${GREEN}The agent is now monitoring network activity and logging to:${NC}"
echo "  $LOG_FILE"
echo ""

