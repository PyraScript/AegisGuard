```bash
#!/usr/bin/env bash

# =========================================================
# AegisGuard Hardened VPS Security Script
# Compatible with Ubuntu 22.04 / 24.04+ and Debian 12+
# =========================================================

set -Eeuo pipefail

# =========================================================
# Colors
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# =========================================================
# Root Check
# =========================================================

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Please run as root.${NC}"
    exit 1
fi

# =========================================================
# Helper Functions
# =========================================================

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

backup_file() {
    local file="$1"

    if [[ -f "$file" ]]; then
        cp "$file" "${file}.bak.$(date +%s)"
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# =========================================================
# Detect SSH Service
# =========================================================

SSH_SERVICE="ssh"

if systemctl list-unit-files | grep -q "^sshd.service"; then
    SSH_SERVICE="sshd"
fi

# =========================================================
# Install Dependencies
# =========================================================

info "Updating package lists..."

apt update

info "Installing required packages..."

DEBIAN_FRONTEND=noninteractive apt install -y \
    fail2ban \
    ufw \
    wget \
    curl \
    systemd \
    openssh-server

# =========================================================
# SSH Port Selection
# =========================================================

read -rp "Enter desired SSH port (leave blank for random): " ssh_port

if [[ -z "${ssh_port:-}" ]]; then
    ssh_port=$(shuf -i 20000-65000 -n 1)
    info "Generated random SSH port: $ssh_port"
fi

# Validate Port
if ! [[ "$ssh_port" =~ ^[0-9]+$ ]]; then
    error "SSH port must be numeric."
    exit 1
fi

if (( ssh_port < 1024 || ssh_port > 65535 )); then
    error "SSH port must be between 1024 and 65535."
    exit 1
fi

# =========================================================
# DNS Configuration
# =========================================================

read -rp "Enter desired DNS server (default: 1.1.1.1): " dns_server

dns_server="${dns_server:-1.1.1.1}"

# Basic IPv4 validation
if ! [[ "$dns_server" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    error "Invalid DNS server format."
    exit 1
fi

# =========================================================
# Configure SSH Securely
# =========================================================

info "Configuring SSH..."

mkdir -p /etc/ssh/sshd_config.d

CUSTOM_SSH_CONFIG="/etc/ssh/sshd_config.d/99-aegisguard.conf"

backup_file "$CUSTOM_SSH_CONFIG"

cat > "$CUSTOM_SSH_CONFIG" <<EOF
# AegisGuard SSH Hardening

Port $ssh_port

Protocol 2

PermitRootLogin prohibit-password

PubkeyAuthentication yes

PasswordAuthentication yes

ChallengeResponseAuthentication no

UsePAM yes

X11Forwarding no

MaxAuthTries 3

ClientAliveInterval 300

ClientAliveCountMax 2

LoginGraceTime 30

PermitEmptyPasswords no

AllowTcpForwarding no

Compression no

EOF

# Validate SSH Config Before Restart
info "Validating SSH configuration..."

if ! sshd -t; then
    error "Invalid SSH configuration detected."
    exit 1
fi

# =========================================================
# Configure DNS
# =========================================================

info "Configuring DNS..."

backup_file /etc/systemd/resolved.conf

if grep -q "^DNS=" /etc/systemd/resolved.conf; then
    sed -i "s/^DNS=.*/DNS=$dns_server/" /etc/systemd/resolved.conf
else
    echo "DNS=$dns_server" >> /etc/systemd/resolved.conf
fi

systemctl restart systemd-resolved || true

# =========================================================
# Disable Ping Responses
# =========================================================

info "Disabling ICMP ping responses..."

cat > /etc/sysctl.d/99-disable-ping.conf <<EOF
net.ipv4.icmp_echo_ignore_all=1
EOF

sysctl --system >/dev/null

# =========================================================
# Additional Sysctl Hardening
# =========================================================

info "Applying kernel hardening..."

cat > /etc/sysctl.d/99-aegisguard.conf <<EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0

# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0

# SYN flood protection
net.ipv4.tcp_syncookies=1

# Log suspicious packets
net.ipv4.conf.all.log_martians=1
EOF

sysctl --system >/dev/null

# =========================================================
# Configure UFW
# =========================================================

info "Configuring UFW firewall..."

ufw --force reset

ufw default deny incoming
ufw default allow outgoing

# Allow SSH Port
ufw allow "${ssh_port}/tcp"

# Enable UFW
ufw --force enable

# =========================================================
# Restart SSH AFTER Firewall Rule Exists
# =========================================================

info "Restarting SSH service..."

systemctl restart "$SSH_SERVICE"

# =========================================================
# Configure Fail2Ban
# =========================================================

info "Configuring Fail2Ban..."

mkdir -p /etc/fail2ban/jail.d

FAIL2BAN_SSH="/etc/fail2ban/jail.d/sshd.local"

backup_file "$FAIL2BAN_SSH"

cat > "$FAIL2BAN_SSH" <<EOF
[sshd]
enabled = true
port = $ssh_port
backend = systemd
maxretry = 2
findtime = 10m
bantime = 24h
bantime.increment = true
bantime.factor = 2
EOF

# =========================================================
# Restart Fail2Ban
# =========================================================

info "Restarting Fail2Ban..."

systemctl enable fail2ban
systemctl restart fail2ban

# =========================================================
# Install Manage Security Tool
# =========================================================

info "Installing manage_security utility..."

if command_exists wget; then
    wget -q -O /usr/local/bin/manage_security \
    https://raw.githubusercontent.com/PyraScript/AegisGuard/main/manage_security || true
else
    curl -fsSL \
    https://raw.githubusercontent.com/PyraScript/AegisGuard/main/manage_security \
    -o /usr/local/bin/manage_security || true
fi

chmod +x /usr/local/bin/manage_security || true

# =========================================================
# Verification
# =========================================================

info "Performing verification checks..."

if ! systemctl is-active --quiet fail2ban; then
    warn "Fail2Ban is not active."
fi

if ! systemctl is-active --quiet "$SSH_SERVICE"; then
    error "SSH service failed to start."
    exit 1
fi

if ! ufw status | grep -q "$ssh_port"; then
    error "UFW rule for SSH port was not applied."
    exit 1
fi

# =========================================================
# Final Output
# =========================================================

echo
echo "========================================================="
echo
echo -e "${GREEN}AegisGuard Security Hardening Completed${NC}"
echo
echo "SSH Port: $ssh_port"
echo "DNS Server: $dns_server"
echo
echo "Installed Components:"
echo " - Fail2Ban"
echo " - UFW Firewall"
echo " - SSH Hardening"
echo " - ICMP Ping Blocking"
echo " - Kernel Hardening"
echo
echo "Useful Commands:"
echo " - ufw status"
echo " - fail2ban-client status"
echo " - systemctl status fail2ban"
echo " - journalctl -u $SSH_SERVICE"
echo
echo "IMPORTANT:"
echo "Reconnect using the NEW SSH port:"
echo
echo "ssh -p $ssh_port user@server-ip"
echo
echo "========================================================="
echo
```
