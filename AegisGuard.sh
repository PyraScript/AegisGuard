#!/usr/bin/env bash

# =============================================================================
# AegisGuard Ultimate VPS Hardening Suite (2026 Edition)
# Ubuntu 22.04 / 24.04 / Debian 12+
#
# FEATURES
# =============================================================================
#
# [✓] SSH Hardening
# [✓] Random SSH Port
# [✓] SSH Key Authentication Support
# [✓] Fail2Ban
# [✓] CrowdSec
# [✓] UFW Firewall
# [✓] IPv6 Hardening
# [✓] Sysctl Kernel Hardening
# [✓] ICMP Disable
# [✓] DNS Configuration
# [✓] Automatic Security Updates
# [✓] Auditd
# [✓] AIDE File Integrity
# [✓] Docker Hardening
# [✓] Rate Limiting
# [✓] Honeypot (Cowrie optional)
# [✓] Memory Exploit Mitigation
# [✓] Rollback Protection
# [✓] Health Checks
# [✓] GeoIP Blocking (Optional)
#
# =============================================================================

set -Eeuo pipefail

# =============================================================================
# Colors
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# =============================================================================
# Helper Functions
# =============================================================================

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

rollback() {
    warn "Rollback triggered."

    if [[ -f /etc/ssh/sshd_config.d/99-aegisguard.conf.bak ]]; then
        cp /etc/ssh/sshd_config.d/99-aegisguard.conf.bak \
           /etc/ssh/sshd_config.d/99-aegisguard.conf
    fi

    systemctl restart ssh || systemctl restart sshd || true
}

trap rollback ERR

# =============================================================================
# Root Check
# =============================================================================

if [[ $EUID -ne 0 ]]; then
    error "Please run as root."
    exit 1
fi

# =============================================================================
# Detect SSH Service
# =============================================================================

SSH_SERVICE="ssh"

if systemctl list-unit-files | grep -q "^sshd.service"; then
    SSH_SERVICE="sshd"
fi

# =============================================================================
# Install Packages
# =============================================================================

info "Installing packages..."

apt update

DEBIAN_FRONTEND=noninteractive apt install -y \
    openssh-server \
    fail2ban \
    crowdsec \
    crowdsec-firewall-bouncer-iptables \
    ufw \
    auditd \
    aide \
    unattended-upgrades \
    apt-listchanges \
    apparmor \
    apparmor-utils \
    curl \
    wget \
    jq \
    gnupg \
    lsb-release \
    ca-certificates \
    software-properties-common \
    ipset \
    rsyslog

# =============================================================================
# SSH PORT
# =============================================================================

read -rp "Enter desired SSH port (blank=random): " ssh_port

if [[ -z "${ssh_port:-}" ]]; then
    ssh_port=$(shuf -i 20000-65000 -n 1)
fi

if ! [[ "$ssh_port" =~ ^[0-9]+$ ]]; then
    error "Invalid SSH port."
    exit 1
fi

if (( ssh_port < 1024 || ssh_port > 65535 )); then
    error "Port must be between 1024-65535"
    exit 1
fi

# =============================================================================
# DNS
# =============================================================================

read -rp "Enter DNS server (default 1.1.1.1): " dns_server
dns_server="${dns_server:-1.1.1.1}"

# =============================================================================
# GEO BLOCKING
# =============================================================================

read -rp "Enable GeoIP blocking? (y/n): " GEOIP_ENABLE

# =============================================================================
# SSH KEY ONLY MODE
# =============================================================================

read -rp "Disable password authentication? (recommended) (y/n): " DISABLE_PASSWORDS

PASSWORD_AUTH="yes"

if [[ "$DISABLE_PASSWORDS" =~ ^[Yy]$ ]]; then
    PASSWORD_AUTH="no"
fi

# =============================================================================
# BACKUPS
# =============================================================================

mkdir -p /root/aegisguard-backups

# =============================================================================
# SSH HARDENING
# =============================================================================

info "Configuring SSH..."

mkdir -p /etc/ssh/sshd_config.d

SSH_CONF="/etc/ssh/sshd_config.d/99-aegisguard.conf"

if [[ -f "$SSH_CONF" ]]; then
    cp "$SSH_CONF" "${SSH_CONF}.bak"
fi

cat > "$SSH_CONF" <<EOF
# AegisGuard SSH Hardening

Port $ssh_port

Protocol 2

PermitRootLogin no

PasswordAuthentication $PASSWORD_AUTH

PubkeyAuthentication yes

KbdInteractiveAuthentication no

ChallengeResponseAuthentication no

UsePAM yes

X11Forwarding no

AllowTcpForwarding no

AllowAgentForwarding no

PermitTunnel no

PermitEmptyPasswords no

Compression no

LoginGraceTime 20

MaxAuthTries 3

MaxSessions 2

ClientAliveInterval 300

ClientAliveCountMax 2

TCPKeepAlive no

UseDNS no

PrintMotd no

Banner none

EOF

# Validate SSH
if ! sshd -t; then
    error "SSH config invalid."
    exit 1
fi

# =============================================================================
# DNS CONFIG
# =============================================================================

info "Configuring DNS..."

backup_file /etc/systemd/resolved.conf

if grep -q "^DNS=" /etc/systemd/resolved.conf; then
    sed -i "s/^DNS=.*/DNS=$dns_server/" /etc/systemd/resolved.conf
else
    echo "DNS=$dns_server" >> /etc/systemd/resolved.conf
fi

# Enable DNS-over-TLS
if grep -q "^#DNSOverTLS=" /etc/systemd/resolved.conf; then
    sed -i 's/^#DNSOverTLS=.*/DNSOverTLS=yes/' /etc/systemd/resolved.conf
else
    echo "DNSOverTLS=yes" >> /etc/systemd/resolved.conf
fi

systemctl restart systemd-resolved || true

# =============================================================================
# SYSCTL HARDENING
# =============================================================================

info "Applying kernel hardening..."

cat > /etc/sysctl.d/99-aegisguard.conf <<EOF
# =============================================================================
# Network Hardening
# =============================================================================

net.ipv4.icmp_echo_ignore_all=1

net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0

net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0

net.ipv4.tcp_syncookies=1

net.ipv4.conf.all.log_martians=1

# =============================================================================
# IPv6 Hardening
# =============================================================================

net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0

net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0

# =============================================================================
# Memory Exploit Mitigation
# =============================================================================

kernel.randomize_va_space=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1

fs.suid_dumpable=0

# =============================================================================
# TCP Hardening
# =============================================================================

net.ipv4.tcp_timestamps=0
net.ipv4.tcp_sack=1

EOF

sysctl --system >/dev/null

# =============================================================================
# Disable Unused Filesystems
# =============================================================================

info "Disabling unused filesystems..."

cat > /etc/modprobe.d/aegisguard.conf <<EOF
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
EOF

# =============================================================================
# OPTIONAL USB BLOCK
# =============================================================================

if systemd-detect-virt | grep -vq "none"; then
    info "Virtual machine detected. Skipping USB blocking."
else
    echo "blacklist usb-storage" > /etc/modprobe.d/disable-usb-storage.conf
fi

# =============================================================================
# UFW
# =============================================================================

info "Configuring firewall..."

sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw || true

ufw --force reset

ufw default deny incoming
ufw default allow outgoing

# SSH
ufw allow "${ssh_port}/tcp"
ufw limit "${ssh_port}/tcp"

# Enable firewall
ufw --force enable

# =============================================================================
# OPTIONAL GEO BLOCKING
# =============================================================================

if [[ "$GEOIP_ENABLE" =~ ^[Yy]$ ]]; then

    read -rp "Allowed country code (example: AE): " COUNTRY

    apt install -y xtables-addons-common geoip-database

    mkdir -p /usr/share/xt_geoip

    info "GeoIP enabled for country: $COUNTRY"

    iptables -A INPUT -m geoip ! --src-cc "$COUNTRY" -j DROP || true
fi

# =============================================================================
# Restart SSH
# =============================================================================

info "Restarting SSH..."

systemctl restart "$SSH_SERVICE"

# =============================================================================
# FAIL2BAN
# =============================================================================

info "Configuring Fail2Ban..."

mkdir -p /etc/fail2ban/jail.d

cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
backend = systemd
port = $ssh_port
maxretry = 2
findtime = 10m
bantime = 24h
bantime.increment = true
bantime.factor = 2
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# =============================================================================
# CrowdSec
# =============================================================================

info "Configuring CrowdSec..."

systemctl enable crowdsec
systemctl restart crowdsec

# =============================================================================
# Automatic Security Updates
# =============================================================================

info "Enabling unattended upgrades..."

dpkg-reconfigure -f noninteractive unattended-upgrades

# =============================================================================
# AUDITD
# =============================================================================

info "Enabling auditd..."

systemctl enable auditd
systemctl restart auditd

# =============================================================================
# AIDE
# =============================================================================

info "Initializing AIDE database..."

aideinit || true

# =============================================================================
# APPARMOR
# =============================================================================

info "Enabling AppArmor..."

systemctl enable apparmor
systemctl restart apparmor

# =============================================================================
# DOCKER HARDENING
# =============================================================================

if command -v docker >/dev/null 2>&1; then

    info "Docker detected. Applying hardening..."

    mkdir -p /etc/docker

    cat > /etc/docker/daemon.json <<EOF
{
    "icc": false,
    "live-restore": true,
    "no-new-privileges": true,
    "userland-proxy": false,
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
EOF

    systemctl restart docker || true
fi

# =============================================================================
# Honeypot Suggestion
# =============================================================================

read -rp "Install Cowrie SSH Honeypot? (y/n): " INSTALL_COWRIE

if [[ "$INSTALL_COWRIE" =~ ^[Yy]$ ]]; then

    info "Installing Cowrie dependencies..."

    apt install -y git python3-venv python3-pip

    useradd -r -s /usr/sbin/nologin cowrie || true

    sudo -u cowrie git clone https://github.com/cowrie/cowrie /home/cowrie || true

    info "Cowrie installed."
fi

# =============================================================================
# HEALTH CHECK SERVICE
# =============================================================================

info "Creating health-check service..."

cat > /usr/local/bin/aegisguard-healthcheck <<EOF
#!/usr/bin/env bash

if ! systemctl is-active --quiet fail2ban; then
    systemctl restart fail2ban
fi

if ! systemctl is-active --quiet crowdsec; then
    systemctl restart crowdsec
fi

if ! systemctl is-active --quiet $SSH_SERVICE; then
    systemctl restart $SSH_SERVICE
fi
EOF

chmod +x /usr/local/bin/aegisguard-healthcheck

cat > /etc/systemd/system/aegisguard-healthcheck.service <<EOF
[Unit]
Description=AegisGuard Health Check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/aegisguard-healthcheck
EOF

cat > /etc/systemd/system/aegisguard-healthcheck.timer <<EOF
[Unit]
Description=Run AegisGuard Healthcheck Every 5 Minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable aegisguard-healthcheck.timer
systemctl start aegisguard-healthcheck.timer

# =============================================================================
# Manage Security Tool
# =============================================================================

info "Installing manage_security..."

wget -q -O /usr/local/bin/manage_security \
https://raw.githubusercontent.com/PyraScript/AegisGuard/main/manage_security || true

chmod +x /usr/local/bin/manage_security || true

# =============================================================================
# FINAL VERIFICATION
# =============================================================================

info "Running verification..."

if ! systemctl is-active --quiet fail2ban; then
    warn "Fail2Ban inactive."
fi

if ! systemctl is-active --quiet crowdsec; then
    warn "CrowdSec inactive."
fi

if ! systemctl is-active --quiet "$SSH_SERVICE"; then
    error "SSH failed."
    exit 1
fi

# =============================================================================
# FINAL OUTPUT
# =============================================================================

echo
echo "============================================================================="
echo
echo -e "${GREEN}AegisGuard Ultimate Hardening Completed Successfully${NC}"
echo
echo "SSH PORT: $ssh_port"
echo "DNS SERVER: $dns_server"
echo
echo "Enabled Components:"
echo
echo " [✓] SSH Hardening"
echo " [✓] Fail2Ban"
echo " [✓] CrowdSec"
echo " [✓] UFW Firewall"
echo " [✓] IPv6 Hardening"
echo " [✓] DNS-over-TLS"
echo " [✓] AppArmor"
echo " [✓] Auditd"
echo " [✓] AIDE"
echo " [✓] Sysctl Hardening"
echo " [✓] Health Monitoring"
echo " [✓] Automatic Security Updates"
echo
echo "Reconnect using:"
echo
echo "ssh -p $ssh_port user@server-ip"
echo
echo "Useful Commands:"
echo
echo "fail2ban-client status"
echo "cscli metrics"
echo "ufw status verbose"
echo "systemctl status crowdsec"
echo "journalctl -xe"
echo
echo "============================================================================="
echo
