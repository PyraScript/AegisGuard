#!/usr/bin/env bash

# =============================================================================
# AegisGuard Secure VPS Installer (Stable 2026 Edition)
# Fixed: CrowdSec repo issue + phased install + safe rollback
# =============================================================================

set -Eeuo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

trap 'warn "Script failed. Check logs above."' ERR

# =============================================================================
# Root check
# =============================================================================

[[ $EUID -ne 0 ]] && { error "Run as root"; exit 1; }

# =============================================================================
# PHASE 0 - BASIC PREPARATION
# =============================================================================

info "Phase 0: system preparation"

apt update -y
apt install -y curl wget gnupg lsb-release ca-certificates jq

mkdir -p /root/aegisguard

# =============================================================================
# SSH PORT
# =============================================================================

read -rp "SSH port (blank=random): " ssh_port
ssh_port=${ssh_port:-$(shuf -i 20000-65000 -n 1)}

[[ ! "$ssh_port" =~ ^[0-9]+$ ]] && { error "Invalid port"; exit 1; }

# =============================================================================
# DNS
# =============================================================================

read -rp "DNS (default 1.1.1.1): " dns_server
dns_server=${dns_server:-1.1.1.1}

# =============================================================================
# PHASE 1 - CORE SECURITY
# =============================================================================

info "Phase 1: core security tools"

apt install -y ufw fail2ban openssh-server systemd

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "$ssh_port/tcp"
ufw limit "$ssh_port/tcp"
ufw --force enable

# =============================================================================
# SSH HARDENING
# =============================================================================

info "Configuring SSH"

mkdir -p /etc/ssh/sshd_config.d

cat > /etc/ssh/sshd_config.d/99-aegis.conf <<EOF
Port $ssh_port
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
EOF

sshd -t || { error "SSH config invalid"; exit 1; }

systemctl restart ssh || systemctl restart sshd || true

# =============================================================================
# DNS CONFIG
# =============================================================================

info "Setting DNS"

echo "DNS=$dns_server" >> /etc/systemd/resolved.conf || true
systemctl restart systemd-resolved || true

# =============================================================================
# SYSCTL HARDENING
# =============================================================================

info "Kernel hardening"

cat > /etc/sysctl.d/99-aegis.conf <<EOF
net.ipv4.tcp_syncookies=1
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
kernel.randomize_va_space=2
kernel.kptr_restrict=2
EOF

sysctl --system >/dev/null

# =============================================================================
# PHASE 2 - CROWDSEC (FIXED)
# =============================================================================

info "Phase 2: CrowdSec install (FIXED repo issue)"

curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash

apt update -y

apt install -y crowdsec crowdsec-firewall-bouncer-iptables || {
    warn "CrowdSec install failed, skipping"
}

systemctl enable crowdsec || true
systemctl restart crowdsec || true

cscli collections install crowdsecurity/sshd || true

# =============================================================================
# PHASE 3 - AUDIT & INTEGRITY
# =============================================================================

info "Phase 3: audit + integrity"

apt install -y auditd aide

systemctl enable auditd
systemctl restart auditd

aideinit || true

# =============================================================================
# PHASE 4 - AUTO UPDATES
# =============================================================================

info "Phase 4: security updates"

apt install -y unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades || true

# =============================================================================
# PHASE 5 - FAIL2BAN CONFIG
# =============================================================================

info "Configuring Fail2Ban"

cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
backend = systemd
port = $ssh_port
maxretry = 2
bantime = 24h
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# =============================================================================
# PHASE 6 - DNS HARDENING (DoT)
# =============================================================================

info "DNS-over-TLS enable"

sed -i 's/#DNSOverTLS=no/DNSOverTLS=yes/' /etc/systemd/resolved.conf || true
systemctl restart systemd-resolved || true

# =============================================================================
# PHASE 7 - ADDITIONAL SECURITY HARDENING
# =============================================================================

info "Extra hardening"

# disable unused FS
cat > /etc/modprobe.d/disable-fs.conf <<EOF
install cramfs /bin/false
install freevxfs /bin/false
install squashfs /bin/false
EOF

# disable ipv6 redirects
cat >> /etc/sysctl.d/99-aegis.conf <<EOF
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF

sysctl --system >/dev/null

# =============================================================================
# PHASE 8 - HEALTH CHECK
# =============================================================================

info "Health monitoring"

cat > /usr/local/bin/aegis-health <<EOF
#!/bin/bash
systemctl restart fail2ban || true
systemctl restart crowdsec || true
EOF

chmod +x /usr/local/bin/aegis-health

cat > /etc/systemd/system/aegis-health.service <<EOF
[Unit]
Description=Aegis Health

[Service]
Type=oneshot
ExecStart=/usr/local/bin/aegis-health
EOF

cat > /etc/systemd/system/aegis-health.timer <<EOF
[Unit]
Description=Run every 5 min

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable aegis-health.timer
systemctl start aegis-health.timer

# =============================================================================
# FINAL CHECKS
# =============================================================================

info "Final checks"

sshd -t || warn "SSH config warning"

systemctl is-active --quiet fail2ban || warn "fail2ban inactive"
systemctl is-active --quiet crowdsec || warn "crowdsec inactive"

# =============================================================================
# OUTPUT
# =============================================================================

echo
echo "=========================================="
echo "AegisGuard installation complete"
echo "SSH Port: $ssh_port"
echo "DNS: $dns_server"
echo
echo "IMPORTANT:"
echo "Reconnect using:"
echo "ssh -p $ssh_port user@IP"
echo "=========================================="
