#!/bin/bash

# Install Fail2Ban
sudo apt update
sudo apt install -y fail2ban

# Install UFW if not already installed
sudo apt install -y ufw

# Ask user for SSH port
read -p "Enter desired SSH port (leave blank for a random port): " ssh_port

# Check if SSH port is provided
if [ -z "$ssh_port" ]; then
    # Generate a random port number between 1024 and 65535
    ssh_port=$(shuf -i 1024-65535 -n 1)
fi

# Change SSH port
sudo sed -i "s/#Port 22/Port $ssh_port/g" /etc/ssh/sshd_config
# Restart SSH service
sudo systemctl restart sshd

# Ask user for DNS server
read -p "Enter desired DNS server (leave blank for Cloudflare DNS - 1.1.1.1): " dns_server

# Check if DNS server is provided
if [ -z "$dns_server" ]; then
    dns_server="1.1.1.1"  # Default to Cloudflare DNS
fi

# Set DNS server in resolved.conf
sudo sed -i "s/#DNS=/DNS=$dns_server/g" /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved

# Disable ping responses
sudo touch /etc/systemd/system/disable_ping.service
# Add Disable ping responses
sudo tee -a /etc/systemd/system/disable_ping.service > /dev/null <<EOL
[Unit]
Description=Disable Ping Responses
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/sysctl -w net.ipv4.icmp_echo_ignore_all=1

[Install]
WantedBy=multi-user.target
EOL

sudo systemctl enable disable_ping.service
sudo systemctl start disable_ping.service

# Create a custom configuration file for SSH
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Remove lines between [sshd] and "backend = %(sshd_backend)s"
sudo sed -i '/\[sshd\]/,/backend = %(sshd_backend)s/d' /etc/fail2ban/jail.local

# Add your custom configuration to jail.local
sudo tee -a /etc/fail2ban/jail.local > /dev/null <<EOL
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 2
bantime = 86400
EOL

# Add Fail2Ban UFW action
sudo tee -a /etc/fail2ban/action.d/ufw.conf > /dev/null <<EOL
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = ufw insert 1 deny from <ip> to any
actionunban = ufw delete deny from <ip> to any
EOL

# Update UFW rules to allow SSH and enable UFW
sudo ufw allow $ssh_port/tcp
sudo ufw --force enable

# Restart Fail2Ban
sudo service fail2ban restart

# Enable Fail2Ban to start on boot
sudo systemctl enable fail2ban

# Install manage_security.sh
sudo wget -O /usr/local/bin/manage_security https://raw.githubusercontent.com/PyraScript/AegisGuard/main/manage_security
sudo chmod +x /usr/local/bin/manage_security

echo "****************************************************************************************************************************"
echo " "
echo "Fail2Ban installed and configured. IP banning after 2 failed SSH login attempts is set for 1 day. UFW is also configured."
echo " "
echo "manage_security.sh installed. You can now use 'manage_security' command to manage Fail2Ban and UFW."
echo " "
echo "Your New ssh port is :" $ssh_port
echo " "
echo "Your New DNS Address set to :" $dns_server
echo " "
echo "It's better to re-login to server"
echo " "
echo "****************************************************************************************************************************"
