#!/bin/bash

# Install Fail2Ban
sudo apt update
sudo apt install -y fail2ban

# Install UFW if not already installed
sudo apt install -y ufw

# Create a custom configuration file for SSH
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit the custom configuration file
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
sudo ufw allow ssh
sudo ufw --force enable

# Restart Fail2Ban
sudo service fail2ban restart

# Enable Fail2Ban to start on boot
sudo systemctl enable fail2ban

echo "Fail2Ban installed and configured. IP banning after 2 failed SSH login attempts is set for 1 day. UFW is also configured."

# Install manage_security.sh
sudo wget -O /usr/local/bin/manage_security https://raw.githubusercontent.com/PyraScript/AegisGuard/main/manage_security
sudo chmod +x /usr/local/bin/manage_security

echo "manage_security installed. You can now use 'manage_security' command to manage Fail2Ban and UFW."

