# Ubuntu 24.04 VM Deployment Guide

## Quick Start

1. **Prepare configuration file**
   ```bash
   cp config.conf.template vm-config.conf
   nano vm-config.conf  # Edit with your values
   ```

2. **Run deployment script**
   ```bash
   chmod +x vm-deploy.sh
   sudo ./vm-deploy.sh -c vm-config.conf
   ```

3. **Verify SSH access**
   ```bash
   ssh hpn@<VM_IP>
   ```

## Pre-Deployment Checklist

- [ ] Base Ubuntu 24.04 VM template ready
- [ ] Network interface name identified (run `ip a` to check)
- [ ] IP addresses allocated (both IPv4 and IPv6)
- [ ] Gateway addresses confirmed
- [ ] DNS server addresses available
- [ ] NTP server addresses available
- [ ] SSH public key ready for admin user
- [ ] Strong password ready (will be prompted during deployment)
- [ ] Hostname chosen
- [ ] Timezone determined

## Configuration Parameters Guide

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `ADMIN_USER` | Administrative username | `hpn` |
| `ADMIN_SSH_KEY` | Public SSH key for remote access | `ssh-rsa AAAA...` |
| `HOSTNAME` | Unique VM hostname | `lab-vm-001` |
| `NETWORK_INTERFACE` | Primary network interface | `ens18`, `eth0`, `ens33` |
| `IPV4_ADDRESS` | IPv4 address | `192.168.1.100` |
| `IPV4_SUBNET` | IPv4 subnet mask (CIDR) | `24` (for /24) |
| `IPV4_GATEWAY` | IPv4 default gateway | `192.168.1.1` |
| `IPV6_ADDRESS` | IPv6 address | `2001:db8::100` |
| `IPV6_SUBNET` | IPv6 subnet prefix length | `64` |
| `IPV6_GATEWAY` | IPv6 default gateway | `2001:db8::1` |
| `DNS_SERVERS` | DNS servers (space-separated) | `192.168.1.10 192.168.1.11` |
| `NTP_SERVERS` | NTP servers (space-separated) | `192.168.1.10 192.168.1.11` |

### Optional Parameters (with defaults)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `TIMEZONE` | `America/New_York` | System timezone |
| `LOCALE` | `en_US.UTF-8` | System locale |
| `KEYBOARD_LAYOUT` | `fr` | Keyboard layout |
| `REBOOT_TIME` | `02:00` | Auto-reboot time (24h format) |

### Common Timezone Values
- US Eastern: `America/New_York`
- US Pacific: `America/Los_Angeles`
- US Central: `America/Chicago`
- Paris: `Europe/Paris`
- London: `Europe/London`
- UTC: `UTC`
- Full list: `timedatectl list-timezones`

### Common Locale Values
- US English: `en_US.UTF-8`
- French: `fr_FR.UTF-8`
- German: `de_DE.UTF-8`
- Spanish: `es_ES.UTF-8`

### Common Keyboard Layouts
- US: `us`
- French: `fr`
- German: `de`
- UK: `uk`

## What the Script Does

### 1. User Management
- Removes all existing user accounts (UID >= 1000)
- Creates new admin user with sudo NOPASSWD access
- Configures SSH key authentication

### 2. SSH Hardening
- Disables root login via SSH
- Disables password authentication for SSH
- Enables key-only authentication
- Keeps password authentication available from console

### 3. Root Account Security
- Locks root password for remote login
- Preserves console access for emergency use

### 4. Network Configuration
- Configures static IPv4 and IPv6 addresses
- Sets up routing and gateways
- Configures DNS servers
- Uses netplan for network management

### 5. Time Synchronization
- Configures NTP with lab servers
- Sets timezone
- Enables systemd-timesyncd

### 6. System Updates
- Performs full system update
- Installs essential packages
- Configures unattended-upgrades for automatic security updates

### 7. Automatic Maintenance
- Enables automatic security updates
- Configures automatic reboots at 2 AM (configurable)
- Enables automatic cleanup of old kernels and packages
- Removes unused dependencies automatically

### 8. Logging
- Configures log rotation to keep ALL logs indefinitely
- Compresses rotated logs to save space
- Never deletes old logs

### 9. Security
- Installs and configures fail2ban
- Disables unnecessary services (snapd, bluetooth, ModemManager)

### 10. Localization
- Sets timezone
- Configures locale
- Sets keyboard layout

## Post-Deployment Verification

After deployment completes, verify the following:

1. **SSH Access**
   ```bash
   ssh hpn@<VM_IP>
   ```

2. **Sudo Access**
   ```bash
   sudo -l  # Should show NOPASSWD for all commands
   ```

3. **Network Connectivity**
   ```bash
   ip a  # Verify IP addresses
   ping -c 3 8.8.8.8  # IPv4 connectivity
   ping6 -c 3 2001:4860:4860::8888  # IPv6 connectivity
   ```

4. **DNS Resolution**
   ```bash
   nslookup google.com
   ```

5. **Time Synchronization**
   ```bash
   timedatectl status
   ```

6. **Automatic Updates**
   ```bash
   sudo systemctl status unattended-upgrades
   cat /var/log/unattended-upgrades/unattended-upgrades.log
   ```

7. **Fail2ban**
   ```bash
   sudo fail2ban-client status
   ```

## Files Created

- `/root/deployment-info.txt` - Summary of deployment configuration
- `/root/deployment-backup-<timestamp>/` - Backup of original configuration files
- `/etc/sudoers.d/hpn` - Sudo configuration for admin user
- `/etc/ssh/sshd_config.d/99-hardening.conf` - SSH hardening settings
- `/etc/netplan/01-netcfg.yaml` - Network configuration
- `/etc/systemd/timesyncd.conf` - NTP configuration
- `/etc/apt/apt.conf.d/50unattended-upgrades` - Auto-update configuration
- `/etc/apt/apt.conf.d/20auto-upgrades` - Auto-update schedule
- `/etc/fail2ban/jail.local` - Fail2ban configuration

## Security Notes

### SSH Access
- **Remote access**: SSH key ONLY (password disabled)
- **Console access**: Password authentication still works
- Root cannot login via SSH (ever)
- Root console login still works for emergency

### Password Requirements
- Password will be prompted securely during deployment (not stored in config file)
- Minimum 8 characters required
- Generate strong, unique passwords for each VM
- Store passwords securely (password manager)
- Each VM should have a different password

### SSH Keys
- Use the same public key for all VMs if centralized management is desired
- Or use unique keys per VM for better security

## Maintenance

### Manual Updates
Although automatic updates are enabled, you can manually update:
```bash
sudo apt update && sudo apt upgrade -y
```

### Check Update Status
```bash
sudo systemctl status unattended-upgrades
sudo tail -f /var/log/unattended-upgrades/unattended-upgrades.log
```

### Force Reboot Check
```bash
# Check if reboot is required
ls /var/run/reboot-required

# See why reboot is needed
cat /var/run/reboot-required.pkgs
```

### View Logs
```bash
# System logs
sudo journalctl -xe

# Authentication logs
sudo tail -f /var/log/auth.log

# Unattended upgrade logs
sudo tail -f /var/log/unattended-upgrades/unattended-upgrades.log
```

## Troubleshooting

### Cannot SSH to VM
1. Check if SSH service is running: `sudo systemctl status ssh`
2. Verify SSH key is correct: `cat ~/.ssh/authorized_keys`
3. Check SSH logs: `sudo tail -f /var/log/auth.log`
4. Verify network connectivity: `ping <VM_IP>`

### Network Not Working
1. Check netplan configuration: `cat /etc/netplan/01-netcfg.yaml`
2. Check interface status: `ip a`
3. Check routes: `ip route show`
4. Test gateway: `ping <GATEWAY_IP>`
5. Apply netplan: `sudo netplan apply`

### Time Not Syncing
1. Check timesyncd status: `timedatectl status`
2. Check NTP servers: `cat /etc/systemd/timesyncd.conf`
3. Restart service: `sudo systemctl restart systemd-timesyncd`

### Updates Not Running
1. Check service status: `sudo systemctl status unattended-upgrades`
2. Check logs: `sudo tail -f /var/log/unattended-upgrades/unattended-upgrades.log`
3. Test manually: `sudo unattended-upgrade -d`

## Backup and Recovery

The deployment script creates a backup directory containing:
- Original SSH configuration
- Original netplan configuration
- Original logrotate configurations

Location: `/root/deployment-backup-<timestamp>/`

To restore a configuration:
```bash
cd /root/deployment-backup-<timestamp>/
sudo cp sshd_config.bak /etc/ssh/sshd_config
sudo systemctl restart ssh
```

## Template Workflow

### For Creating a New Base Template
1. Install fresh Ubuntu 24.04
2. Do NOT run this script yet
3. Install any common software needed by all VMs
4. Create VM template/snapshot

### For Each New VM from Template
1. Clone/deploy from template
2. Create unique config file with VM-specific settings
3. Run deployment script
4. Verify and test

## Advanced Customization

### Adding Custom Packages
Edit the script and add to the package installation section:
```bash
apt-get install -y \
    your-package-1 \
    your-package-2
```

### Adding Custom Services
Add service configuration after the essential packages section:
```bash
# Install custom service
apt-get install -y your-service
systemctl enable your-service
systemctl start your-service
```

### Email Notifications for Updates
Edit `/etc/apt/apt.conf.d/50unattended-upgrades`:
```
Unattended-Upgrade::Mail "admin@example.com";
Unattended-Upgrade::MailReport "on-change";
```

Install mail handler:
```bash
sudo apt-get install mailutils
```
