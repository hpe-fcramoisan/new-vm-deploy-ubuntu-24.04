# Ubuntu 24.04 VM Deployment System

Automated deployment system for secure, auto-updating Ubuntu 24.04 VMs in lab environments.

## Files Included

- `vm-deploy.sh` - Main deployment script
- `reverse-proxy.sh` - Nginx reverse proxy with Let's Encrypt SSL
- `config.conf.template` - Configuration file template
- `gather-info.sh` - Helper to identify network interfaces and system info
- `verify-deployment.sh` - Post-deployment verification

## Quick Start

### 1. Prepare Your Base VM Template
```bash
# On your base template VM, gather system information
sudo ./gather-info.sh
```

### 2. Create Configuration File
```bash
# Copy template
cp config.conf.template my-vm.conf

# Edit with your values
nano my-vm.conf
```

**Required configuration:**
- Admin user credentials (username: hpn)
- SSH public key
- Hostname
- Network settings (IPv4 and IPv6) — not required with `--minimal`
- DNS and NTP servers — not required with `--minimal`

**Note:** 
- The admin password will be prompted securely during deployment (not stored in config file)
- Network interface is auto-detected (can be overridden in config if needed)

### 3. Deploy VM
```bash
# Full deployment (network, timezone, everything)
sudo ./vm-deploy.sh -c my-vm.conf

# Minimal deployment (user, hardening, hostname only — skips network/DNS, timezone/locale, NTP)
sudo ./vm-deploy.sh -c my-vm.conf --minimal
```

### 4. Verify Deployment
```bash
# Run verification
sudo ./verify-deployment.sh
```

### 5. Test SSH Access
```bash
# From another machine
ssh hpn@<VM_IP>
```

## What Gets Configured

### Security
- SSH key-only authentication (password from console only)
- Root login disabled for SSH
- Fail2ban installed and configured
- Unnecessary services disabled

### Auto-Maintenance
- Automatic security updates
- Auto-reboot at 2 AM (configurable)
- Automatic cleanup of old packages/kernels
- All logs retained (compressed)

### Network
- Static IPv4 and IPv6 configuration
- Custom DNS servers
- Custom NTP servers
- Configured via netplan

### User Management
- Old users removed
- If the current login user (the one who ran `sudo`) is being removed, their deletion is deferred to the very end of the script to keep the session alive
- New admin user (hpn) with sudo NOPASSWD
- SSH key configured

### System Settings
- Timezone configured
- Locale configured
- Keyboard layout configured (French by default)

## Important Notes

### SSH Access
- **Remote**: SSH key ONLY (no passwords)
- **Console**: Password login still works
- **Root**: Cannot SSH in (console works for emergencies)

### Passwords
- Password is prompted securely during deployment (not stored in config file)
- Generate unique, strong passwords for each VM (minimum 8 characters)
- Store securely in password manager
- Never reuse passwords across VMs

### Network Changes
- Network configuration requires reboot to take full effect
- Script will ask if you want to apply immediately
- If unsure, apply on next reboot

### Automatic Updates
- Security updates install automatically
- System reboots automatically at 2 AM if needed
- Old kernels and packages removed automatically

## Nginx Reverse Proxy (Optional)

After VM deployment, optionally set up nginx as a reverse proxy with auto-renewing Let's Encrypt certificates.

### Prerequisites
- Azure DNS zone for your domain (DNS-01 challenge)
- Service Principal with "DNS Zone Contributor" role

### Usage
```bash
# Initial setup
sudo ./reverse-proxy.sh -c my-vm.conf

# Management (after setup)
sudo ./reverse-proxy.sh
```

### Features
- Automatic SSL via acme.sh + Azure DNS
- HTTP to HTTPS redirect
- WebSocket support
- Per-domain logging
- Certificate auto-renewal with nginx reload

See `config.conf.template` for configuration options.

## Troubleshooting

### Can't SSH to VM
```bash
# Check from console
sudo systemctl status ssh
sudo tail -f /var/log/auth.log
cat ~/.ssh/authorized_keys
```

### Network Issues
```bash
# Check configuration
cat /etc/netplan/01-netcfg.yaml
ip a
ip route

# Apply netplan
sudo netplan apply
```

### See Full Documentation
```bash
# Read comprehensive guide
less DEPLOYMENT-GUIDE.md
```

## Files Created on VM

After deployment (`vm-deploy.sh`):
- `/root/deployment-info.txt` - Deployment summary
- `/root/deployment-backup-<timestamp>/` - Backup of original configs
- `/etc/sudoers.d/hpn` - Sudo configuration
- `/etc/ssh/sshd_config.d/99-hardening.conf` - SSH settings
- `/etc/netplan/01-netcfg.yaml` - Network configuration
- `/etc/systemd/timesyncd.conf` - NTP configuration
- `/etc/apt/apt.conf.d/50unattended-upgrades` - Auto-update config
- `/etc/fail2ban/jail.local` - Fail2ban configuration

After reverse proxy setup (`reverse-proxy.sh`):
- `/etc/nginx/sites-available/<domain>.conf` - Per-domain nginx config
- `/etc/nginx/ssl/<domain>/` - Certificate symlinks
- `/etc/nginx/backups/` - Config backups before changes
- `/etc/nginx/.reverse-proxy-managed` - Setup marker file
- `/root/.acme.sh/` - acme.sh installation and certificates

## License
Use freely at your own risk