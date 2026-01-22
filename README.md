# Ubuntu 24.04 VM Deployment System

Automated deployment system for secure, auto-updating Ubuntu 24.04 VMs in lab environments.

## Files Included

- `vm-deploy.sh` - Main deployment script
- `config.conf.template` - Configuration file template
- `gather-info.sh` - Helper to identify network interfaces and system info
- `verify-deployment.sh` - Post-deployment verification
- `DEPLOYMENT-GUIDE.md` - Comprehensive documentation

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
- Network settings (IPv4 and IPv6)
- DNS and NTP servers
- Hostname

**Note:** 
- The admin password will be prompted securely during deployment (not stored in config file)
- Network interface is auto-detected (can be overridden in config if needed)

### 3. Deploy VM
```bash
# Run deployment script
sudo ./vm-deploy.sh -c my-vm.conf
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

### ✅ Security
- SSH key-only authentication (password from console only)
- Root login disabled for SSH
- Fail2ban installed and configured
- Unnecessary services disabled

### ✅ Auto-Maintenance
- Automatic security updates
- Auto-reboot at 2 AM (configurable)
- Automatic cleanup of old packages/kernels
- All logs retained (compressed)

### ✅ Network
- Static IPv4 and IPv6 configuration
- Custom DNS servers
- Custom NTP servers
- Configured via netplan

### ✅ User Management
- Old users removed
- New admin user (hpn) with sudo NOPASSWD
- SSH key configured

### ✅ System Settings
- Timezone configured
- Locale configured
- Keyboard layout configured (French by default)

## Configuration File Example

```bash
# Admin user
ADMIN_USER="hpn"
# Password will be prompted during deployment
ADMIN_SSH_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."

# Network
HOSTNAME="lab-vm-001"
# NETWORK_INTERFACE auto-detected (uncomment to override)
# NETWORK_INTERFACE="ens18"
IPV4_ADDRESS="192.168.1.100"
IPV4_SUBNET="24"
IPV4_GATEWAY="192.168.1.1"
IPV6_ADDRESS="2001:db8::100"
IPV6_SUBNET="64"
IPV6_GATEWAY="2001:db8::1"
DNS_SERVERS="192.168.1.10 192.168.1.11"
NTP_SERVERS="192.168.1.10 192.168.1.11"

# Localization
TIMEZONE="America/New_York"
LOCALE="en_US.UTF-8"
KEYBOARD_LAYOUT="fr"
REBOOT_TIME="02:00"
```

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

## Workflow

### For Lab Setup

1. **Create base template once:**
   - Install Ubuntu 24.04
   - Install common software needed by all VMs
   - Create VM template/snapshot
   - **Do not run deployment script on template**

2. **For each new VM:**
   - Clone/deploy from template
   - Create unique configuration file
   - Run `vm-deploy.sh`
   - Verify with `verify-deployment.sh`
   - Test SSH access

3. **Maintenance:**
   - Updates happen automatically
   - Reboots happen automatically at 2 AM
   - No manual intervention needed

## Support

For detailed information, see `DEPLOYMENT-GUIDE.md`

## Security Checklist

Before putting VM into production:
- [ ] Unique password set
- [ ] SSH key added
- [ ] SSH access tested
- [ ] Cannot SSH as root (verified)
- [ ] Sudo works without password (verified)
- [ ] Network connectivity verified (IPv4 and IPv6)
- [ ] DNS resolution working
- [ ] NTP synchronization active
- [ ] Auto-updates enabled
- [ ] Fail2ban running

## Files Created on VM

After deployment, these files are created:

- `/root/deployment-info.txt` - Deployment summary
- `/root/deployment-backup-<timestamp>/` - Backup of original configs
- `/etc/sudoers.d/hpn` - Sudo configuration
- `/etc/ssh/sshd_config.d/99-hardening.conf` - SSH settings
- `/etc/netplan/01-netcfg.yaml` - Network configuration
- `/etc/systemd/timesyncd.conf` - NTP configuration
- `/etc/apt/apt.conf.d/50unattended-upgrades` - Auto-update config
- `/etc/fail2ban/jail.local` - Fail2ban configuration

## License

Use freely for your lab environment.
