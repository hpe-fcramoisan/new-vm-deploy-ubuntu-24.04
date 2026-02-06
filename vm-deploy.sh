#!/bin/bash
#
# Ubuntu 24.04 VM Deployment Script
# Configures a secure, auto-updating VM from base template
#
# Usage: ./vm-deploy.sh -c config.conf [--minimal]
#

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Parse command line arguments
CONFIG_FILE=""
MINIMAL_MODE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c)
            if [[ -z "${2:-}" ]]; then
                log_error "Option -c requires an argument"
                exit 1
            fi
            CONFIG_FILE="$2"
            shift 2
            ;;
        --minimal)
            MINIMAL_MODE=true
            shift
            ;;
        *)
            echo "Usage: $0 -c config.conf [--minimal]"
            exit 1
            ;;
    esac
done

if [[ -z "$CONFIG_FILE" ]]; then
    log_error "Configuration file required. Usage: $0 -c config.conf [--minimal]"
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Source configuration
log_info "Loading configuration from $CONFIG_FILE"
source "$CONFIG_FILE"

# Validate required parameters
REQUIRED_PARAMS=(
    "ADMIN_USER"
    "ADMIN_SSH_KEY"
    "VM_HOSTNAME"
)

if [[ "$MINIMAL_MODE" != true ]]; then
    REQUIRED_PARAMS+=(
        "IPV4_ADDRESS"
        "IPV4_GATEWAY"
        "IPV4_SUBNET"
        "IPV6_ADDRESS"
        "IPV6_GATEWAY"
        "IPV6_SUBNET"
        "DNS_SERVERS"
        "NTP_SERVERS"
    )
fi

for param in "${REQUIRED_PARAMS[@]}"; do
    if [[ -z "${!param:-}" ]]; then
        log_error "Required parameter $param not set in config file"
        exit 1
    fi
done

# Validate SSH key format
if ! [[ "$ADMIN_SSH_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519|sk-ecdsa-sha2-nistp256)[[:space:]] ]]; then
    log_error "ADMIN_SSH_KEY does not appear to be a valid SSH public key"
    log_error "Expected format: ssh-rsa AAAA... or ssh-ed25519 AAAA... (etc.)"
    exit 1
fi
log_info "SSH key format validated"

if [[ "$MINIMAL_MODE" != true ]]; then
    #############################################
    # AUTO-DETECT NETWORK INTERFACE
    #############################################
    log_info "Auto-detecting network interface..."

    # Try to auto-detect the primary network interface
    # Method 1: Get interface with default route (using -o for consistent output format)
    AUTO_INTERFACE=$(ip -o route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -n1)

    # Method 2: If no default route, get first non-loopback interface with an IP
    if [[ -z "$AUTO_INTERFACE" ]]; then
        AUTO_INTERFACE=$(ip -br link show | grep -v "^lo" | grep "UP" | awk '{print $1}' | head -n1)
    fi

    # Method 3: If still nothing, get any non-loopback interface
    if [[ -z "$AUTO_INTERFACE" ]]; then
        AUTO_INTERFACE=$(ip -br link show | grep -v "^lo" | awk '{print $1}' | head -n1)
    fi

    # Check if NETWORK_INTERFACE was provided in config
    if [[ -n "${NETWORK_INTERFACE:-}" ]]; then
        log_info "Using network interface from config: $NETWORK_INTERFACE"
    elif [[ -n "$AUTO_INTERFACE" ]]; then
        log_info "Auto-detected network interface: $AUTO_INTERFACE"
        NETWORK_INTERFACE="$AUTO_INTERFACE"
    else
        log_warn "Could not auto-detect network interface"
        log_info "Available interfaces:"
        ip -br link show | grep -v "^lo" | awk '{print "  - "$1}'
        echo ""

        # Prompt user to select interface
        while true; do
            read -r -p "Enter the network interface name to use: " NETWORK_INTERFACE

            # Verify the interface exists
            if ip link show "$NETWORK_INTERFACE" &>/dev/null; then
                log_info "Selected interface: $NETWORK_INTERFACE"
                break
            else
                log_error "Interface '$NETWORK_INTERFACE' not found. Please try again."
            fi
        done
    fi

    # Final verification
    if ! ip link show "$NETWORK_INTERFACE" &>/dev/null; then
        log_error "Network interface '$NETWORK_INTERFACE' does not exist"
        exit 1
    fi

    log_info "Network interface confirmed: $NETWORK_INTERFACE"
    echo ""

    # Set defaults for optional parameters
    TIMEZONE="${TIMEZONE:-America/New_York}"
    LOCALE="${LOCALE:-en_US.UTF-8}"
    KEYBOARD_LAYOUT="${KEYBOARD_LAYOUT:-fr}"
else
    log_info "Minimal mode: skipping network, timezone/locale, and NTP configuration"
fi

REBOOT_TIME="${REBOOT_TIME:-02:00}"

# Prompt for admin password
log_info "Password configuration for user: $ADMIN_USER"
echo ""
while true; do
    read -rs -p "Enter password for $ADMIN_USER: " ADMIN_PASSWORD
    echo ""
    read -rs -p "Confirm password: " ADMIN_PASSWORD_CONFIRM
    echo ""
    
    if [[ "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD_CONFIRM" ]]; then
        if [[ ${#ADMIN_PASSWORD} -lt 8 ]]; then
            log_error "Password must be at least 8 characters long"
            continue
        fi
        log_info "Password accepted"
        break
    else
        log_error "Passwords do not match. Please try again."
    fi
done
unset ADMIN_PASSWORD_CONFIRM
echo ""

# Backup original files
BACKUP_DIR="/root/deployment-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Created backup directory: $BACKUP_DIR"

#############################################
# 1. REMOVE EXISTING USERS
#############################################
log_info "Step 1: Removing existing users (except system users)"

# Get list of users with UID >= 1000 (regular users)
USERS_TO_REMOVE=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)
CURRENT_LOGIN_USER="${SUDO_USER:-}"
DEFERRED_USER=""

for user in $USERS_TO_REMOVE; do
    if [[ "$user" == "$ADMIN_USER" ]]; then
        log_warn "Skipping removal of $user (target admin user)"
        continue
    fi

    # Defer removal of the user who invoked sudo to avoid killing our own session
    if [[ -n "$CURRENT_LOGIN_USER" && "$user" == "$CURRENT_LOGIN_USER" ]]; then
        log_warn "Deferring removal of $user (current login user)"
        DEFERRED_USER="$user"
        continue
    fi

    log_info "Removing user: $user"
    # Kill all processes owned by user
    pkill -u "$user" || true
    sleep 1
    # Remove user and home directory
    userdel -r "$user" 2>/dev/null || log_warn "Could not fully remove $user"
done


#############################################
# 2. CREATE ADMIN USER
#############################################
log_info "Step 2: Creating admin user: $ADMIN_USER"

if id "$ADMIN_USER" &>/dev/null; then
    log_warn "User $ADMIN_USER already exists, reconfiguring..."
else
    useradd -m -s /bin/bash "$ADMIN_USER"
    log_info "Created user $ADMIN_USER"
fi

# Set password
echo "$ADMIN_USER:$ADMIN_PASSWORD" | chpasswd
unset ADMIN_PASSWORD
log_info "Password set for $ADMIN_USER"

# Add to sudo group with NOPASSWD
usermod -aG sudo "$ADMIN_USER"
echo "$ADMIN_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$ADMIN_USER"
chmod 0440 "/etc/sudoers.d/$ADMIN_USER"
log_info "Sudo access configured with NOPASSWD"

# Setup SSH key
mkdir -p "/home/$ADMIN_USER/.ssh"
chmod 700 "/home/$ADMIN_USER/.ssh"
# Backup existing authorized_keys if present
if [[ -f "/home/$ADMIN_USER/.ssh/authorized_keys" ]]; then
    cp "/home/$ADMIN_USER/.ssh/authorized_keys" "$BACKUP_DIR/authorized_keys.bak"
fi
echo "$ADMIN_SSH_KEY" > "/home/$ADMIN_USER/.ssh/authorized_keys"
chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
chown -R "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
log_info "SSH key configured"

#############################################
# 3. CONFIGURE SSH
#############################################
log_info "Step 3: Hardening SSH configuration"

cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"

# Configure SSH settings
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
# SSH Hardening Configuration
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

log_info "SSH configured for key-only authentication (console password still works)"
systemctl restart ssh

#############################################
# 4. DISABLE ROOT PASSWORD LOGIN
#############################################
log_info "Step 4: Locking root account for remote access"

# Lock root password but keep it usable from console (skip if already locked)
if passwd -S root 2>/dev/null | grep -q ' L '; then
    log_info "Root account already locked, skipping"
else
    passwd -l root
    log_info "Root account locked for SSH (console access preserved)"
fi

#############################################
# 5. SET VM_HOSTNAME
#############################################
log_info "Step 5: Setting hostname to $VM_HOSTNAME"

hostnamectl set-hostname "$VM_HOSTNAME"
# Add hostname to /etc/hosts only if not already present
if ! grep -q "127.0.1.1.*$VM_HOSTNAME" /etc/hosts; then
    echo "127.0.1.1 $VM_HOSTNAME" >> /etc/hosts
fi
log_info "Hostname configured"

if [[ "$MINIMAL_MODE" != true ]]; then
#############################################
# 6. CONFIGURE TIMEZONE, LOCALE, KEYBOARD
#############################################
log_info "Step 6: Configuring timezone, locale, and keyboard"

# Timezone
timedatectl set-timezone "$TIMEZONE"
log_info "Timezone set to $TIMEZONE"

# Locale
locale-gen "$LOCALE"
update-locale LANG="$LOCALE"
log_info "Locale set to $LOCALE"

# Keyboard
cat > /etc/default/keyboard <<EOF
XKBMODEL="pc105"
XKBLAYOUT="$KEYBOARD_LAYOUT"
XKBVARIANT=""
XKBOPTIONS=""
BACKSPACE="guess"
EOF
log_info "Keyboard layout set to $KEYBOARD_LAYOUT"

fi # end skip timezone/locale/keyboard in minimal mode

if [[ "$MINIMAL_MODE" != true ]]; then
#############################################
# 7. CONFIGURE NETWORK (NETPLAN)
#############################################
log_info "Step 7: Configuring network with netplan"

# Backup existing netplan configs and remove them to avoid conflicts
cp -r /etc/netplan "$BACKUP_DIR/" 2>/dev/null || true
for old_config in /etc/netplan/*.yaml /etc/netplan/*.yml; do
    if [[ -f "$old_config" ]]; then
        log_info "Removing existing netplan config: $old_config (backed up to $BACKUP_DIR)"
        rm -f "$old_config"
    fi
done

# Convert space-separated DNS servers to YAML list format
DNS_YAML=""
for dns in $DNS_SERVERS; do
    DNS_YAML="${DNS_YAML}          - ${dns}"$'\n'
done

# Create netplan configuration
cat > /etc/netplan/01-netcfg.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $NETWORK_INTERFACE:
      addresses:
        - $IPV4_ADDRESS/$IPV4_SUBNET
        - $IPV6_ADDRESS/$IPV6_SUBNET
      routes:
        - to: default
          via: $IPV4_GATEWAY
        - to: default
          via: $IPV6_GATEWAY
      nameservers:
        addresses:
${DNS_YAML}      dhcp4: no
      dhcp6: no
EOF

chmod 600 /etc/netplan/01-netcfg.yaml
log_info "Netplan configuration created"

# Apply netplan (will take effect on reboot, or apply now)
log_warn "Network configuration created. Apply now? (y/n)"
read -r -t 10 apply_net || apply_net="n"
if [[ "$apply_net" == "y" ]]; then
    netplan apply
    log_info "Network configuration applied"
else
    log_info "Network configuration will apply on next reboot"
fi

#############################################
# 8. CONFIGURE NTP
#############################################
log_info "Step 8: Configuring NTP time synchronization"

# Configure systemd-timesyncd
cat > /etc/systemd/timesyncd.conf <<EOF
[Time]
NTP=$NTP_SERVERS
FallbackNTP=
EOF

systemctl restart systemd-timesyncd
systemctl enable systemd-timesyncd
timedatectl set-ntp true
log_info "NTP configured with servers: $NTP_SERVERS"

fi # end skip network/NTP in minimal mode

#############################################
# 9. UPDATE SYSTEM
#############################################
log_info "Step 9: Updating system packages"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y
apt-get dist-upgrade -y
log_info "System packages updated"

#############################################
# 10. INSTALL ESSENTIAL PACKAGES
#############################################
log_info "Step 10: Installing essential packages"

apt-get install -y \
    unattended-upgrades \
    apt-listchanges \
    update-notifier-common \
    curl \
    wget \
    vim \
    htop \
    net-tools \
    dnsutils \
    ca-certificates \
    gnupg \
    lsb-release \
    ifstat \

log_info "Essential packages installed"

# Install additional packages if specified
if [[ -n "${ADDITIONAL_PACKAGES:-}" ]]; then
    log_info "Installing additional packages: $ADDITIONAL_PACKAGES"
    # shellcheck disable=SC2086
    apt-get install -y $ADDITIONAL_PACKAGES
    log_info "Additional packages installed"
fi

#############################################
# 11. CONFIGURE UNATTENDED UPGRADES
#############################################
log_info "Step 11: Configuring automatic updates"

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
// Automatic security updates configuration
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
    "\${distro_id}:\${distro_codename}-updates";
};

// Remove unused automatically installed kernel-related packages
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatic reboot configuration
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "$REBOOT_TIME";

// Reboot even if users are logged in
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";

// Email notifications (configure if needed)
// Unattended-Upgrade::Mail "admin@example.com";
// Unattended-Upgrade::MailReport "on-change";

// Automatically clean up
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

// Verbose logging
Unattended-Upgrade::Verbose "true";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

log_info "Unattended upgrades configured (auto-reboot at $REBOOT_TIME)"

#############################################
# 12. CONFIGURE LOG ROTATION
#############################################
log_info "Step 12: Configuring log rotation (keep all logs)"

# Configure logrotate to keep all logs
cat > /etc/logrotate.conf <<EOF
# Global log rotation configuration
# Keep all rotated logs (never delete)

# Rotate logs weekly
weekly

# Keep all log files
rotate 999999

# Create new (empty) log files after rotating old ones
create

# Compress rotated logs
compress

# Delay compression until next rotation
delaycompress

# Don't rotate empty logs
notifempty

# Include all configs from logrotate.d
include /etc/logrotate.d
EOF

# Update common log rotation configs to never delete (skip already modified)
for config in /etc/logrotate.d/*; do
    if [[ -f "$config" ]]; then
        # Only backup and modify if not already set to 999999
        if ! grep -q 'rotate 999999' "$config"; then
            cp "$config" "$BACKUP_DIR/logrotate-$(basename "$config").bak"
            sed -i 's/rotate [0-9]\+/rotate 999999/g' "$config"
        fi
    fi
done

log_info "Log rotation configured to keep all logs"

#############################################
# 13. DISABLE UNNECESSARY SERVICES
#############################################
log_info "Step 13: Disabling unnecessary services"

SERVICES_TO_DISABLE=(
    "snapd"
    "bluetooth"
    "ModemManager"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$service" &>/dev/null; then
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
        log_info "Disabled service: $service"
    fi
done

#############################################
# 14. CONFIGURE FAIL2BAN (Optional but recommended)
#############################################
log_info "Step 14: Installing and configuring fail2ban"

apt-get install -y fail2ban

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log_info "Fail2ban configured and enabled"

#############################################
# 15. FINAL CLEANUP
#############################################
log_info "Step 15: Final cleanup"

# Clean package cache
apt-get autoremove -y
apt-get autoclean -y
apt-get clean

# Note: Not clearing old logs - keeping all logs as configured in step 12

# Clear bash history
history -c
true > "/home/$ADMIN_USER/.bash_history"
true > /root/.bash_history

log_info "Cleanup completed"

#############################################
# 16. CREATE DEPLOYMENT INFO FILE
#############################################
log_info "Step 16: Creating deployment information file"

# Keep deployment history with timestamps
DEPLOYMENT_HISTORY_DIR="/root/deployment-history"
mkdir -p "$DEPLOYMENT_HISTORY_DIR"
if [[ -f /root/deployment-info.txt ]]; then
    # Archive previous deployment info with timestamp
    PREV_TIMESTAMP=$(date -r /root/deployment-info.txt +%Y%m%d-%H%M%S 2>/dev/null || date +%Y%m%d-%H%M%S)
    cp /root/deployment-info.txt "$DEPLOYMENT_HISTORY_DIR/deployment-info-${PREV_TIMESTAMP}.txt"
    log_info "Previous deployment info archived to $DEPLOYMENT_HISTORY_DIR"
fi

if [[ "$MINIMAL_MODE" == true ]]; then
    DEPLOY_MODE="Minimal"
else
    DEPLOY_MODE="Full"
fi

cat > /root/deployment-info.txt <<EOF
========================================
VM Deployment Information
========================================
Deployment Date: $(date)
Deployment Mode: $DEPLOY_MODE
Hostname: $VM_HOSTNAME
Admin User: $ADMIN_USER
EOF

if [[ "$MINIMAL_MODE" != true ]]; then
cat >> /root/deployment-info.txt <<EOF
Timezone: $TIMEZONE
Locale: $LOCALE
Keyboard: $KEYBOARD_LAYOUT

Network Configuration:
  Interface: $NETWORK_INTERFACE
  IPv4: $IPV4_ADDRESS/$IPV4_SUBNET
  IPv4 Gateway: $IPV4_GATEWAY
  IPv6: $IPV6_ADDRESS/$IPV6_SUBNET
  IPv6 Gateway: $IPV6_GATEWAY
  DNS: $DNS_SERVERS
  NTP: $NTP_SERVERS
EOF
fi

cat >> /root/deployment-info.txt <<EOF

Auto-Update Configuration:
  Enabled: Yes
  Auto-Reboot: Yes (at $REBOOT_TIME local time)
  Auto-Cleanup: Yes

Additional Packages: ${ADDITIONAL_PACKAGES:-none}

Security:
  SSH: Key-only authentication
  Root: Password login disabled (console only)
  Fail2ban: Enabled

Backup Location: $BACKUP_DIR
Deployment History: $DEPLOYMENT_HISTORY_DIR
========================================
EOF

log_info "Deployment info saved to /root/deployment-info.txt"

#############################################
# COMPLETION
#############################################
echo ""
log_info "========================================="
log_info "VM Deployment Complete! (${DEPLOY_MODE} mode)"
log_info "========================================="
log_info "Hostname: $VM_HOSTNAME"
log_info "Admin user: $ADMIN_USER"
log_info "SSH access: Key-only (password from console)"
log_info "Auto-updates: Enabled with reboot at $REBOOT_TIME"
log_info ""
log_warn "IMPORTANT: Verify SSH key access before logging out!"
if [[ "$MINIMAL_MODE" != true ]]; then
    log_warn "Test connection: ssh $ADMIN_USER@$IPV4_ADDRESS"
fi
log_info ""
log_info "Deployment details: /root/deployment-info.txt"
log_info "Configuration backup: $BACKUP_DIR"
log_info "Deployment history: $DEPLOYMENT_HISTORY_DIR"
log_info "========================================="
echo ""

# Verify configuration
log_info "Running verification checks..."
systemctl is-active unattended-upgrades && log_info "✓ Unattended upgrades active" || log_error "✗ Unattended upgrades not active"
systemctl is-active fail2ban && log_info "✓ Fail2ban active" || log_error "✗ Fail2ban not active"
systemctl is-active ssh && log_info "✓ SSH active" || log_error "✗ SSH not active"
id "$ADMIN_USER" &>/dev/null && log_info "✓ Admin user exists" || log_error "✗ Admin user missing"
[[ -f "/home/$ADMIN_USER/.ssh/authorized_keys" ]] && log_info "✓ SSH key configured" || log_error "✗ SSH key missing"

# Remove deferred login user as the very last action to keep the session alive throughout deployment
if [[ -n "$DEFERRED_USER" ]]; then
    log_info "Removing deferred user: $DEFERRED_USER (skipping process kill to preserve current session)"
    userdel -r "$DEFERRED_USER" 2>/dev/null || log_warn "Could not fully remove $DEFERRED_USER — processes still running. User will be removed after logout."
fi

echo ""
log_info "Deployment script completed successfully!"
