#!/bin/bash
#
# Post-deployment verification script
# Run this after vm-deploy.sh to verify all configurations
#

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

check_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASS++))
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAIL++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((WARN++))
}

echo "========================================"
echo "VM Deployment Verification"
echo "========================================"
echo ""

# Check if deployment info exists
echo "Deployment Information:"
echo "-----------------------"
if [[ -f /root/deployment-info.txt ]]; then
    check_pass "Deployment info file exists"
    cat /root/deployment-info.txt
else
    check_fail "Deployment info file not found"
fi
echo ""

# Check admin user
echo "Admin User Configuration:"
echo "-------------------------"
ADMIN_USER="hpn"
if id "$ADMIN_USER" &>/dev/null; then
    check_pass "Admin user '$ADMIN_USER' exists"
    
    # Check sudo access
    if sudo -l -U "$ADMIN_USER" 2>/dev/null | grep -q NOPASSWD; then
        check_pass "Admin user has NOPASSWD sudo access"
    else
        check_fail "Admin user missing NOPASSWD sudo access"
    fi
    
    # Check SSH key
    if [[ -f "/home/$ADMIN_USER/.ssh/authorized_keys" ]]; then
        check_pass "SSH authorized_keys file exists"
        key_count=$(wc -l < "/home/$ADMIN_USER/.ssh/authorized_keys")
        echo "  Keys configured: $key_count"
    else
        check_fail "SSH authorized_keys file missing"
    fi
else
    check_fail "Admin user '$ADMIN_USER' not found"
fi
echo ""

# Check for old users
echo "User Cleanup:"
echo "-------------"
old_users=$(awk -F: -v admin="$ADMIN_USER" '$3 >= 1000 && $3 < 65534 && $1 != admin {print $1}' /etc/passwd)
if [[ -z "$old_users" ]]; then
    check_pass "No old user accounts remaining"
else
    check_warn "Old user accounts still exist: $old_users"
fi
echo ""

# Check SSH configuration
echo "SSH Configuration:"
echo "------------------"
if systemctl is-active --quiet ssh; then
    check_pass "SSH service is running"
else
    check_fail "SSH service is not running"
fi

if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config* 2>/dev/null; then
    check_pass "Root login disabled"
else
    check_fail "Root login not properly disabled"
fi

if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config* 2>/dev/null; then
    check_pass "Password authentication disabled for SSH"
else
    check_fail "Password authentication not disabled"
fi
echo ""

# Check root account
echo "Root Account:"
echo "-------------"
if passwd -S root | grep -q " L "; then
    check_pass "Root password is locked"
else
    check_warn "Root password may not be locked"
fi
echo ""

# Check network configuration
echo "Network Configuration:"
echo "----------------------"
if [[ -f /etc/netplan/01-netcfg.yaml ]]; then
    check_pass "Netplan configuration exists"
    echo "  Configuration:"
    sed 's/^/    /' /etc/netplan/01-netcfg.yaml | head -20
else
    check_fail "Netplan configuration missing"
fi

# Check connectivity
if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    check_pass "IPv4 connectivity working"
else
    check_warn "IPv4 connectivity issue (ping 8.8.8.8 failed)"
fi

if ping6 -c 1 -W 2 2001:4860:4860::8888 &>/dev/null; then
    check_pass "IPv6 connectivity working"
else
    check_warn "IPv6 connectivity issue (ping6 failed)"
fi
echo ""

# Check DNS
echo "DNS Configuration:"
echo "------------------"
if nslookup google.com &>/dev/null; then
    check_pass "DNS resolution working"
else
    check_fail "DNS resolution not working"
fi
echo ""

# Check NTP
echo "Time Synchronization:"
echo "---------------------"
if systemctl is-active --quiet systemd-timesyncd; then
    check_pass "NTP service is running"
    
    if timedatectl | grep -q "NTP service: active"; then
        check_pass "NTP synchronization is active"
    else
        check_warn "NTP synchronization may not be active"
    fi
    
    echo "  Current time: $(date)"
    echo "  Timezone: $(timedatectl | grep "Time zone" | awk '{print $3}')"
else
    check_fail "NTP service is not running"
fi
echo ""

# Check unattended upgrades
echo "Automatic Updates:"
echo "------------------"
if systemctl is-enabled --quiet unattended-upgrades; then
    check_pass "Unattended upgrades enabled"
else
    check_fail "Unattended upgrades not enabled"
fi

if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
    check_pass "Unattended upgrades configured"
    
    if grep -q "Automatic-Reboot \"true\"" /etc/apt/apt.conf.d/50unattended-upgrades; then
        check_pass "Automatic reboot enabled"
        reboot_time=$(grep "Automatic-Reboot-Time" /etc/apt/apt.conf.d/50unattended-upgrades | awk '{print $2}' | tr -d '";')
        echo "  Reboot time: $reboot_time"
    else
        check_fail "Automatic reboot not enabled"
    fi
else
    check_fail "Unattended upgrades configuration missing"
fi
echo ""

# Check fail2ban
echo "Security Services:"
echo "------------------"
if systemctl is-active --quiet fail2ban; then
    check_pass "Fail2ban is running"
    echo "  Active jails:"
    sudo fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,/\n/g' | sed 's/^/    /'
else
    check_warn "Fail2ban is not running"
fi
echo ""

# Check disabled services
echo "Disabled Services:"
echo "------------------"
SHOULD_BE_DISABLED=("snapd" "bluetooth" "ModemManager")
for service in "${SHOULD_BE_DISABLED[@]}"; do
    if ! systemctl is-enabled --quiet "$service" 2>/dev/null; then
        check_pass "$service is disabled"
    else
        check_warn "$service is still enabled"
    fi
done
echo ""

# Check log rotation
echo "Log Configuration:"
echo "------------------"
if grep -q "rotate 999999" /etc/logrotate.conf; then
    check_pass "Log rotation configured to keep all logs"
else
    check_warn "Log rotation may not be configured properly"
fi
echo ""

# Check system updates
echo "System Update Status:"
echo "---------------------"
if [[ -f /var/run/reboot-required ]]; then
    check_warn "System reboot required"
    echo "  Packages requiring reboot:"
    sed 's/^/    /' /var/run/reboot-required.pkgs
else
    check_pass "No reboot currently required"
fi

updates_available=$(apt list --upgradable 2>/dev/null | grep -c "upgradable")
if [[ $updates_available -eq 0 ]]; then
    check_pass "System is up to date"
else
    check_warn "$updates_available package updates available"
fi
echo ""

# Summary
echo "========================================"
echo "Verification Summary:"
echo "========================================"
echo -e "${GREEN}Passed:${NC} $PASS"
echo -e "${YELLOW}Warnings:${NC} $WARN"
echo -e "${RED}Failed:${NC} $FAIL"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}✓ Deployment verification successful!${NC}"
    exit 0
else
    echo -e "${RED}✗ Deployment has issues that need attention${NC}"
    exit 1
fi
