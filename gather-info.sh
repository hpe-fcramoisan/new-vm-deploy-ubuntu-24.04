#!/bin/bash
#
# Helper script to gather information needed for VM deployment configuration
# Run this on your base VM template to get network interface names and other details
#

echo "========================================"
echo "VM Configuration Information Helper"
echo "========================================"
echo ""

echo "NETWORK INTERFACES:"
echo "-------------------"
ip -br a | grep -v "lo" | awk '{print "  "$1" - "$3}'
echo ""
echo "Primary interface (usually first non-loopback):"
primary_if=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "  $primary_if"
echo ""

echo "CURRENT IP CONFIGURATION:"
echo "-------------------------"
ip -4 addr show "$primary_if" 2>/dev/null | grep inet | awk '{print "  IPv4: "$2}'
ip -6 addr show "$primary_if" 2>/dev/null | grep "inet6.*scope global" | awk '{print "  IPv6: "$2}'
echo ""

echo "CURRENT GATEWAY:"
echo "----------------"
ip route | grep default | awk '{print "  IPv4 Gateway: "$3}'
ip -6 route | grep default | awk '{print "  IPv6 Gateway: "$3}'
echo ""

echo "CURRENT DNS SERVERS:"
echo "--------------------"
if [ -f /etc/systemd/resolved.conf ]; then
    grep "^DNS=" /etc/systemd/resolved.conf | cut -d= -f2 | sed 's/^/  /'
fi
if command -v resolvectl &> /dev/null; then
    resolvectl status | grep "DNS Servers" | awk '{for(i=3;i<=NF;i++) print "  "$i}'
fi
echo ""

echo "CURRENT TIMEZONE:"
echo "-----------------"
echo "  $(timedatectl | grep "Time zone" | awk '{print $3}')"
echo ""

echo "CURRENT LOCALE:"
echo "---------------"
echo "  $(locale | grep LANG= | cut -d= -f2)"
echo ""

echo "CURRENT KEYBOARD:"
echo "-----------------"
if [ -f /etc/default/keyboard ]; then
    grep "^XKBLAYOUT=" /etc/default/keyboard | cut -d= -f2 | tr -d '"' | sed 's/^/  /'
fi
echo ""

echo "EXISTING USERS (UID >= 1000):"
echo "------------------------------"
awk -F: '$3 >= 1000 && $3 < 65534 {print "  "$1" (UID: "$3")"}' /etc/passwd
echo ""

echo "UBUNTU VERSION:"
echo "---------------"
lsb_release -d | cut -f2 | sed 's/^/  /'
echo ""

echo "KERNEL VERSION:"
echo "---------------"
uname -r | sed 's/^/  /'
echo ""

echo "========================================"
echo "Use this information to fill out your"
echo "config.conf file for deployment"
echo "========================================"
