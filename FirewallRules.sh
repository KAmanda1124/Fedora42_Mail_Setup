#!/bin/bash
#Mail Firewall Rules


echo "========================================="
echo "               Firewall"
echo "========================================="


sudo yum install iptables-services -y -q
echo "stopping alternate firewall services.."
# More like firewall-mid
sudo systemctl stop firewalld && sudo systemctl disable firewalld && sudo systemctl mask firewalld
sudo dnf remove firewalld -y -q
# More like nf-mid
sudo systemctl stop nftables && sudo systemctl disable nftables && sudo systemctl mask nftables
sudo systemctl mask nftables -y -q
# Install and setup IPTABLES
echo "Starting IPTABLES..."
sudo yum install iptables iptables-services -y -q
# Enable and start IPTABLES
sudo systemctl enable iptables && sudo systemctl start iptables

# Empty all rules
sudo iptables -t filter -F
sudo iptables -t filter -X

# Block everything by default
sudo iptables -t filter -P INPUT DROP
sudo iptables -t filter -P FORWARD DROP
sudo iptables -t filter -P OUTPUT DROP

# Authorize already established connections
sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t filter -A INPUT -i lo -j ACCEPT
sudo iptables -t filter -A OUTPUT -o lo -j ACCEPT

# ICMP (Ping)
sudo iptables -t filter -A INPUT -p icmp -j ACCEPT
sudo iptables -t filter -A OUTPUT -p icmp -j ACCEPT

# DNS (Needed for curl, and updates)
sudo iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT

# HTTP/HTTPS
sudo iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT

# NTP (server time)
sudo iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT

# Splunk
sudo iptables -t filter -A OUTPUT -p tcp --dport 8000 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 8089 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# SMTP
sudo iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 587 -j ACCEPT
sudo iptables -t filter -A OUPUT -p tcp --dport 465 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 587 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 465 -j ACCEPT

# POP3
sudo iptables -t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 110 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p udp --dport 110 -j ACCEPT
sudo iptables -t filter -A INPUT -p udp --dport 110 -j ACCEPT

# IMAP
sudo iptables -t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 143 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p udp --dport 143 -j ACCEPT
sudo iptables -t filter -A INPUT -p udp --dport 143 -j ACCEPT

# LDAP traffic
sudo iptables -t filter -A INPUT -p tcp --dport 389 -j ACCEPT
sudo iptables -t filter -A INPUT -p tcp --dport 636 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 389 -j ACCEPT
sudo iptables -t filter -A OUTPUT -p tcp --dport 636 -j ACCEPT

sudo iptables-save | sudo tee /etc/sysconfig/iptables