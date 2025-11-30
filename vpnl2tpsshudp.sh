#!/bin/bash

# ==========================================
# VPN MASTER SERVER - COMPLETE ALL IN ONE
# L2TP/IPsec + OpenVPN + SSH UDP + WireGuard
# With User Management, IP Limit, Auto Ban, Monitoring
# Support: Ubuntu 18.04, 20.04, 22.04, 24.04
# ==========================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global Variables
SERVER_IP=""
INSTALL_DIR="/etc/vpnmaster"
LOG_DIR="/var/log/vpnmaster"
USERS_FILE="$INSTALL_DIR/users.json"
BACKUP_DIR="$INSTALL_DIR/backups"
BAN_LIST="$INSTALL_DIR/banlist.txt"

# Banner
show_banner() {
    clear
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                   🛡️ VPN MASTER SERVER🛡️                   ║"
    echo "║          ALL-IN-ONE Auto Installer - Complete Suite         ║"
    echo "║         L2TP/IPsec • OpenVPN • SSH UDP • WireGuard          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${CYAN}✅ Support: Ubuntu 18.04/20.04/22.04/24.04${NC}"
    echo -e "${CYAN}✅ Features: IP Limit • Auto Ban • Backup • Monitoring${NC}"
    echo -e "${CYAN}✅ Timezone: Asia/Jakarta • Unlimited Speed${NC}"
    echo "================================================================"
}

# Utility Functions
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_loading() { echo -e "${CYAN}⏳ $1${NC}"; }

# Check System
check_system() {
    print_loading "Checking system compatibility..."
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            print_success "Ubuntu $VERSION_ID detected - SUPPORTED"
        else
            print_error "Only Ubuntu OS supported"
            exit 1
        fi
    else
        print_error "Cannot detect OS"
        exit 1
    fi
    
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        echo -e "${YELLOW}Use: sudo bash $0${NC}"
        exit 1
    fi
}

# Get Server IP
get_server_ip() {
    print_loading "Detecting server IP..."
    SERVER_IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')
    print_success "Server IP: $SERVER_IP"
}

# Update System
update_system() {
    print_loading "Updating system packages..."
    apt update && apt upgrade -y
    apt install -y curl wget git jq bc
    print_success "System updated"
}

# Install Dependencies
install_dependencies() {
    print_loading "Installing dependencies..."
    
    apt install -y \
        strongswan xl2tpd \
        openvpn easy-rsa \
        wireguard qrencode \
        net-tools iptables-persistent \
        nginx certbot python3-certbot-nginx \
        iftop htop python3 python3-pip \
        dos2unix netcat socat
    
    # Python dependencies
    pip3 install speedtest-cli psutil requests
    
    print_success "Dependencies installed"
}

# Set Timezone to Jakarta
set_timezone() {
    print_loading "Setting timezone to Jakarta..."
    timedatectl set-timezone Asia/Jakarta
    print_success "Timezone set to Asia/Jakarta"
}

# Kernel Optimization
optimize_kernel() {
    print_loading "Optimizing kernel for VPN performance..."
    
    cat >> /etc/sysctl.conf << EOF

# VPN Master Server Optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_mem = 134217728 134217728 134217728
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
fs.file-max = 1000000
net.core.netdev_max_backlog = 300000
net.ipv4.ip_forward = 1
EOF
    
    sysctl -p
    print_success "Kernel optimized"
}

# Configure Firewall
configure_firewall() {
    print_loading "Configuring firewall..."
    
    # Reset iptables
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    
    # Allow all UDP ports for SSH UDP
    iptables -A INPUT -p udp --dport 1:65535 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 1:65535 -j ACCEPT
    iptables -A FORWARD -p udp --dport 1:65535 -j ACCEPT
    
    # VPN Ports
    for port in 22 80 443 7300 53 1194 51820 1701 500 4500; do
        iptables -A INPUT -p tcp --dport $port -j ACCEPT
        iptables -A INPUT -p udp --dport $port -j ACCEPT
    done
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    
    print_success "Firewall configured - All UDP ports 1-65535 open"
}

# Create Directories
create_directories() {
    print_loading "Creating directory structure..."
    
    mkdir -p $INSTALL_DIR/{modules,backups,configs,users,logs,python_tools}
    mkdir -p $LOG_DIR
    mkdir -p /var/www/html
    
    # Initialize files
    echo '[]' > $USERS_FILE
    touch $BAN_LIST
    
    print_success "Directories created"
}

# ==========================================
# USER MANAGEMENT MODULE
# ==========================================

create_ssh_user() {
    echo "🧑‍💼 CREATE SSH USER"
    echo "────────────────"
    
    read -p "Username: " username
    read -s -p "Password: " password
    echo
    read -p "Expiry (days): " expiry_days
    read -p "Max IP connections: " max_ip
    
    # Validation
    if [[ -z "$username" || -z "$password" || -z "$expiry_days" ]]; then
        echo "❌ All fields required!"
        return 1
    fi
    
    if id "$username" &>/dev/null; then
        echo "❌ User already exists!"
        return 1
    fi
    
    # Create system user
    useradd -m -s /bin/false $username
    echo "$username:$password" | chpasswd
    
    # Calculate expiry
    expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
    created_date=$(date +%Y-%m-%d)
    
    # Add to JSON
    current_data=$(cat $USERS_FILE)
    new_user=$(jq -n \
        --arg user "$username" \
        --arg pass "$password" \
        --arg expiry "$expiry_date" \
        --arg created "$created_date" \
        --arg max_ip "$max_ip" \
        '{username: $user, password: $pass, expiry: $expiry, created: $created, max_ip: $max_ip, status: "active"}')
    
    echo $current_data | jq ". += [$new_user]" > $USERS_FILE
    
    echo "✅ USER CREATED SUCCESSFULLY!"
    echo "══════════════════════════════════"
    echo "👤 Username: $username"
    echo "🔑 Password: $password" 
    echo "📍 Server: $SERVER_IP"
    echo "🔐 Port UDP: 1-65535"
    echo "📅 Expiry: $expiry_date"
    echo "🛡️ Max IP: $max_ip connections"
    echo "⚡ Protocol: UDP CUSTOM"
    echo "🚀 Speed: UNLIMITED"
    echo "══════════════════════════════════"
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Created user: $username (Expiry: $expiry_date, Max IP: $max_ip)" >> "$LOG_DIR/user.log"
}

delete_ssh_user() {
    echo "🗑️ DELETE USER"
    echo "─────────────"
    
    read -p "Username to delete: " username
    
    if ! id "$username" &>/dev/null; then
        echo "❌ User not found!"
        return 1
    fi
    
    # Delete system user
    userdel -r $username
    
    # Remove from JSON
    current_data=$(cat $USERS_FILE)
    echo $current_data | jq "map(select(.username != \"$username\"))" > $USERS_FILE
    
    echo "✅ User $username deleted!"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Deleted user: $username" >> "$LOG_DIR/user.log"
}

list_all_users() {
    echo "📋 ALL USERS"
    echo "───────────"
    
    users_data=$(cat $USERS_FILE)
    user_count=$(echo $users_data | jq length)
    
    if [[ $user_count -eq 0 ]]; then
        echo "😔 No users found"
        return
    fi
    
    echo "$users_data" | jq -r '.[] | "👤 \(.username) | 📅 \(.expiry) | 🛡️ \(.max_ip) IP | 🟢 \(.status)"'
    echo "───────────"
    echo "Total: $user_count users"
}

view_active_users() {
    echo "👥 ACTIVE USERS"
    echo "──────────────"
    
    echo "SSH Connections:"
    who
    
    echo "──────────────"
    echo "Recent Logins:"
    last | head -10
}

# ==========================================
# IP LIMIT & AUTO BAN MODULE
# ==========================================

limit_user_ip() {
    echo "🛡️ IP LIMIT MANAGEMENT"
    echo "───────────────────"
    
    read -p "Username: " username
    read -p "Max IP connections: " max_ip
    
    if [[ -z "$username" || -z "$max_ip" ]]; then
        echo "❌ Username and max IP required!"
        return 1
    fi
    
    # Update user data
    current_data=$(cat $USERS_FILE)
    updated_data=$(echo $current_data | jq \
        --arg user "$username" \
        --arg max_ip "$max_ip" \
        'map(if .username == $user then .max_ip = $max_ip else . end)')
    
    echo $updated_data > $USERS_FILE
    
    echo "✅ IP limit set for $username: $max_ip connections"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - IP limit set: $username - $max_ip IP" >> "$LOG_DIR/user.log"
}

auto_ban_system() {
    echo "🚫 AUTO BAN SYSTEM"
    echo "────────────────"
    
    users_data=$(cat $USERS_FILE)
    violation_count=0
    
    echo "Checking for violations..."
    
    echo "$users_data" | jq -r '.[] | "\(.username):\(.max_ip)"' | while read user_limit; do
        username=$(echo $user_limit | cut -d: -f1)
        max_ip=$(echo $user_limit | cut -d: -f2)
        
        if [[ -n "$max_ip" && "$max_ip" != "null" ]]; then
            # Count current IP connections
            current_ips=$(who | grep "$username" | awk '{print $5}' | sort | uniq | wc -l)
            
            if [[ $current_ips -gt $max_ip ]]; then
                echo "⚠️ $username exceeded IP limit: $current_ips/$max_ip"
                
                # Get newest IP to ban
                newest_ip=$(who | grep "$username" | tail -1 | awk '{print $5}' | sed 's/.*(//' | sed 's/).*//')
                
                if [[ -n "$newest_ip" ]]; then
                    # Add to ban list
                    echo "$newest_ip $(date '+%Y-%m-%d %H:%M:%S') $username" >> $BAN_LIST
                    
                    # Block IP
                    iptables -A INPUT -s $newest_ip -j DROP
                    
                    echo "🚫 Banned IP: $newest_ip for user: $username"
                    echo "$(date '+%Y-%m-%d %H:%M:%S') - Auto banned IP: $newest_ip for user: $username" >> "$LOG_DIR/user.log"
                    ((violation_count++))
                fi
            fi
        fi
    done
    
    if [[ $violation_count -eq 0 ]]; then
        echo "✅ No violations detected"
    else
        echo "✅ Auto ban completed: $violation_count IPs banned"
    fi
}

view_ban_list() {
    echo "🚫 BANNED IP LIST"
    echo "────────────────"
    
    if [[ ! -s $BAN_LIST ]]; then
        echo "✅ No banned IPs"
        return
    fi
    
    echo "IP Address       Date Time         User"
    echo "──────────────────────────────────────"
    cat $BAN_LIST
}

unban_ip() {
    echo "🔓 UNBAN IP"
    echo "──────────"
    
    read -p "IP address to unban: " ip_address
    
    if [[ -z "$ip_address" ]]; then
        echo "❌ IP address required!"
        return 1
    fi
    
    # Remove from ban list
    sed -i "/^$ip_address/d" $BAN_LIST
    
    # Remove from iptables
    iptables -D INPUT -s $ip_address -j DROP 2>/dev/null
    
    echo "✅ IP $ip_address unbanned"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Unbanned IP: $ip_address" >> "$LOG_DIR/user.log"
}

check_user_expiry() {
    echo "📅 CHECK USER EXPIRY"
    echo "──────────────────"
    
    users_data=$(cat $USERS_FILE)
    current_date=$(date +%Y-%m-%d)
    expired_count=0
    
    echo "$users_data" | jq -r '.[] | "\(.username):\(.expiry)"' | while read user_expiry; do
        username=$(echo $user_expiry | cut -d: -f1)
        expiry=$(echo $user_expiry | cut -d: -f2)
        
        if [[ "$current_date" > "$expiry" ]]; then
            echo "❌ $username EXPIRED since $expiry"
            
            # Delete expired user
            userdel -r $username 2>/dev/null
            
            # Update status
            updated_data=$(echo $users_data | jq \
                --arg user "$username" \
                'map(if .username == $user then .status = "expired" else . end)')
            echo $updated_data > $USERS_FILE
            
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Auto deleted expired user: $username" >> "$LOG_DIR/user.log"
            ((expired_count++))
        fi
    done
    
    if [[ $expired_count -eq 0 ]]; then
        echo "✅ No expired users"
    else
        echo "✅ Cleaned up $expired_count expired users"
    fi
}

# ==========================================
# MONITORING & BACKUP MODULE
# ==========================================

monitor_bandwidth() {
    echo "📊 BANDWIDTH MONITORING"
    echo "─────────────────────"
    
    echo "1. Real-time Monitor (iftop)"
    echo "2. Python Speed Test"
    echo "3. System Statistics"
    
    read -p "Choose [1-3]: " choice
    
    case $choice in
        1)
            iftop -i $(ip route | grep default | awk '{print $5}')
            ;;
        2)
            python3_speed_test
            ;;
        3)
            show_system_stats
            ;;
        *)
            echo "❌ Invalid choice"
            ;;
    esac
}

python3_speed_test() {
    echo "🚀 PYTHON SPEED TEST"
    echo "───────────────────"
    
    # Create Python speed test on the fly
    python3 << EOF
import speedtest
import time

try:
    print("📡 Testing download speed...")
    st = speedtest.Speedtest()
    download = st.download() / 1000000
    time.sleep(1)
    
    print("📤 Testing upload speed...")
    upload = st.upload() / 1000000
    time.sleep(1)
    
    st.get_best_server()
    
    print("\\\\n📊 SPEED TEST RESULTS:")
    print(f"⬇️  Download: {download:.2f} Mbps")
    print(f"⬆️  Upload: {upload:.2f} Mbps")
    print(f"📍 Server: {st.results.server['name']}")
    print(f"🏓 Ping: {st.results.ping:.0f} ms")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("💡 Check internet connection")
EOF
}

show_system_stats() {
    echo "🖥️ SYSTEM STATISTICS"
    echo "─────────────────"
    
    # CPU
    echo "💻 CPU Usage:"
    top -bn1 | grep "Cpu(s)" | awk '{print $2 "%"}'
    
    # Memory
    echo "🧠 Memory Usage:"
    free -h
    
    # Disk
    echo "💾 Disk Usage:"
    df -h
    
    # Uptime
    echo "⏰ Uptime:"
    uptime -p
    
    # Connections
    echo "🔗 Active Connections:"
    netstat -tn | grep ESTABLISHED | wc -l
}

backup_system() {
    echo "💾 SYSTEM BACKUP"
    echo "──────────────"
    
    backup_file="$BACKUP_DIR/vpnmaster-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    echo "Backing up system..."
    tar -czf $backup_file \
        /etc/vpnmaster \
        /etc/ssh \
        /etc/openvpn \
        /etc/ipsec.conf \
        /etc/ipsec.secrets \
        /etc/wireguard \
        /var/www/html 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        echo "✅ Backup successful: $backup_file"
        echo "📦 Size: $(du -h $backup_file | cut -f1)"
    else
        echo "❌ Backup failed!"
    fi
}

restore_backup() {
    echo "🔄 RESTORE BACKUP"
    echo "───────────────"
    
    echo "Available backups:"
    ls -la $BACKUP_DIR/*.tar.gz 2>/dev/null || echo "No backups found"
    
    read -p "Backup file to restore: " backup_file
    
    if [[ ! -f "$backup_file" ]]; then
        echo "❌ Backup file not found!"
        return 1
    fi
    
    echo "Restoring backup..."
    tar -xzf $backup_file -C /
    
    if [[ $? -eq 0 ]]; then
        echo "✅ Restore successful!"
        echo "🔄 Restarting services..."
        systemctl restart ssh openvpn strongswan wireguard@wg0 2>/dev/null
    else
        echo "❌ Restore failed!"
    fi
}

# ==========================================
# VPN PROTOCOLS INSTALLATION
# ==========================================

install_l2tp_ipsec() {
    print_loading "Installing L2TP/IPsec VPN..."
    
    apt install -y strongswan xl2tpd
    
    # IPsec Configuration
    cat > /etc/ipsec.conf << EOF
config setup
    uniqueids=never

conn L2TP-IKEv1
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev1
    fragmentation=yes
    forceencaps=yes
    
    left=%defaultroute
    leftnexthop=%defaultroute
    leftprotoport=17/1701
    
    right=%any
    rightprotoport=17/%any
    rightsubnet=0.0.0.0/0
    rightsourceip=10.0.1.0/24
    
    authby=secret
    ike=aes256-sha2_256-modp2048s256,aes128-sha2_256-modp2048s256!
    esp=aes256-sha2_256,aes128-sha2_256!
EOF

    # Generate PSK
    PSK=$(openssl rand -base64 32)
    echo "%any %any : PSK \"$PSK\"" > /etc/ipsec.secrets
    
    print_success "L2TP/IPsec installed"
    echo "🔐 Pre-Shared Key: $PSK"
    echo "📍 Server: $SERVER_IP"
    echo "🔐 Ports: 500, 4500 UDP"
}

install_openvpn() {
    print_loading "Installing OpenVPN..."
    
    apt install -y openvpn easy-rsa
    
    # Setup Easy-RSA
    cp -r /usr/share/easy-rsa/ /etc/openvpn/
    cd /etc/openvpn/easy-rsa
    
    # Initialize PKI (non-interactive)
    ./easyrsa init-pki
    EASYRSA_REQ_CN="VPN Server" ./easyrsa build-ca nopass
    EASYRSA_REQ_CN="OpenVPN Server" ./easyrsa gen-req server nopass
    ./easyrsa sign-req server server
    ./easyrsa gen-dh
    
    # Server Configuration
    cat > /etc/openvpn/server.conf << EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
EOF

    systemctl enable openvpn@server
    systemctl start openvpn@server
    
    print_success "OpenVPN installed"
    echo "📍 Server: $SERVER_IP"
    echo "🔐 Port: 1194 UDP"
}

install_ssh_udp() {
    print_loading "Installing SSH UDP Server..."
    
    # Download UDP Custom
    wget -q -O /usr/bin/udp-custom "https://github.com/loadfile1/udp-custom/releases/latest/download/udp-custom-linux-amd64"
    chmod +x /usr/bin/udp-custom
    
    # Create service
    cat > /etc/systemd/system/udp-custom.service << EOF
[Unit]
Description=UDP Custom Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/udp-custom server -l 0.0.0.0:1-65535
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable udp-custom
    systemctl start udp-custom
    
    print_success "SSH UDP installed"
    echo "📍 Server: $SERVER_IP"
    echo "🔐 Ports: 1-65535 UDP"
    echo "🚀 Speed: UNLIMITED"
}

install_wireguard() {
    print_loading "Installing WireGuard..."
    
    apt install -y wireguard qrencode
    
    # Generate server keys
    cd /etc/wireguard
    wg genkey | tee server-private.key | wg pubkey > server-public.key
    
    # Server configuration
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat server-private.key)
Address = 10.0.2.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF

    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    print_success "WireGuard installed"
    echo "📍 Server: $SERVER_IP"
    echo "🔐 Port: 51820 UDP"
}

# ==========================================
# MAIN MANAGEMENT MENU
# ==========================================

user_management_menu() {
    while true; do
        echo -e "${BLUE}👤 USER MANAGEMENT${NC}"
        echo "────────────────"
        echo "1. 🧑‍💼 Create User"
        echo "2. 🗑️  Delete User" 
        echo "3. 📋 List All Users"
        echo "4. 👥 View Active Users"
        echo "5. 🛡️  Set IP Limit"
        echo "6. 🚫 Auto Ban System"
        echo "7. 📅 Check User Expiry"
        echo "8. 🚫 View Ban List"
        echo "9. 🔓 Unban IP"
        echo "10. ↩️ Back"
        echo
        
        read -p "Choose [1-10]: " choice
        
        case $choice in
            1) create_ssh_user ;;
            2) delete_ssh_user ;;
            3) list_all_users ;;
            4) view_active_users ;;
            5) limit_user_ip ;;
            6) auto_ban_system ;;
            7) check_user_expiry ;;
            8) view_ban_list ;;
            9) unban_ip ;;
            10) break ;;
            *) echo -e "${RED}Invalid choice!${NC}" ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
    done
}

monitoring_menu() {
    while true; do
        echo -e "${GREEN}📊 MONITORING & BACKUP${NC}"
        echo "────────────────────"
        echo "1. 📈 Monitor Bandwidth"
        echo "2. 🚀 Speed Test (Python)"
        echo "3. 🖥️  System Statistics"
        echo "4. 💾 Backup System"
        echo "5. 🔄 Restore Backup"
        echo "6. ↩️ Back"
        echo
        
        read -p "Choose [1-6]: " choice
        
        case $choice in
            1) monitor_bandwidth ;;
            2) python3_speed_test ;;
            3) show_system_stats ;;
            4) backup_system ;;
            5) restore_backup ;;
            6) break ;;
            *) echo -e "${RED}Invalid choice!${NC}" ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
    done
}

vpn_status_menu() {
    echo -e "${YELLOW}🔧 VPN STATUS${NC}"
    echo "────────────"
    
    echo "L2TP/IPsec: $(systemctl is-active strongswan 2>/dev/null || echo 'Not installed')"
    echo "OpenVPN: $(systemctl is-active openvpn@server 2>/dev/null || echo 'Not installed')"
    echo "SSH UDP: $(systemctl is-active udp-custom 2>/dev/null || echo 'Not installed')"
    echo "WireGuard: $(systemctl is-active wg-quick@wg0 2>/dev/null || echo 'Not installed')"
    
    echo
    read -p "Press Enter to continue..."
}

main_menu() {
    while true; do
        show_banner
        echo -e "${PURPLE}📋 MAIN MENU${NC}"
        echo "──────────"
        echo "1. 👤 User Management"
        echo "2. 📊 Monitoring & Backup"
        echo "3. 🔧 VPN Status"
        echo "4. 🚪 Exit"
        echo
        
        read -p "Choose [1-4]: " choice
        
        case $choice in
            1) user_management_menu ;;
            2) monitoring_menu ;;
            3) vpn_status_menu ;;
            4)
                echo -e "${GREEN}Thank you for using VPN Master Server! 👋${NC}"
                exit 0
                ;;
            *) echo -e "${RED}Invalid choice!${NC}" ;;
        esac
    done
}

# ==========================================
# MAIN INSTALLATION
# ==========================================

main_installation() {
    show_banner
    check_system
    get_server_ip
    
    print_loading "Starting complete VPN installation..."
    
    # Installation steps
    update_system
    install_dependencies
    set_timezone
    optimize_kernel
    create_directories
    configure_firewall
    
    # Install all VPN protocols
    install_l2tp_ipsec
    install_openvpn
    install_ssh_udp
    install_wireguard
    
    # Create web interface
    cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>VPN Master Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .header { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .status { padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid; }
        .success { background: #d4edda; color: #155724; border-color: #28a745; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 VPN Master Server</h1>
            <p>Complete VPN Solution - All Protocols</p>
        </div>
        
        <div class="status success">
            <strong>✅ SERVER STATUS: RUNNING</strong>
        </div>
        
        <div class="status">
            <strong>📊 SERVER INFORMATION:</strong><br>
            IP: <strong>$SERVER_IP</strong><br>
            Protocols: L2TP/IPsec, OpenVPN, SSH UDP, WireGuard<br>
            Timezone: Asia/Jakarta<br>
            Install Date: $(date)
        </div>
        
        <div class="status">
            <strong>🎯 MANAGEMENT:</strong><br>
            Access management menu via SSH:<br>
            <code>sudo bash $0</code>
        </div>
    </div>
</body>
</html>
EOF

    print_success "🎉 VPN MASTER SERVER INSTALLATION COMPLETED!"
    echo
    echo -e "${GREEN}📊 SERVER INFORMATION:${NC}"
    echo -e "  🌐 IP Address: ${GREEN}$SERVER_IP${NC}"
    echo -e "  🖥️  Web Interface: ${GREEN}http://$SERVER_IP${NC}"
    echo -e "  ⏰ Timezone: ${GREEN}Asia/Jakarta${NC}"
    echo
    echo -e "${GREEN}🔧 VPN PROTOCOLS INSTALLED:${NC}"
    echo -e "  🔐 L2TP/IPsec - Ports: 500, 4500 UDP"
    echo -e "  🛡️ OpenVPN - Port: 1194 UDP"  
    echo -e "  🌐 SSH UDP - Ports: 1-65535 UDP"
    echo -e "  ⚡ WireGuard - Port: 51820 UDP"
    echo
    echo -e "${GREEN}🎯 MANAGEMENT:${NC}"
    echo -e "  Run: ${GREEN}sudo bash $0${NC} for management menu"
    echo
    echo -e "${GREEN}📝 FEATURES:${NC}"
    echo -e "  ✅ User Management with IP Limit"
    echo -e "  ✅ Auto Ban System"
    echo -e "  ✅ User Expiry Check"
    echo -e "  ✅ Bandwidth Monitoring"
    echo -e "  ✅ System Backup & Restore"
    echo -e "  ✅ Python Speed Test"
    echo
    echo "================================================================"
}

# Start
if [[ $# -eq 0 ]]; then
    main_installation
    echo
    read -p "Press Enter to start management menu..."
    main_menu
else
    case $1 in
        menu) main_menu ;;
        install) main_installation ;;
        *) echo "Usage: $0 [menu|install]" ;;
    esac
fi