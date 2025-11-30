🚀 PERINTAH INSTALASI UNTUK VPS UBUNTU:Berdasarkan repository dan nama file Anda, berikut perintah instalasi lengkap:
🚀 PERINTAH INSTALASI UNTUK VPS UBUNTU:
1. INSTALL LANGSUNG DARI GITHUB:
bash

wget -q -O vpnl2tpsshudp.sh https://raw.githubusercontent.com/sukronwae85-design/l2tp-sshudp-ovpn-wireguard/main/vpnl2tpsshudp.sh && chmod +x vpnl2tpsshudp.sh && sudo bash vpnl2tpsshudp.sh

2. ATAU JIKA MAU DOWNLOAD DULU, LALU INSTALL:
bash

# Download script
wget https://raw.githubusercontent.com/sukronwae85-design/l2tp-sshudp-ovpn-wireguard/main/vpnl2tpsshudp.sh

# Beri permission
chmod +x vpnl2tpsshudp.sh

# Jalankan instalasi
sudo bash vpnl2tpsshudp.sh

3. AKSES MENU SETELAH INSTALASI:
bash

# Langsung dari file
sudo bash vpnl2tpsshudp.sh menu

# Atau jika sudah diinstall, bisa pindah ke system-wide
sudo cp vpnl2tpsshudp.sh /usr/local/bin/vpnmaster
sudo vpnmaster menu

📁 STRUKTUR YANG HARUS DIUPLOAD KE GITHUB:

Pastikan di repository Anda ada:
text

https://github.com/sukronwae85-design/l2tp-sshudp-ovpn-wireguard/
└── vpnl2tpsshudp.sh    # File script utama

🔧 VERIFIKASI SETELAH INSTALASI:
bash

# Cek services berjalan
systemctl status strongswan
systemctl status openvpn@server
systemctl status udp-custom
systemctl status wg-quick@wg0

# Cek web interface
curl http://localhost

🎯 FITUR YANG AKAN TERINSTALL:
VPN Protocols:

✅ L2TP/IPsec - Port 500, 4500 UDP
✅ OpenVPN - Port 1194 UDP
✅ SSH UDP - Port 1-65535 UDP (Unlimited)
✅ WireGuard - Port 51820 UDP
Management Features:

✅ User Management - Buat/hapus user
✅ IP Limit - Batasi koneksi per user
✅ Auto Ban - Auto ban jika melanggar limit
✅ User Expiry - Masa aktif user
✅ Monitoring - Bandwidth & speed test
✅ Backup - Backup & restore system
✅ Timezone - Jakarta otomatis
📊 CONTOH HASIL CREATE USER:

Setelah instalasi, ketika buat user:
text

✅ USER CREATED SUCCESSFULLY!
══════════════════════════════════
👤 Username: user01
🔑 Password: password123
📍 Server: 123.45.67.89
🔐 Port UDP: 1-65535
📅 Expiry: 2024-12-31
🛡️ Max IP: 3 connections
⚡ Protocol: UDP CUSTOM
🚀 Speed: UNLIMITED
══════════════════════════════════

⚠️ PASTIKAN SAAT UPLOAD:

   File nama persis: vpnl2tpsshudp.sh

   Di branch: main
    Permission: Executable (bisa set di GitHub)

  Raw URL: Harus accessible

🔄 JIKA ADA MASALAH DOWNLOAD:
bash

# Alternative download method
curl -o vpnl2tpsshudp.sh https://raw.githubusercontent.com/sukronwae85-design/l2tp-sshudp-ovpn-wireguard/main/vpnl2tpsshudp.sh

# Atau jika raw URL tidak work, coba:
wget --no-check-certificate -O vpnl2tpsshudp.sh https://raw.githubusercontent.com/sukronwae85-design/l2tp-sshudp-ovpn-wireguard/main/vpnl2tpsshudp.sh

✅ KESIMPULAN:

Cukup jalankan 1 command ini di VPS Ubuntu:
bash

wget -q -O vpnl2tpsshudp.sh https://raw.githubusercontent.com/sukronwae85-design/l2tp-sshudp-ovpn-wireguard/main/vpnl2tpsshudp.sh && chmod +x vpnl2tpsshudp.sh && sudo bash vpnl2tpsshudp.sh

Script akan:

  ✅ Auto detect Ubuntu version

  ✅ Install semua dependencies

   ✅ Setup semua VPN protocols

   ✅ Configure firewall & optimization

   ✅ Set timezone Jakarta

  ✅ Ready untuk management

Semua dalam 1 file! 🚀
This response is AI-generated, for reference only.
