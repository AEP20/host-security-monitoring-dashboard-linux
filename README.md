# HIDS – Host Intrusion Detection Dashboard

A lightweight Flask-based security monitoring dashboard for a single Linux machine.
Tracks logs, processes, ports, CPU/RAM and detects suspicious activity through rule-based analysis.

## Features
- System metrics monitoring
- Log parsing (auth, syslog, kernel)
- Rule engine for suspicious activity
- Config checker for insecure settings
- Web dashboard (Flask + Jinja)

## Installation & Commands

```bash
# Permission Setup
chmod +x scripts/run_dev.sh
chmod +x scripts/venv-activate.sh
chmod +x scripts/venv-deactivate.sh

# Paths & File System
/opt/HIDS/                      # Proje kodları (deploy ile değişebilir)
/var/lib/hids/hids.db           # Kalıcı veritabanı
/var/lib/hids/log_offsets.json  # Log offsetleri (kalıcı)
/etc/hids/config.json           # Ayarlar
/usr/local/bin/hids-deploy      # GitHub’dan projeyi otomatik indirir/sync eder
                                # (/opt/HIDS'deki geçici veriler kaybedilir)

# Virtual Environment
source /opt/HIDS/venv/bin/activate

# Service Management (/etc/systemd/system/hids.service)
sudo systemctl daemon-reload
sudo systemctl restart hids.service
sudo systemctl status hids.service
sudo systemctl enable hids.service
sudo systemctl stop hids.service
sudo systemctl start hids.service
sudo journalctl -u hids.service -f

# Logging & Maintenance
/var/log/hids/app.log           # HIDS uygulama logları
tail -n 150 /var/log/hids/app.log
sudo truncate -s 0 /var/log/hids/app.log # Uygulama içi logları temizle

sudo nmap -T1 -p- 127.0.0.1 # test scan
sudo tcpdump -i lo     # test capture
```