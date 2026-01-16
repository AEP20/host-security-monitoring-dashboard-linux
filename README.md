# HIDS – Host Intrusion Detection Dashboard

A lightweight Flask-based security monitoring dashboard for a single Linux machine.
Tracks logs, processes, ports, CPU/RAM and detects suspicious activity through rule-based analysis.

## Features
- System metrics monitoring
- Log parsing (auth, syslog, kernel)
- Rule engine for suspicious activity
- Web dashboard (Flask + Jinja)

## Installation & Commands


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

flask --app backend.dev_app --debug run -p 3001 # dev run

HIDS_API_MODE=real HIDS_BACKEND_URL=http://192.168.x.x:5000 \
flask --app backend.dev_app --debug run -p 3001 # dev run with real api


WHERE alert_id IN (
    SELECT id
    FROM alerts
    WHERE timestamp >= datetime('now', '-1 day')
);
sqlite> DELETE FROM alerts
WHERE timestamp >= datetime('now', '-1 day');
sqlite> exi


## Contributors
- Ahmet Emre Parmaksız (@AEP20)
- Deniz Özmen (@dozmen23)

```