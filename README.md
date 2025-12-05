# HIDS – Host Intrusion Detection Dashboard

A lightweight Flask-based security monitoring dashboard for a single Linux machine.
Tracks logs, processes, ports, CPU/RAM and detects suspicious activity through rule-based analysis.

## Features
- System metrics monitoring
- Log parsing (auth, syslog, kernel)
- Rule engine for suspicious activity
- Config checker for insecure settings
- Web dashboard (Flask + Jinja)

## Installation


## 
chmod +x scripts/run_dev.sh
chmod +x scripts/venv-activate.sh
chmod +x scripts/venv-deactivate.sh

/opt/HIDS/                  -> Proje kodları (deploy ile değişebilir)
/var/lib/hids/hids.db       -> Kalıcı veritabanı
/var/lib/hids/log_offsets.json -> Log offsetleri (kalıcı)
/var/log/hids/              -> HIDS çalışma logları
/etc/hids/config.json       -> Ayarlar
/etc/systemd/system/hids.service -> HIDS servisinin başlatma/durdurma/auto-restart yapılandırması, /opt/HIDS/backend/app.py üzerinden başlatır.
/usr/local/bin/hids-deploy -> GitHub’dan projeyi otomatik indirir/sync eder, /opt/HIDS'deki geçici veriler kaybedilir
source /opt/HIDS/venv/bin/activate -> activate venv
