#!/bin/bash

# ----------------------------
# Deployment Script (Safe Mode)
# ----------------------------

REPO_DIR="/opt/HIDS"
SSH_KEY="/etc/hidsssh/hids_deploy_key"

echo "[+] Starting deployment..."

# 1) Repo klasörüne gir
cd "$REPO_DIR" || { echo "[-] Repo directory not found!"; exit 1; }

# 2) Son kodları çek (özel key ile)
echo "[+] Pulling latest code from GitHub..."
GIT_SSH_COMMAND="ssh -i $SSH_KEY -o IdentitiesOnly=yes" git pull

# 3) Venv aktif et
echo "[+] Activating virtual environment..."
source venv/bin/activate

# 4) Gereksinimleri yükle
echo "[+] Installing requirements..."
pip install -r backend/requirements.txt

# 5) Servisi restart et
echo "[+] Restarting systemd service..."
sudo systemctl restart hids.service

echo "[+] Deployment completed successfully!"

# before run
# chmod +x /opt/HIDS/scripts/deploy.sh
