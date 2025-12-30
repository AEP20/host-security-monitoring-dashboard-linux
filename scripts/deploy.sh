#!/bin/bash

# ----------------------------
# Deployment Script (Safe Mode)
# ----------------------------

REPO_DIR="/opt/HIDS"
SSH_KEY="/etc/hidsssh/hids_deploy_key"

echo "[+] Starting deployment..."

cd "$REPO_DIR" || { echo "[-] Repo directory not found!"; exit 1; }

echo "[+] Pulling latest code from GitHub..."
GIT_SSH_COMMAND="ssh -i $SSH_KEY -o IdentitiesOnly=yes" git fetch --all
git reset --hard origin/main

echo "[+] Activating virtual environment..."
source venv/bin/activate

echo "[+] Installing requirements..."
pip install -r backend/requirements.txt

echo "[+] Restarting systemd service..."
sudo systemctl restart hids.service

echo "[+] Deployment completed successfully!"

# before run
# chmod +x /opt/HIDS/scripts/deploy.sh
