#!/bin/bash
set -e

APP_DIR="/opt/Excalibur"

echo "[*] Deploying Excalibur..."

#rsync -av --delete \
#    --exclude=".git" \
#    --exclude=".venv" \
#    --exclude="*.sqlite" \
#    --exclude="*.sqlite-shm" \
#    --exclude="*.sqlite-wal" \
#    --exclude="__pycache__" \
#    --exclude="*.pyc" \
#    ./ \
#    "$APP_DIR/"

# Prevent deployments from overwriting production rule packs.
# TODO: Replace with proper rule deployment/override mechanism.

rsync -av \
    --exclude=".git" \
    --exclude=".venv" \
    --exclude="*.sqlite*" \
    --exclude="rules/" \
    --exclude="__pycache__" \
    --exclude="third_party/" \
    --exclude="*.pyc" \
    ./ \
    "$APP_DIR/"

chown -R excalibur:excalibur "$APP_DIR"

if systemctl list-unit-files | grep -Fq "excalibur-helper.service"; then
    systemctl restart excalibur-helper.service
fi
systemctl restart excalibur-sniffer excalibur-dashboard

echo "[+] Deployment complete."
