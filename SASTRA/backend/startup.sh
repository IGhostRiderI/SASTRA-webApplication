#!/bin/bash
set -e

cd /home/site/wwwroot/SASTRA/backend

# Ensure data directory exists (SQLite + logs + backups will be created here)
mkdir -p app/data/logs app/data/backups

pip install --quiet -r requirements.txt

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
