@echo off
cd /d "%~dp0"
title IDS Dashboard
set IDS_INTERFACE=Wi-Fi
set IDS_HOST=0.0.0.0
set IDS_PORT=5000
set IDS_USER=admin
set IDS_PASSWORD=changeme

echo [*] Checking dependencies...
python -m pip install -r requirements.txt --quiet

echo [*] Starting IDS... Browser will open at http://127.0.0.1:5000
timeout /t 2 /nobreak >nul
start "" http://127.0.0.1:5000
python run_dashboard.py --with-ids
pause
