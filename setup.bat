@echo off
setlocal EnableDelayedExpansion

:: Always work from the project folder (handles spaces in path)
cd /d "%~dp0"

:: ── Auto-elevate: re-launch this exact file as admin ────
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

echo ============================================
echo  IDS Project - First-Time Setup
echo ============================================
echo.

:: ── Check Python ─────────────────────────────
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Python not found. Install Python 3.10+ from https://python.org
    echo     Tick "Add Python to PATH" during install, then run setup.bat again.
    pause
    exit /b 1
)
echo [+] Python found.

:: ── Create required directories ──────────────
if not exist logs mkdir logs
if not exist database mkdir database
echo [+] Directories ready.

:: ── Install Python dependencies ──────────────
echo.
echo [*] Installing Python dependencies (this may take a minute)...
python -m pip install -r requirements.txt --quiet
if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] pip install failed.
    echo     Make sure you have an internet connection and try again.
    pause
    exit /b 1
)
echo [+] Python packages installed.

:: ── Check / Install Npcap ────────────────────
echo.
echo [*] Checking for Npcap...
sc query npcap >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [+] Npcap is already installed.
) else (
    reg query "HKLM\SOFTWARE\Npcap" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        echo [+] Npcap is already installed.
    ) else (
        reg query "HKLM\SOFTWARE\WOW6432Node\Npcap" >nul 2>&1
        if %ERRORLEVEL% equ 0 (
            echo [+] Npcap is already installed.
        ) else (
            echo.
            echo [!] Npcap is not installed.
            echo     Opening the Npcap download page in your browser...
            echo.
            echo     STEPS:
            echo       1. Download the latest Npcap installer
            echo       2. Run it
            echo       3. Tick "WinPcap API-compatible mode"
            echo       4. Complete the install
            echo       5. Come back here and press any key to continue setup
            echo.
            start "" "https://npcap.com/#download"
            pause
        )
    )
)

:: ── Detect network interface ─────────────────
echo.
echo [*] Detecting network interface...
set "DETECTED_IF=Wi-Fi"
for /f "tokens=*" %%a in ('ipconfig ^| findstr /i "Wi-Fi\|Wireless\|Ethernet adapter" ^| findstr /v "VirtualBox\|VMware\|Loopback\|vEthernet"') do (
    set "LINE=%%a"
    set "LINE=!LINE:*adapter !=!"
    set "LINE=!LINE::=!"
    set "DETECTED_IF=!LINE!"
    goto :IF_DONE
)
:IF_DONE
echo [+] Using interface: %DETECTED_IF%

:: ── Create start.bat ─────────────────────────
echo.
echo [*] Creating start.bat...
(
    echo @echo off
    echo cd /d "%%~dp0"
    echo title IDS Dashboard
    echo set IDS_INTERFACE=%DETECTED_IF%
    echo set IDS_HOST=0.0.0.0
    echo set IDS_PORT=5000
    echo set IDS_USER=admin
    echo set IDS_PASSWORD=changeme
    echo.
    echo echo [*] Checking dependencies...
    echo python -m pip install -r requirements.txt --quiet
    echo.
    echo echo [*] Starting IDS... Browser will open at http://127.0.0.1:5000
    echo timeout /t 2 /nobreak ^>nul
    echo start "" http://127.0.0.1:5000
    echo python run_dashboard.py --with-ids
    echo pause
) > start.bat
echo [+] start.bat created.

echo.
echo ============================================
echo  Setup complete!
echo ============================================
echo.
echo  HOW TO USE:
echo  - Double-click  start.bat  to launch the IDS.
echo  - Browser opens automatically at http://127.0.0.1:5000
echo  - Login: admin / changeme
echo.
echo  To change the password, open start.bat in Notepad
echo  and edit the IDS_PASSWORD line before starting.
echo.
pause
echo  and edit the IDS_PASSWORD line before starting.
echo.
pause
