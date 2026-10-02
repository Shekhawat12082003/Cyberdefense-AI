@echo off
echo ============================================================
echo  CyberDefense-AI — Starting with Administrator privileges
echo  This enables full packet capture for nmap/brute-force detection
echo ============================================================
echo.

:: Check if already admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running as Administrator
) else (
    echo [!] Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/k cd /d %CD% && call start_admin.bat' -Verb RunAs"
    exit /b
)

echo.
echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

echo [*] Starting CyberDefense-AI backend...
echo     Local IP will be detected automatically
echo     Port scan threshold: 5 ports / 30s
echo     Brute force threshold: 8 attempts / 60s
echo.
python app.py

pause
