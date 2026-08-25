@echo off
setlocal
echo =======================================================
echo          STARTING CYBERGUARD AI ENTERPRISE PLATFORM
echo =======================================================

set PATH=%PATH%;C:\Users\Teddy\nodejs

echo [1/3] Starting CyberGuard AI FastAPI Backend (Port 8000)...
start "CyberGuard Backend" cmd /k "cd /d %~dp0backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

echo [2/3] Starting CyberGuard AI Async Worker...
start "CyberGuard Worker" cmd /k "cd /d %~dp0backend && python -m app.queue.worker"

echo [3/3] Starting CyberGuard AI React SOC Dashboard (Port 5173)...
start "CyberGuard Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo =======================================================
echo  CyberGuard AI is launching!
echo  - SOC Web Dashboard : http://localhost:5173
echo  - FastAPI Docs API  : http://localhost:8000/api/v1/docs
echo  - Metrics / Probes  : http://localhost:8000/metrics
echo.
echo  Default SOC Admin Credentials:
echo    Username: admin
echo    Password: AdminSecret123!
echo =======================================================
