# CyberGuard AI Enterprise Launcher
$env:Path += ";C:\Users\Teddy\nodejs"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "       STARTING CYBERGUARD AI ENTERPRISE PLATFORM      " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# 1. Start Backend in separate process
Write-Host "[1/3] Starting FastAPI Backend on http://localhost:8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

# 2. Start Worker in separate process
Write-Host "[2/3] Starting Background Ingestion Worker..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; python -m app.queue.worker"

# 3. Start Frontend in separate process
Write-Host "[3/3] Starting React SOC Dashboard on http://localhost:5173..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\frontend'; npm run dev"

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " CyberGuard AI is online:" -ForegroundColor White
Write-Host "  - SOC Web Dashboard : http://localhost:5173" -ForegroundColor Yellow
Write-Host "  - FastAPI Docs API  : http://localhost:8000/api/v1/docs" -ForegroundColor Yellow
Write-Host "  - Metrics / Probes  : http://localhost:8000/metrics" -ForegroundColor Yellow
Write-Host ""
Write-Host " Default SOC Admin Credentials:" -ForegroundColor White
Write-Host "   Username: admin" -ForegroundColor Gray
Write-Host "   Password: AdminSecret123!" -ForegroundColor Gray
Write-Host "=======================================================" -ForegroundColor Cyan
