@echo off
title GREEN GRID - Development Launcher
echo ===================================================
echo Starting GREEN GRID Development Servers (Windows)
echo ===================================================

echo [1/2] Starting Flask Backend on http://127.0.0.1:5000 ...
start "GREEN GRID - Backend Server" cmd /k "cd /d %~dp0backend && python app.py"

echo [2/2] Starting Vite Frontend on http://127.0.0.1:5173 ...
start "GREEN GRID - Frontend Client" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo Both development servers have been launched in separate terminals:
echo   - Backend:      http://127.0.0.1:5000/api
echo   - Health Check: http://127.0.0.1:5000/api/health
echo   - Frontend:     http://localhost:5173
echo.
pause
