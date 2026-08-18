@echo off
setlocal
REM AEGIS launcher for Windows. Double-click this file.
REM
REM Runs setup on first launch (config + build), then starts the server and
REM opens the console. Safe to run repeatedly: setup keeps existing tokens
REM and data, so this is just "start AEGIS" every time after the first.

cd /d "%~dp0"
title AEGIS

echo.
echo   AEGIS
echo   =====
echo.

REM Find Node. PATH first, then the usual install locations - a fresh install
REM often isn't on PATH until the user logs out and back in, and per-user
REM installs frequently never are. Failing there would send people hunting a
REM problem they don't have.
set "NODE="
where node >nul 2>&1 && set "NODE=node"
if not defined NODE if exist "%ProgramFiles%\nodejs\node.exe" set "NODE=%ProgramFiles%\nodejs\node.exe"
if not defined NODE if exist "%ProgramFiles(x86)%\nodejs\node.exe" set "NODE=%ProgramFiles(x86)%\nodejs\node.exe"
if not defined NODE if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" set "NODE=%LOCALAPPDATA%\Programs\nodejs\node.exe"
if not defined NODE if exist "%APPDATA%\nvm\node.exe" set "NODE=%APPDATA%\nvm\node.exe"

if not defined NODE (
  echo   Node.js is not installed, or not on PATH.
  echo.
  echo   Install the LTS build from https://nodejs.org and run this again.
  echo   ^(Node 18 or newer. Nothing else is needed - AEGIS has no
  echo    dependencies to download.^)
  echo.
  pause
  exit /b 1
)

if not exist "server\config.json" (
  echo   First run - setting up...
  echo.
  "%NODE%" setup.mjs
  if errorlevel 1 (
    echo.
    echo   Setup failed. See the message above.
    pause
    exit /b 1
  )
  echo.
  echo   Press any key to start the server...
  pause >nul
) else (
  REM Rebuild so the console always matches the current source.
  "%NODE%" build.mjs >nul 2>&1
)

REM Give the server a moment to bind before the browser asks for the page.
REM ping, not timeout: timeout refuses to run when stdin is redirected, which
REM happens whenever this is launched from another process rather than a
REM console, and it fails loudly enough to look like AEGIS itself broke.
start "" /b cmd /c "ping -n 3 127.0.0.1 >nul & start http://127.0.0.1:8787"

echo.
echo   Starting AEGIS. Close this window to stop it.
echo.
"%NODE%" server\aegis-server.mjs --config ./server/config.json

echo.
echo   AEGIS has stopped.
pause
