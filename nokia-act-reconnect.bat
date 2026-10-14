@echo off
rem ===========================================================================
rem  nokia-act-reconnect - JDownloader reconnect for Nokia / Alcatel-Lucent
rem  GPON ONT routers.
rem
rem  Usage:
rem    nokia-reconnect.bat                 reboot the ONT (reconnect)
rem    nokia-reconnect.bat -Mode test      verify login + encryption, no reboot
rem    nokia-reconnect.bat -ConfigFile "C:\path\to\config.psd1"
rem
rem  Exit code 0 = success (JDownloader treats 0 as a successful reconnect).
rem ===========================================================================
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0nokia-reconnect.ps1" %*
exit /b %ERRORLEVEL%
