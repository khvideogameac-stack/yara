@echo off
:: Wazuh Active Response wrapper for YARA PowerShell scanner
:: This file must be in: C:\Program Files (x86)\ossec-agent\active-response\bin\
::
:: Called automatically by Wazuh when FIM detects file changes
:: Executes yara-scan.ps1 which scans the file and logs results

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0yara-scan.ps1"
exit /b %ERRORLEVEL%
