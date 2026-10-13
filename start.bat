@echo off
chcp 65001 > nul
echo Gmail 
cd /d "%~dp0"
python -B app.py
pause
