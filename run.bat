@echo off
echo ================================
echo   HoneyLogger - Starting
echo ================================
echo.

if not exist honeylogger.exe (
    echo HATA: honeylogger.exe bulunamadi!
    echo Once build.bat calistirin.
    pause
    exit /b 1
)

echo Honeypot sistemi baslatiliyor...
echo.
honeylogger.exe
