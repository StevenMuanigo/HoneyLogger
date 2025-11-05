@echo off
echo ================================
echo   HoneyLogger - Build Script
echo ================================
echo.

echo [1/3] Go modulleri indiriliyor...
go mod download
if %errorlevel% neq 0 (
    echo HATA: Go modulleri indirilemedi!
    pause
    exit /b 1
)

echo [2/3] Kod derleniyor...
go build -o honeylogger.exe main.go
if %errorlevel% neq 0 (
    echo HATA: Derleme basarisiz!
    pause
    exit /b 1
)

echo [3/3] Tamamlandi!
echo.
echo ================================
echo   Build basarili!
echo   Calistirmak icin: run.bat
echo ================================
pause
