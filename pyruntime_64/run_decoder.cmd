@echo off
title ZTE Config Decoder (Portable)

set PY=python.exe
set IN=config\config.bin
set OUT=config\output.xml

if not exist "%IN%" (
    echo [ERROR] File config.bin tidak ditemukan di folder config!
    pause
    exit
)

:menu
cls
echo =====================================
echo        ZTE CONFIG DECODER
echo =====================================
echo.
echo [1] Auto Mode (Default)
echo [2] Normal Mode
echo [3] Skip145 Mode
echo [4] Trykeys Mode
echo [5] Decode + Check Login
echo [6] Advanced (Custom Arguments)
echo [0] Exit
echo.
set /p OPT=Pilih menu: 

if "%OPT%"=="1" goto auto
if "%OPT%"=="2" goto normal
if "%OPT%"=="3" goto skip
if "%OPT%"=="4" goto trykeys
if "%OPT%"=="5" goto checklogin
if "%OPT%"=="6" goto advanced
if "%OPT%"=="0" exit

goto menu

:auto
%PY% decoder.py %IN% %OUT%
pause
goto menu

:normal
%PY% decoder.py %IN% %OUT% --mode normal
pause
goto menu

:skip
%PY% decoder.py %IN% %OUT% --mode skip145
pause
goto menu

:trykeys
%PY% decoder.py %IN% %OUT% --mode trykeys
pause
goto menu

:checklogin
echo.
set /p IP=Masukkan IP Router (contoh 192.168.1.1): 
%PY% decoder.py %IN% %OUT% --check-login http://%IP%
pause
goto menu

:advanced
cls
echo =====================================
echo        ADVANCED DECODER MODE
echo =====================================
echo.
echo Argumen yang sering digunakan (ZTE):
echo.
echo   --model F670L
echo   --serial ZTE123456789
echo   --mac AA:BB:CC:11:22:33
echo   --signature "ZXHN F670L"
echo.
echo Contoh kombinasi:
echo   --model F670L --serial ZTE123456789 --mac AA:BB:CC:11:22:33
echo.
echo Gunakan:
echo   python.exe decoder.py --help
echo untuk melihat semua opsi lengkap.
echo.
set /p ARGS=Masukkan argumen decoder: 

%PY% decoder.py %IN% %OUT% %ARGS%
pause
goto menu