@echo off
title ZTE Config Encoder (Portable)

set PY=python.exe
set XML=config\output.xml

if not exist "%XML%" (
    echo [ERROR] File output.xml tidak ditemukan di folder config!
    pause
    exit
)

:menu
cls
echo =====================================
echo        ZTE CONFIG ENCODER
echo =====================================
echo.
echo [0] Type 0 - RAW
echo [1] Type 1 - Compressed
echo [2] Type 2 - AES ECB
echo [3] Type 3 - AES CBC (KP Variant)
echo [4] Type 4 - AES CBC (GPON Lama)
echo [5] Type 5 - AES CBC (Manual)
echo [6] Type 6 - AES CBC + Template
echo.
echo [9] Advanced (Custom Arguments)
echo [H] Help (Lihat semua opsi)
echo [X] Exit
echo.
set /p TYPE=Pilih menu:  

if "%TYPE%"=="0" goto type0
if "%TYPE%"=="1" goto type1
if "%TYPE%"=="2" goto type2
if "%TYPE%"=="3" goto type3
if "%TYPE%"=="4" goto type4
if "%TYPE%"=="5" goto type5
if "%TYPE%"=="6" goto type6
if "%TYPE%"=="9" goto advanced
if /I "%TYPE%"=="H" goto help
if /I "%TYPE%"=="X" exit

goto menu

:type0
%PY% encoder.py --xml %XML% --out config/type0.bin --payload-type 0 --verbose
pause
goto menu

:type1
%PY% encoder.py --xml %XML% --out config/type1.bin --payload-type 1 --verbose
pause
goto menu

:type2
echo.
set /p KEY=Masukkan KEY (HEX / ASCII): 
%PY% encoder.py --xml %XML% --out config/type2.bin --payload-type 2 --key %KEY% --verbose
pause
goto menu

:type3
echo.
set /p SERIAL=Masukkan SERIAL: 
set /p MAC=Masukkan MAC (AA:BB:CC:11:22:33): 
%PY% encoder.py --xml %XML% --out config/type3.bin --payload-type 3 --serial %SERIAL% --mac %MAC% --verbose
pause
goto menu

:type4
echo.
set /p SERIAL=Masukkan SERIAL: 
set /p MAC=Masukkan MAC (AA:BB:CC:11:22:33): 
%PY% encoder.py --xml %XML% --out config/type4.bin --payload-type 4 --serial %SERIAL% --mac %MAC% --verbose
pause
goto menu

:type5
echo.
set /p KEY=Masukkan KEY: 
set /p IV=Masukkan IV (boleh kosong): 
if "%IV%"=="" (
    %PY% encoder.py --xml %XML% --out config/type5.bin --payload-type 5 --key %KEY% --verbose
) else (
    %PY% encoder.py --xml %XML% --out config/type5.bin --payload-type 5 --key %KEY% --iv %IV% --verbose
)
pause
goto menu

:type6
echo.
set /p SERIAL=Masukkan SERIAL: 
set /p MAC=Masukkan MAC: 
%PY% encoder.py --template config/config.bin --xml %XML% --out config/type6.bin --payload-type 6 --serial %SERIAL% --mac %MAC% --verbose
pause
goto menu

:advanced
cls
echo =====================================
echo        ADVANCED ENCODER MODE
echo =====================================
echo.
echo File XML   : config/output.xml
echo Output BIN : config/config_new.bin
echo.
echo Contoh argumen yang sering dipakai:
echo.
echo   --payload-type 1 --compress lzma
echo.
echo   --payload-type 4 --serial ZTE123456789 --mac AA:BB:CC:11:22:33
echo.
echo   --payload-type 6 --template config/config.bin --serial ZTE123456789 --mac AA:BB:CC:11:22:33
echo.
echo Gunakan:
echo   python.exe encoder.py --help
echo untuk melihat semua opsi lengkap.
echo.
set /p ARGS=Masukkan argumen encoder: 

%PY% encoder.py --xml config\output.xml --out config\config_new.bin %ARGS%
pause
goto menu

:help
cls
echo =====================================
echo        ENCODER HELP
echo =====================================
echo.
%PY% encoder.py --help
echo.
pause
goto menu