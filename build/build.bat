@echo off
:: build.bat — Gera apenas o usb_agent.exe via PyInstaller (sem instalador)
:: Para o instalador completo, use: build\build_installer.bat

echo ============================================================
echo  IN9USBAgent — Build PyInstaller (somente .exe)
echo ============================================================

pyinstaller ^
    --onefile ^
    --name usb_agent ^
    --noconsole ^
    --hidden-import win32timezone ^
    --hidden-import win32service ^
    --hidden-import win32serviceutil ^
    --hidden-import win32event ^
    --hidden-import win32job ^
    --hidden-import win32process ^
    --hidden-import win32api ^
    --hidden-import win32security ^
    --hidden-import ntsecuritycon ^
    --hidden-import win32con ^
    --hidden-import servicemanager ^
    --hidden-import wmi ^
    --hidden-import pywintypes ^
    --hidden-import pystray._win32 ^
    --hidden-import PIL.Image ^
    --hidden-import PIL.ImageDraw ^
    --collect-all pystray ^
    main.py

if %errorlevel% neq 0 (
    echo ERRO: Build falhou.
    exit /b 1
)

echo.
echo dist\usb_agent.exe gerado.
echo Para o instalador completo: build\build_installer.bat
