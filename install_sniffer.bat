@echo off
setlocal EnableDelayedExpansion

echo =======================================================
echo     Rafael Sniffer - Environment Checker
echo =======================================================

:: 1. Check Python
echo [1/4] Checking Python Environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [MISSING] Python is not installed.
    start https://www.python.org/downloads/
    pause && exit /b
)

:: 2. Check Wireshark (Registry + Common Folders)
echo [2/4] Detecting Wireshark...
set "WIRESHARK_PATH="

:: A. Try Registry
for %%k in ("HKLM\SOFTWARE\Wireshark" "HKLM\SOFTWARE\WOW6432Node\Wireshark") do (
    for /f "tokens=2*" %%a in ('reg query %%k /v "InstallDir" 2^>nul') do (
        set "WIRESHARK_PATH=%%b"
    )
)

:: B. Try Default Paths if Registry failed
if not exist "!WIRESHARK_PATH!" (
    if exist "C:\Program Files\Wireshark\Wireshark.exe" (
        set "WIRESHARK_PATH=C:\Program Files\Wireshark"
    ) else if exist "C:\Program Files (x86)\Wireshark\Wireshark.exe" (
        set "WIRESHARK_PATH=C:\Program Files (x86)\Wireshark"
    )
)

:: C. Final check
if not exist "!WIRESHARK_PATH!" (
    echo [MISSING] Wireshark not detected. 
    echo If you HAVE installed it, please run Wireshark once or check your path.
    echo Opening download page just in case...
    start https://www.wireshark.org/download.html
    pause && exit /b
)
echo [FOUND] Wireshark located at: !WIRESHARK_PATH!

:: 3. Setup Folders
set "USER_EXTCAP=%APPDATA%\Wireshark\extcap"
if not exist "!USER_EXTCAP!" mkdir "!USER_EXTCAP!"

:: 4. Install & Deploy
echo [3/4] Installing Dependencies (pyspinel)...
python -m pip install --user .

echo [4/4] Deploying extcap files...
python setup.py install --extcap-path="!USER_EXTCAP!"

if exist "extcap_ot.bat" (
    copy /Y "extcap_ot.bat" "!USER_EXTCAP!\" >nul
)

echo =======================================================
echo [SUCCESS] Installation Complete!
echo 1. Restart Wireshark.
echo 2. Find "OpenThread Sniffer" in the interface list.
echo =======================================================
pause