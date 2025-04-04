@echo off
set servicesPath=HKLM\SYSTEM\CurrentControlSet\Services
:: Loop through all subkeys (services) in the Services registry path
for /f "tokens=*" %%i in ('reg query "%servicesPath%" /s /f "" ^| findstr "HKEY_LOCAL_MACHINE"') do (
    :: Disable SvcHostSplitDisable for each service
    reg add "%%i" /v SvcHostSplitDisable /t REG_DWORD /d 1 /f
)
:: Install RamCleaner
mkdir %windir%\Setup\Scripts
copy /y emptystandbylist.exe %windir%\Setup\Scripts\emptystandbylist.exe
copy /y RamCleaner.bat %windir%\Setup\Scripts\RamCleaner.bat
schtasks /create /tn "RamCleaner" /xml "RamCleaner.xml" /ru "SYSTEM"


