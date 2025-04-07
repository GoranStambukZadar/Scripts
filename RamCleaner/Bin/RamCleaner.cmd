@echo off

:: Install RamCleaner
mkdir %windir%\Setup\Scripts
copy /y emptystandbylist.exe %windir%\Setup\Scripts\emptystandbylist.exe
copy /y RamCleaner.bat %windir%\Setup\Scripts\RamCleaner.bat
schtasks /create /tn "RamCleaner" /xml "RamCleaner.xml" /ru "SYSTEM"