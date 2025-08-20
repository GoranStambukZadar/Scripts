@echo off
takeown /f %windir%\system32\consent.exe /A
icacls %windir%\system32\consent.exe /inheritance:r /T /C
icacls %windir%\system32\consent.exe /grant:r "Console Logon":RX
icacls %windir%\system32\consent.exe /remove "ALL APPLICATION PACKAGES"
icacls %windir%\system32\consent.exe /remove "ALL RESTRICTED APPLICATION PACKAGES"
icacls %windir%\system32\consent.exe /remove "System"
icacls %windir%\system32\consent.exe /remove "Users"
icacls %windir%\system32\consent.exe /remove "Authenticated Users"
icacls %windir%\system32\consent.exe /remove "Administrators"
icacls %windir%\system32\consent.exe /remove "NT SERVICE\TrustedInstaller"
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f