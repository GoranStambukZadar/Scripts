@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

:: Configuration
set "BROWSER_PROCESSES=battle chrome firefox flash iexplore iexplorer opera palemoon plugin-container skype steam yahoo"
set "VNC_PROCESSES=winvnc winvnc4 uvnc_service tvnserver"
set "FLASH_GUIDS_ACTIVE_X=cdf0cc64-4741-4e43-bf97-fef8fa1d6f1c ..."
set "FLASH_GUIDS_PLUGIN=F6E23569-A22A-4924-93A4-3F215BEF63D2 ..."

:: Clean Flash Player
for %%i in (%BROWSER_PROCESSES%) do taskkill /F /IM "%%i*" /T 2>NUL
wmic product where "name like 'Adobe Flash Player%%'" uninstall /nointeractive 2>NUL
for %%g in (%FLASH_GUIDS_ACTIVE_X% %FLASH_GUIDS_PLUGIN%) do MsiExec.exe /uninstall {%%g} /quiet /norestart 2>NUL

:: Clean VNC
for %%s in (%VNC_PROCESSES%) do (
    net stop %%s 2>NUL
    taskkill /F /IM %%s.exe 2>NUL
    sc delete %%s 2>NUL
)
for %%k in (UltraVNC ORL RealVNC TightVNC) do reg delete "HKLM\SOFTWARE\%%k" /f 2>NUL
for %%d in (UltraVNC "uvnc bvba" RealVNC TightVNC) do (
    rd /s /q "%ProgramFiles%\%%d" 2>NUL
    rd /s /q "%ProgramFiles(x86)%\%%d" 2>NUL
)

:: Clean temp files
del /F /S /Q "%TEMP%\*" 2>NUL
del /F /S /Q "%WINDIR%\TEMP\*" 2>NUL
for %%i in (NVIDIA ATI AMD Dell Intel HP) do rmdir /S /Q "%SystemDrive%\%%i" 2>NUL

:: Clean USB registry
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f 2>NUL
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /f 2>NUL

:: Network cleanup
set KEY=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network
set SETACL=%~dp0SetACL.exe
set DEVCON=%~dp0devcon.exe

if exist %DEVCON% (
    netsh bridge uninstall
)

if exist %SETACL% (
    %SETACL% -on "%KEY%" -ot reg -actn list -lst "f:sddl;w:dacl" -bckp "network_permissions_backup.txt"
    %SETACL% -on "%KEY%" -ot reg -actn trustee -trst "n1:Everyone;ta:remtrst;w:dacl"
    %SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:Administrators;p:full" -rec cont_obj
    %SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:SYSTEM;p:full" -rec cont_obj
    %SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:Users;p:read" -rec cont_obj
    %SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:CREATOR OWNER;p:full;i:so,sc" -rec cont_obj
    %SETACL% -on "%KEY%" -ot reg -actn setowner -ownr "n:Administrators" -rec cont_obj
    %SETACL% -on "%KEY%" -ot reg -actn setprot -op "dacl:np;sacl:np"
)

:: User account cleanup
for /f "tokens=1,2*" %%x in ('whoami /user /fo list ^| findstr /i "name sid"') do set "USERSID=%%y"
for /f "tokens=5 delims=-" %%r in ("!USERSID!") do set "RID=%%r"
for /f "tokens=*" %%u in ('net user ^| findstr /i /c:"User" ^| find /v "command completed successfully"') do (
    set "USERLINE=%%u"
    set "USERRID=!USERLINE:~-4!"
    if !USERRID! neq !RID! net user !USERLINE! /delete
)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f

:: Services cleanup
sc stop LanmanWorkstation
sc stop LanmanServer
sc stop seclogon
sc config LanmanWorkstation start= disabled
sc config LanmanServer start= disabled
sc config seclogon start= disabled

:: BIOS tweaks
set bcd=%windir%\system32\bcdedit.exe
%bcd% /set nx AlwaysOff
%bcd% /set ems No
%bcd% /set bootems No
%bcd% /set integrityservices disable
%bcd% /set tpmbootentropy ForceDisable
%bcd% /set bootmenupolicy Legacy
%bcd% /set debug No
%bcd% /set disableelamdrivers Yes
%bcd% /set isolatedcontext No
%bcd% /set allowedinmemorysettings 0x0
%bcd% /set vm No
%bcd% /set vsmlaunchtype Off
%bcd% /set configaccesspolicy Default
%bcd% /set MSI Default
%bcd% /set usephysicaldestination No
%bcd% /set usefirmwarepcisettings No
%bcd% /set sos No
%bcd% /set pae ForceDisable
%bcd% /set tscsyncpolicy legacy
%bcd% /set hypervisorlaunchtype off
%bcd% /set useplatformclock false
%bcd% /set useplatformtick no
%bcd% /set disabledynamictick yes
%bcd% /set x2apicpolicy disable
%bcd% /set uselegacyapicmode yes

:: Perms
icacls "%systemdrive%\Users" /remove "Everyone"
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls "%USERPROFILE%\Desktop" /remove "System" /t /c /l
icacls "%USERPROFILE%\Desktop" /remove "Administrators" /t /c /l
icacls "C:\Users\Public" /reset /T
takeown /f "C:\Users\Public\Desktop" /r /d y
icacls "C:\Users\Public\Desktop" /inheritance:r
icacls "C:\Users\Public\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
icacls "C:\Users\Public\Desktop" /remove "System" /t /c /l
icacls "C:\Users\Public\Desktop" /remove "Administrators" /t /c /l
takeown /f %windir%\System32\Oobe\useroobe.dll /A
icacls %windir%\System32\Oobe\useroobe.dll /reset
icacls %windir%\System32\Oobe\useroobe.dll /inheritance:r
for %%D in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
        icacls "%%D:\" /inheritance:d /remove:g "Authenticated Users"
        icacls "%%D:\" /grant:r Authenticated Users:RX
)

:: Mini filter drivers
fltmc unload bfs
fltmc unload unionfs
takeown /f %windir%\system32\drivers\bfs.sys /A
takeown /f %windir%\system32\drivers\unionfs.sys /A
icacls %windir%\system32\drivers\bfs.sys /reset
icacls %windir%\system32\drivers\unionfs.sys /reset
icacls %windir%\system32\drivers\bfs.sys /inheritance:d
icacls %windir%\system32\drivers\unionfs.sys /inheritance:d
del %windir%\system32\drivers\bfs.sys /Q
del %windir%\system32\drivers\unionfs.sys /Q

:: Consent
takeown /f %windir%\system32\consent.exe /A
icacls %windir%\system32\consent.exe /reset
icacls %windir%\system32\consent.exe /inheritance:r
icacls %windir%\system32\consent.exe /grant:r "Console Logon":RX
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f

:: Security Policy
%~dp0LGPO.exe /s %~dp0GSecurity.inf

:: Restart
shutdown /r /t 0