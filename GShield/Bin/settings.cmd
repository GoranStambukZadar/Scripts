@echo off

:: Perms
:: Create temporary files
set "TEMP_FILE=%TEMP%\sid_list.txt"
set "ITEMS_FILE=%TEMP%\items_list.txt"
if exist "%TEMP_FILE%" del "%TEMP_FILE%"
if exist "%ITEMS_FILE%" del "%ITEMS_FILE%"

:: Loop through drives A to Z to find items with SIDs
for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        echo Scanning drive %%d:\ for SIDs...
        :: Get all permissions with full paths and filter for S-1-5-21
        dir "%%d:\" /s /b 2>nul | for /f "tokens=*" %%f in ('more') do (
            icacls "%%f" /C /Q 2>nul | findstr "S-1-5-21" >nul && echo %%f>>"%ITEMS_FILE%"
            icacls "%%f" /C /Q 2>nul | findstr "S-1-5-21" >>"%TEMP_FILE%"
        )
    )
)

:: Process unique SIDs from the temp file
echo Processing identified SIDs...
if exist "%TEMP_FILE%" if exist "%ITEMS_FILE%" (
    for /f "tokens=1 delims=:" %%s in ('type "%TEMP_FILE%" ^| findstr /r "S-1-5-21-[0-9-]*" ^| sort /unique') do (
        set "SID=%%s"
        echo Processing SID: !SID!
        
        :: Process each item containing this SID
        for /f "tokens=*" %%i in ('type "%ITEMS_FILE%"') do (
            echo Taking ownership of "%%i"...
            takeown /F "%%i" /A /D Y 2>nul
            
            echo Removing inheritance from "%%i"...
            icacls "%%i" /inheritance:d /C /Q 2>nul
            
            echo Removing SID !SID! from "%%i"...
            icacls "%%i" /remove "!SID!" /C /Q 2>nul
        )
    )
    del "%TEMP_FILE%"
    del "%ITEMS_FILE%"
) else (
    echo No SIDs matching S-1-5-21 found.
)

echo Done.

for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        takeown /f %%d:\
        icacls %%d:\ /setowner "Administrators"
        icacls %%d:\ /grant:r "Console Logon":M /T /C
        icacls %%e:\ /grant:r "Users":RX /T /C
        icacls %%e:\ /grant:r "System":F /T /C
        icacls %%e:\ /grant:r "Administrators":F /T /C
        icacls %%e:\ /grant:r "Authenticated Users":M /T /C
        icacls %%d:\ /remove "Everyone"
        icacls %%d:\ /remove "Authenticated Users"
        icacls %%d:\ /remove "Users"
    )
)

takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:d /T /C
icacls "%SystemDrive%\Users\Public\Desktop" /remove "INTERACTIVE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "SERVICE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "BATCH"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "CREATOR OWNER"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "System"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Administrators"
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:d /T /C
icacls "%USERPROFILE%\Desktop" /remove "System"
icacls "%USERPROFILE%\Desktop" /remove "Administrators"

:: Reset group policy
rd /S /Q "%WinDir%\System32\GroupPolicyUsers"
rd /S /Q "%WinDir%\System32\GroupPolicy"
rd /S /Q "%WinDir%\SysWOW64\GroupPolicyUsers"
rd /S /Q "%WinDir%\SysWOW64\GroupPolicy"

:: Wmic
DISM /Online /Add-Capability /CapabilityName:WMIC~~~~

:: Autopilot
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Uninstall-ProvisioningPackage -AllInstalledPackages"
rd /s /q %ProgramData%\Microsoft\Provisioning
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverInstall\Restrictions" /v "AllowUserDeviceClasses" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "2" /f

:: Biometrics, Homegroup, and License
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v "DisableHomeGroup" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f

:: Riddance
for /f "tokens=1,2*" %%x in ('whoami /user /fo list ^| findstr /i "name sid"') do (
    set "USERNAME=%%z"
    set "USERSID=%%y"
)

for /f "tokens=5 delims=-" %%r in ("!USERSID!") do set "RID=%%r"

for /f "tokens=*" %%u in ('net user ^| findstr /i /c:"User" ^| find /v "command completed successfully"') do (
    set "USERLINE=%%u"
    set "USERRID=!USERLINE:~-4!"
    if !USERRID! neq !RID! (
        echo Removing user: !USERLINE!
        net user "!USERLINE!" /delete
    )
)

:: threats
reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_SZ /d "1" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /t REG_SZ /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d "1" /f

:: Remove default user
net user defaultuser0 /delete
net user defaultuser1 /delete
net user defaultuser100000 /delete

:: Loop through all network adapters and apply the DisablePXE setting
for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)

for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)

:: Remove symbolic links
for %%D in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist "%%D:\" (
        for /f "delims=" %%F in ('dir /aL /s /b "%%D:\" 2^>nul') do (
            echo Deleting symbolic link: %%F
            rmdir "%%F" 2>nul || del "%%F" 2>nul
        )
    )
)

:: disable netbios
sc config lmhosts start= disabled
@powershell.exe -ExecutionPolicy Bypass -Command "Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object { $_.SetTcpipNetbios(2) }"
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableNetbios" /t REG_DWORD /d "0" /f

:: takeown of group policy client service
SetACL.exe -on "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" -ot reg -actn setowner -ownr n:Administrators
SetACL.exe -on "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" -ot reg -actn ace -ace "n:Administrators;p:full"
sc stop gpsvc

:: Services stop and disable
sc stop SSDPSRV
sc stop upnphost
sc stop NetBT
sc stop BTHMODEM
sc stop gpsvc
sc stop LanmanWorkstation
sc stop LanmanServer
sc stop seclogon
sc stop Messenger

sc config SSDPSRV start= disabled
sc config upnphost start= disabled
sc config NetBT start= disabled
sc config BTHMODEM start= disabled
sc config gpsvc start= disabled
sc config LanmanWorkstation start= disabled
sc config LanmanServer start= disabled
sc config seclogon start= disabled
sc config Messenger start= disabled
