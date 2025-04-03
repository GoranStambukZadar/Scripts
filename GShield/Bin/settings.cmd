@echo off

:: Remove default user
net user defaultuser0 /delete
net user defaultuser1 /delete
net user defaultuser100000 /delete


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
