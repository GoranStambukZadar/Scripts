function Harden-PrivilegeRights {
    # Ensure script is run as Administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as an Administrator."
        return
    }

    # Privilege rights settings
    $privilegeSettings = @'
[Privilege Rights]
SeChangeNotifyPrivilege = *S-1-1-0
SeInteractiveLogonRight = *S-1-2-1
SeDenyNetworkLogonRight = *S-1-5-21,*S-1-5-32-545,*S-1-5-32-584,*S-1-5-65-1,*S-1-5-13,*S-1-5-32-581,*S-1-5-18,*S-1-18-2,*S-1-5-6,*S-1-5-32-552,*S-1-5-32-580,*S-1-5-14,*S-1-5-32-555,*S-1-5-32-547,*S-1-5-32-558,*S-1-5-32-559,*S-1-3-4,*S-1-5-32-585,*S-1-5-20,*S-1-5-32-556,*S-1-5-2,*S-1-5-19,*S-1-5-114,*S-1-5-113,*S-1-5-17,*S-1-5-4,*S-1-5-32-568,*S-1-5-32-578,*S-1-5-32-546,Guest,*S-1-1-0,*S-1-5-32-573,*S-1-5-32-562,*S-1-5-1,*S-1-5-32-583,*S-1-5-32-569,*S-1-3-0,*S-1-3-1,*S-1-2-1,*S-1-5-3,*S-1-5-32-551,*S-1-18-1,*S-1-5-11,*S-1-5-7,*S-1-15-2-1,*S-1-15-2-2,*S-1-5-32-544,*S-1-5-32-579,*S-1-15-3
SeDenyInteractiveLogonRight = Guest
SeDenyRemoteInteractiveLogonRight = *S-1-5-21,*S-1-5-32-545,*S-1-5-32-584,*S-1-5-65-1,*S-1-5-13,*S-1-5-32-581,*S-1-5-18,*S-1-18-2,*S-1-5-6,*S-1-5-32-552,*S-1-5-32-580,*S-1-5-14,*S-1-5-32-555,*S-1-5-32-547,*S-1-5-32-558,*S-1-5-32-559,*S-1-3-4,*S-1-5-32-585,*S-1-5-20,*S-1-5-32-556,*S-1-5-2,*S-1-5-19,*S-1-5-114,*S-1-5-113,*S-1-5-17,*S-1-5-4,*S-1-5-32-568,*S-1-5-32-578,*S-1-5-32-546,Guest,*S-1-1-0,*S-1-5-32-573,*S-1-5-32-562,*S-1-5-1,*S-1-5-32-583,*S-1-5-32-569,*S-1-3-0,*S-1-3-1,*S-1-2-1,*S-1-5-3,*S-1-5-32-551,*S-1-18-1,*S-1-5-11,*S-1-5-7,*S-1-15-2-1,*S-1-15-2-2,*S-1-5-32-544,*S-1-5-32-579,*S-1-15-3
SeDenyServiceLogonRight = *S-1-5-32-545
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeAssignPrimaryTokenPrivilege=
SeBackupPrivilege=
SeCreateTokenPrivilege=
SeDebugPrivilege=
SeImpersonatePrivilege=
SeLoadDriverPrivilege=
SeRemoteInteractiveLogonRight=
SeServiceLogonRight=
'@

    # Secure temp file path
    $cfgPath = [System.IO.Path]::GetTempFileName()

    try {
        # Export current security policy
        secedit /export /cfg $cfgPath /quiet

        # Write new settings
        Set-Content -Path $cfgPath -Value $privilegeSettings -ErrorAction Stop

        # Apply new security policy
        secedit /configure /db c:\windows\security\local.sdb /cfg $cfgPath /areas USER_RIGHTS /quiet

        Write-Output "Privilege rights hardened successfully."
    }
    catch {
        Write-Error "Error hardening privilege rights: $_"
    }
    finally {
        # Clean up temp file
        if (Test-Path $cfgPath) {
            Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Execute function
Harden-PrivilegeRights

