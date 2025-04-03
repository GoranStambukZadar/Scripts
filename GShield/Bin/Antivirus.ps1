# Simple Antivirus by Gorstak (Hardened for Reinstalls)

# Define paths and parameters
$taskName = "SimpleAntivirusStartup"
$taskDescription = "Runs the Simple Antivirus script at user logon with admin privileges."
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\Antivirus.ps1"
$quarantineFolder = "C:\Quarantine"
$logFile = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$scannedFiles = @{}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Logging Function with Rotation
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host "Logging: $logEntry"
    if (-not (Test-Path $quarantineFolder)) {
        New-Item -Path $quarantineFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "Created folder: $quarantineFolder"
    }
    if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Rename-Item -Path $logFile -NewName $archiveName -ErrorAction Stop
        Write-Host "Rotated log to: $archiveName"
    }
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8 -ErrorAction Stop
}

# Initial log with diagnostics
Write-Log "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Write-Log "Set execution policy to Bypass for current user."
}

# Setup script directory and copy script
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Log "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction Stop
    Write-Log "Copied/Updated script to: $scriptPath"
}

# Register scheduled task (recreate if user context changed)
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $existingTask -and $isAdmin) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction Stop
    Write-Log "Scheduled task '$taskName' registered to run as SYSTEM."
} elseif (-not $isAdmin) {
    Write-Log "Skipping task registration: Admin privileges required"
}

# Load Scanned Files Database
if (Test-Path $localDatabase) {
    $lines = Get-Content $localDatabase -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        if ($line -match "^([0-9a-f]{64}),(true|false)$") {
            $scannedFiles[$matches[1]] = [bool]$matches[2]
        }
    }
    Write-Log "Loaded $($scannedFiles.Count) scanned file entries from database."
} else {
    New-Item -Path $localDatabase -ItemType File -Force -ErrorAction Stop | Out-Null
    Write-Log "Created new database: $localDatabase"
}

# Take Ownership and Modify Permissions
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        $acl = Get-Acl -Path $filePath
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $filePath -AclObject $acl -ErrorAction Stop
        Write-Log "Set ownership and permissions for $filePath"
        return $true
    } catch {
        Write-Log "Failed to set ownership/permissions for ${filePath}: $($_.Exception.Message)"
        return $false
    }
}

# Calculate File Hash and Signature
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        Write-Log "Error processing ${filePath}: $($_.Exception.Message)"
        return $null
    }
}

# Quarantine File
function Quarantine-File {
    param ([string]$filePath)
    $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
    Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
    Write-Log "Quarantined file: $filePath to $quarantinePath"
}

# Stop Processes Using DLL
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
    foreach ($process in $processes) {
        Stop-Process -Id $process.Id -Force -ErrorAction Stop
        Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
    }
}

# Remove Unsigned DLLs
function Remove-UnsignedDLLs {
    Write-Log "Starting unsigned DLL scan."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        $dllFiles = Get-ChildItem -Path $root -Filter *.dll -Recurse -File -ErrorAction SilentlyContinue
        foreach ($dll in $dllFiles) {
            $fileHash = Calculate-FileHash -filePath $dll.FullName
            if ($fileHash) {
                if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                    Write-Log "Skipping already scanned file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                    if (-not $scannedFiles[$fileHash.Hash]) {
                        if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                            Stop-ProcessUsingDLL -filePath $dll.FullName
                            Quarantine-File -filePath $dll.FullName
                        }
                    }
                } else {
                    $isValid = $fileHash.Status -eq 'Valid'
                    $scannedFiles[$fileHash.Hash] = $isValid
                    "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8
                    Write-Log "Scanned new file: $($dll.FullName) (Valid: $isValid)"
                    if (-not $isValid) {
                        if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                            Stop-ProcessUsingDLL -filePath $dll.FullName
                            Quarantine-File -filePath $dll.FullName
                        }
                    }
                }
            }
        }
    }
}

# File System Watcher
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
foreach ($drive in $drives) {
    $monitorPath = $drive.DeviceID + "\"
    $fileWatcher = New-Object System.IO.FileSystemWatcher
    $fileWatcher.Path = $monitorPath
    $fileWatcher.Filter = "*.dll"
    $fileWatcher.IncludeSubdirectories = $true
    $fileWatcher.EnableRaisingEvents = $true

    $action = {
        param($sender, $e)
        if ($e.ChangeType -in "Created", "Changed") {
            Write-Log "Detected file change: $($e.FullPath)"
            $fileHash = Calculate-FileHash -filePath $e.FullPath
            if ($fileHash) {
                if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                    Write-Log "Skipping already scanned file: $($e.FullPath) (Hash: $($fileHash.Hash))"
                    if (-not $scannedFiles[$fileHash.Hash]) {
                        if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                            Stop-ProcessUsingDLL -filePath $e.FullPath
                            Quarantine-File -filePath $e.FullPath
                        }
                    }
                } else {
                    $isValid = $fileHash.Status -eq 'Valid'
                    $scannedFiles[$fileHash.Hash] = $isValid
                    "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                    Write-Log "Added new file to database: $($e.FullPath) (Valid: $isValid)"
                    if (-not $isValid) {
                        if (Set-FileOwnershipAndPermissions -filePath $e.FullPath) {
                            Stop-ProcessUsingDLL -filePath $e.FullPath
                            Quarantine-File -filePath $e.FullPath
                        }
                    }
                }
            }
        }
    }

    Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action
    Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action
}

# Initial scan
Remove-UnsignedDLLs
Write-Log "Initial scan completed. Monitoring started."

# Keep script running
Write-Host "Antivirus running. Press [Ctrl] + [C] to stop."
while ($true) { Start-Sleep -Seconds 10 }