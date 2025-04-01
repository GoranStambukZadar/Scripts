# Simple Antivirus by Gorstak

# Define scheduled task parameters
$taskName = "SimpleAntivirusStartup"
$taskDescription = "Runs the Simple Antivirus script at user logon with admin privileges."

# Define script path
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\Antivirus.ps1"
$quarantineFolder = "C:\Quarantine"
$logFile = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$scannedFiles = @{}

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Logging Function with Rotation
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host "Logging: $logEntry"
    if (-not (Test-Path $quarantineFolder)) {
        try {
            New-Item -Path $quarantineFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Host "Created folder: $quarantineFolder"
        } catch {
            Write-Host "Failed to create folder: $($_.Exception.Message)"
            return
        }
    }
    if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        try {
            Rename-Item -Path $logFile -NewName $archiveName -ErrorAction Stop
            $logEntry = "[$timestamp] Rotated log to $archiveName"
            Write-Host "Rotated log to: $archiveName"
        } catch {
            $logEntry += " (Log rotation failed: $($_.Exception.Message))"
        }
    }
    try {
        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8 -ErrorAction Stop
        Write-Host "Wrote to log: $logFile"
    } catch {
        Write-Host "Failed to write log: $($_.Exception.Message)"
    }
}

# Initial log
Write-Host "Script starting"
Write-Log "Script initialized. Admin: $isAdmin"

# Check if task exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $existingTask -and $isAdmin) {
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
        Register-ScheduledTask -TaskName $taskName -InputObject $task -ErrorAction Stop
        Write-Log "Scheduled task '$taskName' registered successfully"
    } catch {
        Write-Log "Failed to register scheduled task: $($_.Exception.Message)"
    }
} elseif (-not $isAdmin) {
    Write-Log "Skipping task registration: Admin privileges required"
}

# Ensure script directory exists and copy script
if (-not (Test-Path $scriptDir)) {
    try {
        New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Log "Created script directory: $scriptDir"
    } catch {
        Write-Log "Failed to create script directory: $($_.Exception.Message)"
    }
}
if (-not (Test-Path $scriptPath)) {
    try {
        Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction Stop
        Write-Log "Copied script to: $scriptPath"
    } catch {
        Write-Log "Failed to copy script: $($_.Exception.Message)"
    }
}

# Load Scanned Files Database
if (Test-Path $localDatabase) {
    try {
        $lines = Get-Content $localDatabase -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                $scannedFiles[$matches[1]] = [bool]$matches[2]
            }
        }
        Write-Log "Loaded $($scannedFiles.Count) scanned file entries from database."
    } catch {
        Write-Log "Failed to load scanned files database: $($_.Exception.Message)"
    }
} else {
    try {
        "Initial entry" | Out-File -FilePath $localDatabase -Encoding UTF8 -ErrorAction Stop
        Write-Log "Created ${localDatabase}"
    } catch {
        Write-Log "Failed to create ${localDatabase}: $($_.Exception.Message)"
    }
}

# Remove Unsigned DLLs
function Remove-UnsignedDLLs {
    Write-Log "Starting unsigned DLL scan across all drives."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    if (-not $drives) {
        Write-Log "No drives detected for scanning."
        return
    }
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        try {
            # Get all DLL files from the drive
            $dllFiles = Get-ChildItem -Path $root -Filter *.dll -Recurse -File -ErrorAction SilentlyContinue
            if ($null -eq $dllFiles -or $dllFiles.Count -eq 0) {
                Write-Log "No DLL files found on drive $root"
                continue
            }
            
            foreach ($dll in $dllFiles) {
                try {
                    if ($dll.FullName -like "*\Windows\*") {
                        continue
                    }
                    $cert = Get-AuthenticodeSignature -FilePath $dll.FullName -ErrorAction Stop
                    if ($cert.Status -ne 'Valid') {
                        Write-Log "Found unsigned DLL: $($dll.FullName)"
                        Quarantine-File -filePath $dll.FullName
                    }
                } catch {
                    Write-Log "Error processing $($dll.FullName): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log "Drive scan error on ${root}: $($_.Exception.Message)"
        }
    }
}

function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        $result = [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
        return $result
    } catch {
        Write-Log "Error processing ${filePath}: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Hash = $null
            Status = "Error"
            StatusMessage = $_.Exception.Message
        }
    }
}

function Quarantine-File {
    param ([string]$filePath)
    $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
    try {
        Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "Quarantined file: $filePath to $quarantinePath"
    } catch {
        Write-Log "Failed to quarantine ${filePath}: $($_.Exception.Message)"
    }
}

function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) }
        foreach ($process in $processes) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Write-Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
        }
    } catch {
        Write-Log "Error stopping processes for ${filePath}: $($_.Exception.Message)"
    }
}

# --- File System Watcher ---
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }

foreach ($drive in $drives) {
    $monitorPath = $drive.DeviceID

    $fileWatcher = New-Object System.IO.FileSystemWatcher
    $fileWatcher.Path = $monitorPath
    $fileWatcher.Filter = "*.dll"
    $fileWatcher.IncludeSubdirectories = $true
    $fileWatcher.EnableRaisingEvents = $true

    $action = {
        param($sender, $e)
        if ($e.ChangeType -eq [System.IO.WatcherChangeTypes]::Created -or $e.ChangeType -eq [System.IO.WatcherChangeTypes]::Changed) {
            Write-Log "Detected file change: $($e.FullPath). Running scan..."
            Remove-UnsignedDLLs
        }
    }

    Register-ObjectEvent -InputObject $fileWatcher -EventName Created -Action $action
    Register-ObjectEvent -InputObject $fileWatcher -EventName Changed -Action $action
}

# Initial log
Write-Host "File system watcher set up to monitor for DLL file changes on all drives."

# Keep the script running to listen for file system events
Write-Host "Antivirus running. Press [Ctrl] + [C] to stop."
while ($true) {
    Start-Sleep -Seconds 10
}
