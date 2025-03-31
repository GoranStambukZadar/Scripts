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

# Check if task exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if (-not $existingTask) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription

    # Register the task
    Register-ScheduledTask -TaskName $taskName -InputObject $task
}

# Logging Function with Rotation
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Output $logEntry
    if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Rename-Item -Path $logFile -NewName $archiveName -ErrorAction SilentlyContinue
        Write-Output "Rotated log to $archiveName"
    }
    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    } catch {
        Write-Output "Failed to write to log: $($_.Exception.Message)"
    }
}

# Ensure script directory exists and copy script
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
    Write-Log "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath)) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force
    Write-Log "Copied script to: $scriptPath"
}

# Create Quarantine Folder and Log
if (-not (Test-Path -Path $quarantineFolder)) {
    New-Item -Path $quarantineFolder -ItemType Directory -Force | Out-Null
    Write-Log "Created quarantine folder: $quarantineFolder"
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
}

# Remove Unsigned DLLs
function Remove-UnsignedDLLs {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DriveType -in @('Fixed', 'Removable', 'Network') }
    foreach ($drive in $drives) {
        $dllFiles = Get-ChildItem -Path $drive.Root -Recurse -Filter *.dll -ErrorAction SilentlyContinue
        foreach ($dll in $dllFiles) {
            $signatureCheck = Calculate-FileHash -FilePath $dll.FullName
            if ($signatureCheck.Status -ne "Valid") {
                Stop-ProcessUsingDLL -filePath $dll.FullName
                Quarantine-File -filePath $dll.FullName
            }
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

Start-Job -ScriptBlock {
    while ($true) {
        try {
            Write-Log "Starting antivirus scan"
            Remove-UnsignedDLLs
            Write-Log "Antivirus scan completed successfully"
        } catch {
            Write-Log "Error during execution: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 1
    }
}
