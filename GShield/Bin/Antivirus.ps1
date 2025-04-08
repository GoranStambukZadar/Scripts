# Simple Antivirus by Gorstak
# Define paths and necessary folders
$quarantineFolder = "C:\Quarantine"
$logFile = "C:\antivirus_log.txt"
$localDatabase = "C:\local_database.txt"
$scannedFiles = @{}
# Log function
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host "Logging: $logEntry"
    if (-not (Test-Path $quarantineFolder)) {
        New-Item -Path $quarantineFolder -ItemType Directory -Force | Out-Null
        Write-Host "Created folder: $quarantineFolder"
    }
    if ((Test-Path $logFile) -and ((Get-Item $logFile).Length -ge 10MB)) {
        $archiveName = "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
        Write-Host "Rotating log to: $archiveName"
        Compress-Archive -Path $logFile -DestinationPath $archiveName
        Clear-Content -Path $logFile -Force
    }
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
}
# Function to take ownership and set file permissions
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        icacls $filePath /inheritance:d | Out-Null
        icacls $filePath /grant "Administrators:F" | Out-Null
        Write-Log ("Forcibly set ownership and permissions for " + $filePath)
        return $true
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log ("Failed to set ownership/permissions for " + $filePath + ": " + $errorMessage)
        return $false
    }
}
# Function to calculate file hash and check signature
function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        Write-Log ("Signature status for " + $filePath + ": " + $signature.Status + " - " + $signature.StatusMessage)
        
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log ("Error processing " + $filePath + ": " + $errorMessage)
        return $null
    }
}
# Function to stop processes using DLL
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-WmiObject Win32_Process | Where-Object { $_.ExecutablePath -eq $filePath }
        foreach ($process in $processes) {
            Write-Log ("Killing process " + $process.Name + " using " + $filePath)
            Stop-Process -Id $process.ProcessId -Force
        }
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log ("Error stopping processes using " + $filePath + ": " + $errorMessage)
    }
}
# Function to quarantine files
function Quarantine-File {
    param ([string]$filePath)
    try {
        $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
        Move-Item -Path $filePath -Destination $quarantinePath -Force
        Write-Log ("Moved file " + $filePath + " to quarantine")
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log ("Failed to quarantine " + $filePath + ": " + $errorMessage)
    }
}
# Helper function to log messages
function Write-Log {
    param (
        [string]$logMessage
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "$timestamp - $logMessage"
}
# Helper function to log messages
function Write-Log {
    param (
        [string]$logMessage
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "$timestamp - $logMessage"
}
# Function to remove unsigned DLLs
function Remove-UnsignedDLLs {
    Write-Log "Starting unsigned DLL scan."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    foreach ($drive in $drives) {
        $root = $drive.DeviceID + "\"
        Write-Log "Scanning drive: $root"
        try {
            $dllFiles = Get-ChildItem -Path $root -Filter *.dll -Recurse -File -Exclude @($quarantineFolder, "C:\Windows\System32\config") -ErrorAction Stop
            foreach ($dll in $dllFiles) {
                try {
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
                            $isValid = $fileHash.Status -eq "Valid"
                            $scannedFiles[$fileHash.Hash] = $isValid
                            "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                            Write-Log "Scanned new file: $($dll.FullName) (Valid: $isValid)"
                            if (-not $isValid) {
                                if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                    Stop-ProcessUsingDLL -filePath $dll.FullName
                                    Quarantine-File -filePath $dll.FullName
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "Error processing file $($dll.FullName): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log "Scan failed for drive ${root} $($_.Exception.Message)"
        }
    }
    # Explicit System32 Scan and System-critical handling
    Write-Log "Starting explicit System32 scan."
    try {
        $system32Files = Get-ChildItem -Path "C:\Windows\System32" -Filter *.dll -File -ErrorAction Stop
        foreach ($dll in $system32Files) {
            try {
                $fileHash = Calculate-FileHash -filePath $dll.FullName
                if ($fileHash) {
                    if ($scannedFiles.ContainsKey($fileHash.Hash)) {
                        Write-Log "Skipping already scanned System32 file: $($dll.FullName) (Hash: $($fileHash.Hash))"
                        if (-not $scannedFiles[$fileHash.Hash]) {
                            if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                Stop-ProcessUsingDLL -filePath $dll.FullName
                                Quarantine-File -filePath $dll.FullName
                            }
                        }
                    } else {
                        $isValid = $fileHash.Status -eq "Valid"
                        $scannedFiles[$fileHash.Hash] = $isValid
                        "$($fileHash.Hash),$isValid" | Out-File -FilePath $localDatabase -Append -Encoding UTF8 -ErrorAction Stop
                        Write-Log "Scanned new System32 file: $($dll.FullName) (Valid: $isValid)"
                        if (-not $isValid) {
                            # Aggressive killing of system files
                            if (Set-FileOwnershipAndPermissions -filePath $dll.FullName) {
                                Stop-ProcessUsingDLL -filePath $dll.FullName
                                Quarantine-File -filePath $dll.FullName
                            }
                        }
                    }
                }
            } catch {
                Write-Log "Error processing System32 file $($dll.FullName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Log "System32 scan failed: $($_.Exception.Message)"
    }
}
# File System Watcher (Monitor for DLL changes)
$lastEventTime = 0
$minInterval = 500  # Minimum interval between events in milliseconds
$action = {
    param($sender, $e)
    try {
        $currentTime = Get-Date
        $timeSinceLastEvent = ($currentTime - $lastEventTime).TotalMilliseconds
        if ($timeSinceLastEvent -ge $minInterval) {
            $lastEventTime = $currentTime
            if ($e.ChangeType -in "Created", "Changed" -and $e.FullPath -notlike "$quarantineFolder*") {
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
                        $isValid = $fileHash.Status -eq "Valid"
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
    } catch {
        Write-Log "Watcher error for $($e.FullPath): $($_.Exception.Message)"
    }
}
# Register file watcher for the DLL directories
$folderWatcher = New-Object System.IO.FileSystemWatcher
$folderWatcher.Path = "C:\"
$folderWatcher.Filter = "*.dll"
$folderWatcher.IncludeSubdirectories = $true
$folderWatcher.EnableRaisingEvents = $true
Register-ObjectEvent -InputObject $folderWatcher -EventName "Changed" -Action $action
# Run the initial scan
Remove-UnsignedDLLs
