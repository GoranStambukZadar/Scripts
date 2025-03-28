$ErrorActionPreference = 'Stop'
trap {
    Write-Host -ForegroundColor Red "CRITICAL ERROR: $_"
    Write-Host "Stack Trace: $($_.ScriptStackTrace)"
    Pause
    exit 1
}

# Define paths
$scriptDir = "F:\Gorstak\GShield\Bin"
$scriptPath = "$scriptDir\Antivirus.ps1"
$quarantineFolder = "C:\Quarantine"
$logFile = "$quarantineFolder\antivirus_log.txt"
$localDatabase = "$quarantineFolder\scanned_files.txt"
$scannedFiles = @{}

# Ensure script directory exists and copy script
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
    Write-Log "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath)) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force
    Write-Log "Copied script to: $scriptPath"
}

# Define scheduled task parameters
$taskName = "SimpleAntivirusStartup"
$taskDescription = "Runs the Simple Antivirus script at user logon with admin privileges."

# Logging Function with Rotation
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $message"
    Write-Host $logEntry
    if ((Test-Path $logFile) -and ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Rename-Item -Path $logFile -NewName $archiveName -ErrorAction SilentlyContinue
        Write-Log "Rotated log to $archiveName"
    }
    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    } catch {
        Write-Log "Failed to write to log: $($_.Exception.Message)"
    }
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

function Remove-UnsignedDLLs {
    param ([int]$maxFiles = 100)
    Write-Log "Starting unsigned DLL scan across all drives."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in (2, 3, 4) }
    if (-not $drives) {
        Write-Log "No drives detected for scanning."
        return
    }
    try {
        foreach ($drive in $drives) {
            $root = $drive.DeviceID + "\"
            Write-Log "Scanning drive: $root"
            try {
                $dllFiles = Get-ChildItem -Path $root -Filter *.dll -Recurse -File -ErrorAction SilentlyContinue
                
                if ($null -eq $dllFiles -or $dllFiles.Count -eq 0) {
                    Write-Log "No DLL files found on drive $root"
                    continue
                }
                
                $limitedDllFiles = $dllFiles | Select-Object -First $maxFiles
                
                foreach ($dll in $limitedDllFiles) {
                    try {
                        if ($dll.FullName -like "*\Windows\*") {
                            continue
                        }
                        $cert = Get-AuthenticodeSignature -FilePath $dll.FullName -ErrorAction Stop
                        if ($cert.Status -ne 'Valid') {
                            Write-Log "Found unsigned DLL: $($dll.FullName)"
                            Quarantine-File -filePath $dll.FullName
                        }
                    }
                    catch {
                        Write-Log "Error processing $($dll.FullName): $($_.Exception.Message)"
                    }
                }
            }
            catch {
                Write-Log "Drive scan error on ${root}: $($_.Exception.Message)"
                continue
            }
        }
    }
    catch {
        Write-Log "Fatal error in scan: $($_.Exception.Message)"
        throw
    }
}

function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash.ToLower()
    } catch {
        Write-Log "Error hashing ${filePath}: $($_.Exception.Message)"
        return $null
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

try {
    Write-Log "Starting antivirus scan"
    Remove-UnsignedDLLs
    Write-Log "Antivirus scan completed successfully"
 }
catch {
    Write-Log "Script crashed: $($_.Exception.Message)"
    Write-Log "Error details: $($_.ScriptStackTrace)"
}
finally {
Start-Sleep -Seconds 1
}
