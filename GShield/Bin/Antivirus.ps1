# Simple Antivirus by Gorstak

# Define paths and parameters
$taskName = "SimpleAntivirusStartup"
$taskDescription = "Runs the Simple Antivirus script at user logon with admin privileges."
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\Antivirus.ps1"
$quarantineFolder = "C:\Quarantine"

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
Write-Output "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Write-Output "Set execution policy to Bypass for current user."
}

# Setup script directory and copy script
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Output "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction Stop
    Write-Output "Copied/Updated script to: $scriptPath"
}

# Register scheduled task as SYSTEM
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $existingTask -and $isAdmin) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction Stop
    Write-Output "Scheduled task '$taskName' registered to run as SYSTEM."
} elseif (-not $isAdmin) {
    Write-Output "Skipping task registration: Admin privileges required"
}

# Ensure quarantine folder exists
try {
    if (!(Test-Path $quarantineFolder)) {
        New-Item -ItemType Directory -Path $quarantineFolder -Force | Out-Null
        Write-Output "Created quarantine folder at $quarantineFolder"
    }
} catch {
    Write-Output "Failed to create quarantine folder: $($_.Exception.Message)"
}

function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object {
            try {
                $_.Modules | Where-Object { $_.FileName -eq $filePath }
            } catch {}
        }

        foreach ($process in $processes) {
            try {
                taskkill /F /PID $($process.Id) | Out-Null
                Write-Output "Killed process $($process.Name) (PID: $($process.Id))"
            } catch {
                Write-Output "Failed to kill process $($process.Id): $($_.Exception.Message)"
            }

            try {
                $parentId = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($process.Id)").ParentProcessId
                if ($parentId -and $parentId -ne 0 -and $parentId -ne $process.Id) {
                    $parentProc = Get-Process -Id $parentId -ErrorAction SilentlyContinue
                    if ($parentProc) {
                        taskkill /F /PID $parentId | Out-Null
                        Write-Output "Killed parent process $($parentProc.Name) (PID: $parentId)"
                    }
                }
            } catch {
                Write-Output "Failed to get or kill parent process for $($process.Id): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Output "Failed to stop process using ${filePath}: $($_.Exception.Message)"
    }
}

function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        icacls $filePath /inheritance:d | Out-Null
        icacls $filePath /grant "Administrators:F" | Out-Null
        Write-Output "Forcibly set ownership and permissions for ${filePath}"
        return $true
    } catch {
        Write-Output "Failed to set ownership/permissions for ${filePath}: $($_.Exception.Message)"
        return $false
    }
}

function Is-SignedFileValid {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        Write-Output "Signature status: $($signature.Status) for ${filePath}"
        return ($signature.Status -eq "Valid")
    } catch {
        Write-Output "Signature check failed for ${filePath}: $($_.Exception.Message)"
        return $false
    }
}

function Quarantine-File {
    param ([string]$filePath)
    $maxRetries = 3
    $retryCount = 0
    $success = $false
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
            Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
            Write-Output "Quarantined file: ${filePath} to $quarantinePath"
            $success = $true
        } catch {
            Write-Output "Retry $($retryCount + 1)/$maxRetries - Failed to quarantine ${filePath}: $($_.Exception.Message)"
            Start-Sleep -Seconds 1
            $retryCount++
        }
    }
    if (-not $success) {
        Write-Output "Quarantine of ${filePath} failed after $maxRetries retries"
    }
}

function Remove-UnsignedDLLs {
    param ([string]$changedPath)

    try {
        if (Test-Path $changedPath -PathType Leaf -and $changedPath -like "*.dll") {
            Write-Output "Detected DLL: $changedPath"
            $isValid = Is-SignedFileValid -filePath $changedPath
            if (-not $isValid) {
                if (Set-FileOwnershipAndPermissions -filePath $changedPath) {
                    Stop-ProcessUsingDLL -filePath $changedPath
                    Quarantine-File -filePath $changedPath
                }
            }
        }
    } catch {
        Write-Output "Error during file handling for ${changedPath}: $($_.Exception.Message)"
    }
}

# Start watchers on all drives
try {
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in 2, 3, 4 }

    foreach ($drive in $drives) {
        try {
            $path = $drive.DeviceID + "\"
            Write-Output "Setting watcher on drive: $path"

            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $path
            $watcher.IncludeSubdirectories = $true
            $watcher.Filter = "*.dll"
            $watcher.EnableRaisingEvents = $true

            Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action {
                try {
                    Start-Sleep -Milliseconds 500
                    $event = $Event.SourceEventArgs
                    $fullPath = $event.FullPath
                    Remove-UnsignedDLLs -changedPath $fullPath
                } catch {
                    Write-Output "Watcher error (Created): $($_.Exception.Message)"
                }
            }

            Register-ObjectEvent -InputObject $watcher -EventName "Changed" -Action {
                try {
                    Start-Sleep -Milliseconds 500
                    $event = $Event.SourceEventArgs
                    $fullPath = $event.FullPath
                    Remove-UnsignedDLLs -changedPath $fullPath
                } catch {
                    Write-Output "Watcher error (Changed): $($_.Exception.Message)"
                }
            }

        } catch {
            Write-Output "Failed to start watcher on ${path}: $($_.Exception.Message)"
        }
    }
} catch {
    Write-Output "Error setting up watchers: $($_.Exception.Message)"
}

Write-Output "DLL watchers running. Press Ctrl+C to exit."
while ($true) {
    Start-Sleep -Seconds 30
}
