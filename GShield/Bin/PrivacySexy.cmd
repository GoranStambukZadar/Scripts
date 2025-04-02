@echo off
:: https://privacy.sexy — v0.13.8 — Wed, 02 Apr 2025 04:30:38 GMT
:: Ensure PowerShell is available
where PowerShell >nul 2>&1 || (
    echo PowerShell is not available. Please install or enable PowerShell.
    pause & exit 1
)
:: Ensure admin privileges
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: ----------------------------------------------------------
:: -----Clear credentials in Windows Credential Manager------
:: ----------------------------------------------------------
echo --- Clear credentials in Windows Credential Manager
PowerShell -ExecutionPolicy Unrestricted -Command "$cmdkeyPath = Get-Command cmdkey -ErrorAction SilentlyContinue; if (-not $cmdkeyPath) { throw 'Failed to find the `cmdkey` utility on this system.'; }; $cmdkeyListOutput = & $cmdkeyPath /list; if ($LASTEXITCODE -ne 0) { throw "^""Failed to execute `cmdkey /list`. Exit code: $LASTEXITCODE."^""; }; if (-not $cmdkeyListOutput) { throw 'Failed to retrieve credentials list. The output from `cmdkey /list` is empty.'; }; $credentialEntries = @($cmdkeyListOutput | Select-String 'Target'); if (-not $credentialEntries) { Write-Host 'Skipping: No credentials found for deletion.'; exit 0; }; $allCredentialsDeletedSuccessfully = $true; Write-Host "^""Total of $($credentialEntries.Length) credential(s) found. Initiating deletion..."^""; foreach ($credentialEntry in $credentialEntries) { if ($credentialEntry -notmatch 'Target:(.+)') { Write-Error "^""Failed to parse credential from output: $credentialEntry"^""; $allCredentialsDeletedSuccessfully = $false; continue; }; $credentialTargetName = $matches[1].Trim(); Write-Host "^""Deleting credential: `"^""$credentialTargetName`"^""..."^""; & $cmdkeyPath /delete:$credentialTargetName; if ($LASTEXITCODE -ne 0) { Write-Error "^""Failed to delete credential '$credentialTargetName'. `cmdkey` returned exit code: $LASTEXITCODE."^""; $allCredentialsDeletedSuccessfully = $false; } else { Write-Host "^""Successfully deleted credential: `"^""$credentialTargetName`"^""."^""; }; }; if (-not $allCredentialsDeletedSuccessfully) { Write-Warning 'Failed to delete some credentials. Please check the error messages above.'; } else { Write-Host "^""Successfully deleted all $($credentialEntries.Length) credential(s)."^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Remove the controversial `default0` user---------
:: ----------------------------------------------------------
echo --- Remove the controversial `default0` user
net user defaultuser0 /delete 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Minimize DISM "Reset Base" update data----------
:: ----------------------------------------------------------
echo --- Minimize DISM "Reset Base" update data
:: Set the registry value: "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration!DisableResetbase"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration'; $data =  '0'; reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration' /v 'DisableResetbase' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Remove Windows product key from registry---------
:: ----------------------------------------------------------
echo --- Remove Windows product key from registry
cscript.exe //nologo "%SYSTEMROOT%\System32\slmgr.vbs" /cpky
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Clear volume backups (shadow copies)-----------
:: ----------------------------------------------------------
echo --- Clear volume backups (shadow copies)
vssadmin delete shadows /all /quiet
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Clear System Resource Usage Monitor (SRUM) data------
:: ----------------------------------------------------------
echo --- Clear System Resource Usage Monitor (SRUM) data
:: Stop service: DPS (with state file) (wait until stopped)
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'DPS'; Write-Host "^""Stopping service: `"^""$serviceName`"^""."^""; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if (!$service) { Write-Host "^""Skipping, service `"^""$serviceName`"^"" could not be not found, no need to stop it."^""; exit 0; }; if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""Skipping, `"^""$serviceName`"^"" is not running, no need to stop."^""; exit 0; }; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { $service | Stop-Service -Force -ErrorAction Stop; $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped); } catch { throw "^""Failed to stop the service `"^""$serviceName`"^"": $_"^""; }; Write-Host "^""Successfully stopped the service: `"^""$serviceName`"^""."^""; function Get-StateFilePath($BaseName, $Suffix) { $escapedBaseName = $BaseName.Split([IO.Path]::GetInvalidFileNameChars()) -Join '_'; $uniqueFilename = $escapedBaseName, $Suffix -Join '-'; $path = [IO.Path]::Combine( $env:APPDATA, 'privacy.sexy', 'state', $uniqueFilename ); return $path; }; function Get-UniqueStateFilePath($BaseName) { $suffix = New-Guid; $path = Get-StateFilePath -BaseName $BaseName -Suffix $suffix; if (Test-Path -Path $path) { Write-Verbose "^""Path collision detected at: '$path'. Generating new path..."^""; return Get-UniqueStateFilePath $serviceName; }; return $path; }; function New-EmptyFile($Path) { $parentDirectory = [System.IO.Path]::GetDirectoryName($Path); if (-not (Test-Path $parentDirectory -PathType Container)) { try { New-Item -ItemType Directory -Path $parentDirectory -Force -ErrorAction Stop | Out-Null; }  catch { Write-Warning "^""Failed to create parent directory of file `"^""$parentDirectory`"^"": $_"^""; }; }; try { New-Item -ItemType File -Path $Path -Force -ErrorAction Stop | Out-Null; return $true; } catch { Write-Warning "^""Failed to create file `"^""$Path`"^"": $_"^""; return $false; }; }; $path = Get-UniqueStateFilePath $serviceName; if (New-EmptyFile $path) { Write-Host 'Service will restart automatically.'; } else { Write-Warning 'Manual restart required - please restart your computer.'; }"
:: Delete files matching pattern: "%SYSTEMROOT%\System32\sru\SRUDB.dat"
PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%SYSTEMROOT%\System32\sru\SRUDB.dat"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; <# Not using `Get-Acl`/`Set-Acl` to avoid adjusting token privileges #>; $parentDirectory = [System.IO.Path]::GetDirectoryName($expandedPath); $fileName = [System.IO.Path]::GetFileName($expandedPath); if ($parentDirectory -like '*[*?]*') { throw "^""Unable to grant permissions to glob path parent directory: `"^""$parentDirectory`"^"", wildcards in parent directory are not supported by ``takeown`` and ``icacls``."^""; }; if (($fileName -ne '*') -and ($fileName -like '*[*?]*')) { throw "^""Unable to grant permissions to glob path file name: `"^""$fileName`"^"", wildcards in file name is not supported by ``takeown`` and ``icacls``."^""; }; Write-Host "^""Taking ownership of `"^""$expandedPath`"^""."^""; $cmdPath = $expandedPath; if ($cmdPath.EndsWith('\')) { $cmdPath += '\' <# Escape trailing backslash for correct handling in batch commands #>; }; $takeOwnershipCommand = "^""takeown /f `"^""$cmdPath`"^"" /a"^"" <# `icacls /setowner` does not succeed, so use `takeown` instead. #>; if (-not (Test-Path -Path "^""$expandedPath"^"" -PathType Leaf)) { $localizedYes = 'Y' <# Default 'Yes' flag (fallback) #>; try { $choiceOutput = cmd /c "^""choice <nul 2>nul"^""; if ($choiceOutput -and $choiceOutput.Length -ge 2) { $localizedYes = $choiceOutput[1]; } else { Write-Warning "^""Failed to determine localized 'Yes' character. Output: `"^""$choiceOutput`"^"""^""; }; } catch { Write-Warning "^""Failed to determine localized 'Yes' character. Error: $_"^""; }; $takeOwnershipCommand += "^"" /r /d $localizedYes"^""; }; $takeOwnershipOutput = cmd /c "^""$takeOwnershipCommand 2>&1"^"" <# `stderr` message is misleading, e.g. "^""ERROR: The system cannot find the file specified."^"" is not an error. #>; if ($LASTEXITCODE -eq 0) { Write-Host "^""Successfully took ownership of `"^""$expandedPath`"^"" (using ``$takeOwnershipCommand``)."^""; } else { Write-Host "^""Did not take ownership of `"^""$expandedPath`"^"" using ``$takeOwnershipCommand``, status code: $LASTEXITCODE, message: $takeOwnershipOutput."^""; <# Do not write as error or warning, because this can be due to missing path, it's handled in next command. #>; <# `takeown` exits with status code `1`, making it hard to handle missing path here. #>; }; Write-Host "^""Granting permissions for `"^""$expandedPath`"^""."^""; $adminSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'; $adminAccount = $adminSid.Translate([System.Security.Principal.NTAccount]); $adminAccountName = $adminAccount.Value; $grantPermissionsCommand = "^""icacls `"^""$cmdPath`"^"" /grant `"^""$($adminAccountName):F`"^"" /t"^""; $icaclsOutput = cmd /c "^""$grantPermissionsCommand"^""; if ($LASTEXITCODE -eq 3) { Write-Host "^""Skipping, no items available for deletion according to: ``$grantPermissionsCommand``."^""; exit 0; } elseif ($LASTEXITCODE -ne 0) { Write-Host "^""Take ownership message:`n$takeOwnershipOutput"^""; Write-Host "^""Grant permissions:`n$icaclsOutput"^""; Write-Warning "^""Failed to assign permissions for `"^""$expandedPath`"^"" using ``$grantPermissionsCommand``, status code: $LASTEXITCODE."^""; } else { $fileStats = $icaclsOutput | ForEach-Object { $_ -match '\d+' | Out-Null; $matches[0] } | Where-Object { $_ -ne $null } | ForEach-Object { [int]$_ }; if ($fileStats.Count -gt 0 -and ($fileStats | ForEach-Object { $_ -eq 0 } | Where-Object { $_ -eq $false }).Count -eq 0) { Write-Host "^""Skipping, no items available for deletion according to: ``$grantPermissionsCommand``."^""; exit 0; } else { Write-Host "^""Successfully granted permissions for `"^""$expandedPath`"^"" (using ``$grantPermissionsCommand``)."^""; }; }; $deletedCount = 0; $failedCount = 0; $skippedCount = 0; $foundAbsolutePaths = @(); try { $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) { Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) { if (Test-Path -Path $path -PathType Container) { Write-Host "^""Skipping, the path is not a file but a folder: $($path)."^""; $skippedCount++; continue; }; if (-not (Test-Path $path)) { <# Re-check existence as prior deletions might remove subsequent items (e.g., subdirectories). #>; Write-Host "^""Successfully deleted: $($path) (already deleted)."^""; $deletedCount++; continue; }; try { Remove-Item -Path $path -Force -Recurse -ErrorAction Stop; $deletedCount++; Write-Host "^""Successfully deleted: $($path)"^""; } catch { $failedCount++; Write-Warning "^""Unable to delete $($path): $_"^""; }; }; if ($skippedCount -gt 0) { Write-Host "^""Skipped $($skippedCount) items."^""; }; Write-Host "^""Successfully deleted $($deletedCount) items."^""; if ($failedCount -gt 0) { Write-Warning "^""Failed to delete $($failedCount) items."^""; }"
:: Start service: DPS (if state requires)
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'DPS'; function Get-StateFilePath($BaseName, $Suffix) { $escapedBaseName = $BaseName.Split([IO.Path]::GetInvalidFileNameChars()) -Join '_'; $uniqueFilename = $escapedBaseName, $Suffix -Join '-'; $path = [IO.Path]::Combine( $env:APPDATA, 'privacy.sexy', 'state', $uniqueFilename ); return $path; }; $fileGlob = Get-StateFilePath -BaseName $serviceName -Suffix '*'; $files = Get-ChildItem -Path "^""$fileGlob"^""; if ($files.Count -gt 0) { $firstFilePath = $files[0].FullName; try { Remove-Item -Path $firstFilePath -Force -ErrorAction Stop; Write-Host 'The service is expected to be started.'; } catch { Write-Warning "^""Failed to delete the service state file `"^""$firstFilePath`"^"": $_"^""; }; }; if ($files.Count -ne 1) { <# Not the last file requiring restart #>; Write-Host 'Skipping starting the service: It was not running before.'; exit 0; }; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if (!$service) { throw "^""Failed to start service `"^""$serviceName`"^"": Service not found."^""; }; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""Skipping, `"^""$serviceName`"^"" is already running, no need to start."^""; exit 0; }; Write-Host "^""`"^""$serviceName`"^"" is not running, starting it."^""; try { $service | Start-Service -ErrorAction Stop; Write-Host "^""Successfully started the service: `"^""$serviceName`"^""."^""; } catch { Write-Warning "^""Failed to start the service: `"^""$serviceName`"^""."^""; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Disable Recall----------------------
:: ----------------------------------------------------------
echo --- Disable Recall
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot!DisableAIDataAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' /v 'DisableAIDataAnalysis' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable cloud-based speech recognition----------
:: ----------------------------------------------------------
echo --- Disable cloud-based speech recognition
:: Set the registry value: "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy!HasAccepted"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' /v 'HasAccepted' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Opt out of Windows privacy consent------------
:: ----------------------------------------------------------
echo --- Opt out of Windows privacy consent
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Personalization\Settings!AcceptedPrivacyPolicy"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Personalization\Settings'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Personalization\Settings' /v 'AcceptedPrivacyPolicy' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Windows feedback collection------------
:: ----------------------------------------------------------
echo --- Disable Windows feedback collection
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Siuf\Rules!NumberOfSIUFInPeriod"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Siuf\Rules'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Siuf\Rules' /v 'NumberOfSIUFInPeriod' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Delete the registry value "PeriodInNanoSeconds" from the key "HKCU\SOFTWARE\Microsoft\Siuf\Rules" 
PowerShell -ExecutionPolicy Unrestricted -Command "$keyName = 'HKCU\SOFTWARE\Microsoft\Siuf\Rules'; $valueName = 'PeriodInNanoSeconds'; $hive = $keyName.Split('\')[0]; $path = "^""$($hive):$($keyName.Substring($hive.Length))"^""; Write-Host "^""Removing the registry value '$valueName' from '$path'."^""; if (-Not (Test-Path -LiteralPath $path)) { Write-Host 'Skipping, no action needed, registry key does not exist.'; Exit 0; }; $existingValueNames = (Get-ItemProperty -LiteralPath $path).PSObject.Properties.Name; if (-Not ($existingValueNames -Contains $valueName)) { Write-Host 'Skipping, no action needed, registry value does not exist.'; Exit 0; }; try { if ($valueName -ieq '(default)') { Write-Host 'Removing the default value.'; $(Get-Item -LiteralPath $path).OpenSubKey('', $true).DeleteValue(''); } else { Remove-ItemProperty -LiteralPath $path -Name $valueName -Force -ErrorAction Stop; }; Write-Host 'Successfully removed the registry value.'; } catch { Write-Error "^""Failed to remove the registry value: $($_.Exception.Message)"^""; }"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection!DoNotShowFeedbackNotifications"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'DoNotShowFeedbackNotifications' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection!DoNotShowFeedbackNotifications"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'DoNotShowFeedbackNotifications' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable text and handwriting data collection-------
:: ----------------------------------------------------------
echo --- Disable text and handwriting data collection
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization!RestrictImplicitInkCollection"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' /v 'RestrictImplicitInkCollection' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization!RestrictImplicitTextCollection"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' /v 'RestrictImplicitTextCollection' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports!PreventHandwritingErrorReports"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' /v 'PreventHandwritingErrorReports' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC!PreventHandwritingDataSharing"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC' /v 'PreventHandwritingDataSharing' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization!AllowInputPersonalization"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization' /v 'AllowInputPersonalization' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore!HarvestContacts"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' /v 'HarvestContacts' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable device sensors------------------
:: ----------------------------------------------------------
echo --- Disable device sensors
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors!DisableSensors"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' /v 'DisableSensors' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable Wi-Fi Sense--------------------
:: ----------------------------------------------------------
echo --- Disable Wi-Fi Sense
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting!value"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' /v 'value' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config!AutoConnectAllowedOEM"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' /v 'AutoConnectAllowedOEM' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable app launch tracking (hides most-used apps)----
:: ----------------------------------------------------------
echo --- Disable app launch tracking (hides most-used apps)
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced!Start_TrackProgs"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Start_TrackProgs' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Website Access of Language List----------
:: ----------------------------------------------------------
echo --- Disable Website Access of Language List
:: Set the registry value: "HKCU\Control Panel\International\User Profile!HttpAcceptLanguageOptOut"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Control Panel\International\User Profile'; $data =  '1'; reg add 'HKCU\Control Panel\International\User Profile' /v 'HttpAcceptLanguageOptOut' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable automatic map downloads--------------
:: ----------------------------------------------------------
echo --- Disable automatic map downloads
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps!AllowUntriggeredNetworkTrafficOnSettingsPage"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps' /v 'AllowUntriggeredNetworkTrafficOnSettingsPage' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps!AutoDownloadAndUpdateMapData"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps' /v 'AutoDownloadAndUpdateMapData' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable internet access for Windows DRM----------
:: ----------------------------------------------------------
echo --- Disable internet access for Windows DRM
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\WMDRM!DisableOnline"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\WMDRM'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\WMDRM' /v 'DisableOnline' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable typing feedback (sends typing data)--------
:: ----------------------------------------------------------
echo --- Disable typing feedback (sends typing data)
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Input\TIPC!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Input\TIPC'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\Input\TIPC' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Input\TIPC!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Input\TIPC'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Input\TIPC' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Activity Feed feature---------------
:: ----------------------------------------------------------
echo --- Disable Activity Feed feature
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\System!EnableActivityFeed"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'EnableActivityFeed' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable NET Core CLI telemetry--------------
:: ----------------------------------------------------------
echo --- Disable NET Core CLI telemetry
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable PowerShell telemetry---------------
:: ----------------------------------------------------------
echo --- Disable PowerShell telemetry
setx POWERSHELL_TELEMETRY_OPTOUT 1
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable "Razer Game Scanner Service"-----------
:: ----------------------------------------------------------
echo --- Disable "Razer Game Scanner Service"
:: Disable service(s): `Razer Game Scanner Service`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'Razer Game Scanner Service'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable "Logitech Gaming Registry Service"--------
:: ----------------------------------------------------------
echo --- Disable "Logitech Gaming Registry Service"
:: Disable service(s): `LogiRegistryService`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'LogiRegistryService'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable CCleaner data collection-------------
:: ----------------------------------------------------------
echo --- Disable CCleaner data collection
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!Monitoring"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v 'Monitoring' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!HelpImproveCCleaner"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v 'HelpImproveCCleaner' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!SystemMonitoring"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v 'SystemMonitoring' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!UpdateAuto"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v 'UpdateAuto' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!UpdateCheck"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v 'UpdateCheck' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!UpdateBackground"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v 'UpdateBackground' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!CheckTrialOffer"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v 'CheckTrialOffer' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!(Cfg)HealthCheck"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v '(Cfg)HealthCheck' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!(Cfg)QuickClean"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v '(Cfg)QuickClean' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!(Cfg)QuickCleanIpm"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v '(Cfg)QuickCleanIpm' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!(Cfg)GetIpmForTrial"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v '(Cfg)GetIpmForTrial' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!(Cfg)SoftwareUpdater"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v '(Cfg)SoftwareUpdater' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Piriform\CCleaner!(Cfg)SoftwareUpdaterIpm"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Piriform\CCleaner'; $data =  '0'; reg add 'HKCU\Software\Piriform\CCleaner' /v '(Cfg)SoftwareUpdaterIpm' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Enable Data Execution Prevention (DEP)----------
:: ----------------------------------------------------------
echo --- Enable Data Execution Prevention (DEP)
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer!NoDataExecutionPrevention"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'NoDataExecutionPrevention' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\System!DisableHHDEP"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'DisableHHDEP' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable AutoPlay and AutoRun---------------
:: ----------------------------------------------------------
echo --- Disable AutoPlay and AutoRun
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoDriveTypeAutoRun"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '255'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoDriveTypeAutoRun' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoAutorun"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoAutorun' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer!NoAutoplayfornonVolume"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'NoAutoplayfornonVolume' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable lock screen camera access-------------
:: ----------------------------------------------------------
echo --- Disable lock screen camera access
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization!NoLockScreenCamera"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization' /v 'NoLockScreenCamera' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable storage of the LAN Manager password hashes----
:: ----------------------------------------------------------
echo --- Disable storage of the LAN Manager password hashes
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Lsa!NoLMHash"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'NoLMHash' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable "Always install with elevated privileges" in Windows Installer
echo --- Disable "Always install with elevated privileges" in Windows Installer
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer!AlwaysInstallElevated"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' /v 'AlwaysInstallElevated' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Enable Structured Exception Handling Overwrite Protection (SEHOP)
echo --- Enable Structured Exception Handling Overwrite Protection (SEHOP)
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel!DisableExceptionChainValidation"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' /v 'DisableExceptionChainValidation' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Enable security against PowerShell 2.0 downgrade attacks-
:: ----------------------------------------------------------
echo --- Enable security against PowerShell 2.0 downgrade attacks
:: Disable the "MicrosoftWindowsPowerShellV2" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'MicrosoftWindowsPowerShellV2'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: Disable the "MicrosoftWindowsPowerShellV2Root" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'MicrosoftWindowsPowerShellV2Root'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable "Windows Connect Now" wizard-----------
:: ----------------------------------------------------------
echo --- Disable "Windows Connect Now" wizard
:: Set the registry value: "HKLM\Software\Policies\Microsoft\Windows\WCN\UI!DisableWcnUi"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\Windows\WCN\UI'; $data =  '1'; reg add 'HKLM\Software\Policies\Microsoft\Windows\WCN\UI' /v 'DisableWcnUi' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars!DisableFlashConfigRegistrar"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' /v 'DisableFlashConfigRegistrar' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars!DisableInBand802DOT11Registrar"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' /v 'DisableInBand802DOT11Registrar' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars!DisableUPnPRegistrar"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' /v 'DisableUPnPRegistrar' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars!DisableWPDRegistrar"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' /v 'DisableWPDRegistrar' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars!EnableRegistrars"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' /v 'EnableRegistrars' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable lock screen app notifications-----------
:: ----------------------------------------------------------
echo --- Disable lock screen app notifications
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\System!DisableLockScreenAppNotifications"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'DisableLockScreenAppNotifications' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Live Tiles push notifications-----------
:: ----------------------------------------------------------
echo --- Disable Live Tiles push notifications
:: Set the registry value: "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications!NoTileApplicationNotification"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; $data =  '1'; reg add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' /v 'NoTileApplicationNotification' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable the "Look For An App In The Store" option-----
:: ----------------------------------------------------------
echo --- Disable the "Look For An App In The Store" option
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer!NoUseStoreOpenWith"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'NoUseStoreOpenWith' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable the display of recently used files in Quick Access
echo --- Disable the display of recently used files in Quick Access
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer!ShowRecent"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v 'ShowRecent' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Delete the registry value "(Default)" from the key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" 
PowerShell -ExecutionPolicy Unrestricted -Command "$keyName = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}'; $valueName = '(Default)'; $hive = $keyName.Split('\')[0]; $path = "^""$($hive):$($keyName.Substring($hive.Length))"^""; Write-Host "^""Removing the registry value '$valueName' from '$path'."^""; if (-Not (Test-Path -LiteralPath $path)) { Write-Host 'Skipping, no action needed, registry key does not exist.'; Exit 0; }; $existingValueNames = (Get-ItemProperty -LiteralPath $path).PSObject.Properties.Name; if (-Not ($existingValueNames -Contains $valueName)) { Write-Host 'Skipping, no action needed, registry value does not exist.'; Exit 0; }; try { if ($valueName -ieq '(default)') { Write-Host 'Removing the default value.'; $(Get-Item -LiteralPath $path).OpenSubKey('', $true).DeleteValue(''); } else { Remove-ItemProperty -LiteralPath $path -Name $valueName -Force -ErrorAction Stop; }; Write-Host 'Successfully removed the registry value.'; } catch { Write-Error "^""Failed to remove the registry value: $($_.Exception.Message)"^""; }"
:: Delete the registry value "(Default)" from the key "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" 
PowerShell -ExecutionPolicy Unrestricted -Command "$keyName = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}'; $valueName = '(Default)'; $hive = $keyName.Split('\')[0]; $path = "^""$($hive):$($keyName.Substring($hive.Length))"^""; Write-Host "^""Removing the registry value '$valueName' from '$path'."^""; if (-Not (Test-Path -LiteralPath $path)) { Write-Host 'Skipping, no action needed, registry key does not exist.'; Exit 0; }; $existingValueNames = (Get-ItemProperty -LiteralPath $path).PSObject.Properties.Name; if (-Not ($existingValueNames -Contains $valueName)) { Write-Host 'Skipping, no action needed, registry value does not exist.'; Exit 0; }; try { if ($valueName -ieq '(default)') { Write-Host 'Removing the default value.'; $(Get-Item -LiteralPath $path).OpenSubKey('', $true).DeleteValue(''); } else { Remove-ItemProperty -LiteralPath $path -Name $valueName -Force -ErrorAction Stop; }; Write-Host 'Successfully removed the registry value.'; } catch { Write-Error "^""Failed to remove the registry value: $($_.Exception.Message)"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable sync provider notifications------------
:: ----------------------------------------------------------
echo --- Disable sync provider notifications
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced!ShowSyncProviderNotifications"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowSyncProviderNotifications' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Enable camera on/off OSD notifications----------
:: ----------------------------------------------------------
echo --- Enable camera on/off OSD notifications
:: Set the registry value: "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoPhysicalCameraLED"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '1'; reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoPhysicalCameraLED' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable app usage tracking----------------
:: ----------------------------------------------------------
echo --- Disable app usage tracking
:: Set the registry value: "HKCU\Software\Policies\Microsoft\Windows\EdgeUI!DisableMFUTracking"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Policies\Microsoft\Windows\EdgeUI'; $data =  '1'; reg add 'HKCU\Software\Policies\Microsoft\Windows\EdgeUI' /v 'DisableMFUTracking' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable recent apps--------------------
:: ----------------------------------------------------------
echo --- Disable recent apps
:: Set the registry value: "HKCU\Software\Policies\Microsoft\Windows\EdgeUI!DisableRecentApps"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Policies\Microsoft\Windows\EdgeUI'; $data =  '1'; reg add 'HKCU\Software\Policies\Microsoft\Windows\EdgeUI' /v 'DisableRecentApps' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable backtracking-------------------
:: ----------------------------------------------------------
echo --- Disable backtracking
:: Set the registry value: "HKCU\Software\Policies\Microsoft\Windows\EdgeUI!TurnOffBackstack"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Policies\Microsoft\Windows\EdgeUI'; $data =  '1'; reg add 'HKCU\Software\Policies\Microsoft\Windows\EdgeUI' /v 'TurnOffBackstack' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Remove "Meet Now" icon from taskbar------------
:: ----------------------------------------------------------
echo --- Remove "Meet Now" icon from taskbar
:: Set the registry value: "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!HideSCAMeetNow"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '1'; reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'HideSCAMeetNow' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Set NTP (time) server to `pool.ntp.org`----------
:: ----------------------------------------------------------
echo --- Set NTP (time) server to `pool.ntp.org`
:: Configure time source
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
:: Stop time service if running
SC queryex "w32time"|Find "STATE"|Find /v "RUNNING">Nul||(
    net stop w32time
)
:: Start time service and sync now
net start w32time
w32tm /config /update
w32tm /resync
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable reserved storage for updates-----------
:: ----------------------------------------------------------
echo --- Disable reserved storage for updates
dism /online /Set-ReservedStorageState /State:Disabled /NoRestart
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager!ShippedWithReserves"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' /v 'ShippedWithReserves' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager!PassedPolicy"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' /v 'PassedPolicy' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager!MiscPolicyInfo"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager'; $data =  '2'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' /v 'MiscPolicyInfo' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Customer Experience Improvement Program data collection
echo --- Disable Customer Experience Improvement Program data collection
:: Set the registry value: "HKLM\Software\Policies\Microsoft\SQMClient\Windows!CEIPEnable"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\SQMClient\Windows'; $data =  '0'; reg add 'HKLM\Software\Policies\Microsoft\SQMClient\Windows' /v 'CEIPEnable' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\Software\Microsoft\SQMClient\Windows!CEIPEnable"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Microsoft\SQMClient\Windows'; $data =  '0'; reg add 'HKLM\Software\Microsoft\SQMClient\Windows' /v 'CEIPEnable' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Customer Experience Improvement Program data uploads
echo --- Disable Customer Experience Improvement Program data uploads
:: Set the registry value: "HKLM\Software\Microsoft\SQMClient!UploadDisableFlag"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Microsoft\SQMClient'; $data =  '0'; reg add 'HKLM\Software\Microsoft\SQMClient' /v 'UploadDisableFlag' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Application Impact Telemetry (AIT)--------
:: ----------------------------------------------------------
echo --- Disable Application Impact Telemetry (AIT)
:: Set the registry value: "HKLM\Software\Policies\Microsoft\Windows\AppCompat!AITEnable"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\Windows\AppCompat'; $data =  '0'; reg add 'HKLM\Software\Policies\Microsoft\Windows\AppCompat' /v 'AITEnable' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Application Compatibility Engine---------
:: ----------------------------------------------------------
echo --- Disable Application Compatibility Engine
:: Set the registry value: "HKLM\Software\Policies\Microsoft\Windows\AppCompat!DisableEngine"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\Windows\AppCompat'; $data =  '1'; reg add 'HKLM\Software\Policies\Microsoft\Windows\AppCompat' /v 'DisableEngine' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Remove "Program Compatibility" tab from file properties (context menu)
echo --- Remove "Program Compatibility" tab from file properties (context menu)
:: Set the registry value: "HKLM\Software\Policies\Microsoft\Windows\AppCompat!DisablePropPage"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\Windows\AppCompat'; $data =  '1'; reg add 'HKLM\Software\Policies\Microsoft\Windows\AppCompat' /v 'DisablePropPage' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Steps Recorder (collects screenshots, mouse/keyboard input and UI data)
echo --- Disable Steps Recorder (collects screenshots, mouse/keyboard input and UI data)
:: Set the registry value: "HKLM\Software\Policies\Microsoft\Windows\AppCompat!DisableUAR"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\Windows\AppCompat'; $data =  '1'; reg add 'HKLM\Software\Policies\Microsoft\Windows\AppCompat' /v 'DisableUAR' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable "Inventory Collector" task------------
:: ----------------------------------------------------------
echo --- Disable "Inventory Collector" task
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat!DisableInventory"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'DisableInventory' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable active connectivity tests (breaks internet connection status, captive portals)
echo --- Disable active connectivity tests (breaks internet connection status, captive portals)
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator!NoActiveProbe"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' /v 'NoActiveProbe' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet!EnableActiveProbing"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' /v 'EnableActiveProbing' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting computer for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart your computer.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: Disable passive connectivity tests (breaks internet connection status)
echo --- Disable passive connectivity tests (breaks internet connection status)
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator!DisablePassivePolling"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' /v 'DisablePassivePolling' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet!PassivePollPeriod"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' /v 'PassivePollPeriod' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Remove "Network Connectivity Status Indicator (NCSI)" app (breaks internet connection status icon)
echo --- Remove "Network Connectivity Status Indicator (NCSI)" app (breaks internet connection status icon)
:: Enable removal of system app 'NcsiUwpApp' by marking it as "EndOfLife"
:: Create "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$CURRENT_USER_SID\NcsiUwpApp_8wekyb3d8bbwe" registry key
PowerShell -ExecutionPolicy Unrestricted -Command "$keyPath='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$CURRENT_USER_SID\NcsiUwpApp_8wekyb3d8bbwe'; $registryHive = $keyPath.Split('\')[0]; $registryPath = "^""$($registryHive):$($keyPath.Substring($registryHive.Length))"^""; $userSid = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value; $registryPath = $registryPath.Replace('$CURRENT_USER_SID', $userSid); if (Test-Path $registryPath) { Write-Host "^""Skipping, no action needed, registry path `"^""$registryPath`"^"" already exists."^""; exit 0; }; try { New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null; Write-Host "^""Successfully created the registry key at path `"^""$registryPath`"^""."^""; } catch { Write-Error "^""Failed to create the registry key at path `"^""$registryPath`"^"": $($_.Exception.Message)"^""; }"
:: Uninstall 'NcsiUwpApp' Store app
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'NcsiUwpApp' | Remove-AppxPackage"
:: Mark 'NcsiUwpApp' as deprovisioned to block reinstall during Windows updates.
:: Create "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\NcsiUwpApp_8wekyb3d8bbwe" registry key
PowerShell -ExecutionPolicy Unrestricted -Command "$keyPath='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\NcsiUwpApp_8wekyb3d8bbwe'; $registryHive = $keyPath.Split('\')[0]; $registryPath = "^""$($registryHive):$($keyPath.Substring($registryHive.Length))"^""; if (Test-Path $registryPath) { Write-Host "^""Skipping, no action needed, registry path `"^""$registryPath`"^"" already exists."^""; exit 0; }; try { New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null; Write-Host "^""Successfully created the registry key at path `"^""$registryPath`"^""."^""; } catch { Write-Error "^""Failed to create the registry key at path `"^""$registryPath`"^"": $($_.Exception.Message)"^""; }"
:: Remove the registry key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$CURRENT_USER_SID\NcsiUwpApp_8wekyb3d8bbwe" (Revert 'NcsiUwpApp' to its default, non-removable state.)
PowerShell -ExecutionPolicy Unrestricted -Command "$keyPath='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$CURRENT_USER_SID\NcsiUwpApp_8wekyb3d8bbwe'; $registryHive = $keyPath.Split('\')[0]; $registryPath = "^""$($registryHive):$($keyPath.Substring($registryHive.Length))"^""; $userSid = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value; $registryPath = $registryPath.Replace('$CURRENT_USER_SID', $userSid); Write-Host "^""Removing registry key at `"^""$registryPath`"^""."^""; if (-not (Test-Path -LiteralPath $registryPath)) { Write-Host "^""Skipping, no action needed, registry key `"^""$registryPath`"^"" does not exist."^""; exit 0; }; try { Remove-Item -LiteralPath $registryPath -Force -ErrorAction Stop | Out-Null; Write-Host "^""Successfully removed the registry key at path `"^""$registryPath`"^""."^""; } catch { Write-Error "^""Failed to remove the registry key at path `"^""$registryPath`"^"": $($_.Exception.Message)"^""; }"
:: ----------------------------------------------------------


:: Block Microsoft connectivity check hosts (breaks internet connection status, captive portals)
echo --- Block Microsoft connectivity check hosts (breaks internet connection status, captive portals)
:: Add hosts entries for msftncsi.com
PowerShell -ExecutionPolicy Unrestricted -Command "$domain ='msftncsi.com'; $hostsFilePath = "^""$env:SYSTEMROOT\System32\drivers\etc\hosts"^""; $comment = "^""managed by privacy.sexy"^""; $hostsFileEncoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Utf8; $blockingHostsEntries = @(; @{ AddressType = "^""IPv4"^"";  IPAddress = '0.0.0.0'; }; @{ AddressType = "^""IPv6"^"";  IPAddress = '::1'; }; ); try { $isHostsFilePresent = Test-Path -Path $hostsFilePath -PathType Leaf -ErrorAction Stop; } catch { Write-Error "^""Failed to check hosts file existence. Error: $_"^""; exit 1; }; if (-Not $isHostsFilePresent) { Write-Output "^""Creating a new hosts file at $hostsFilePath."^""; try { New-Item -Path $hostsFilePath -ItemType File -Force -ErrorAction Stop | Out-Null; Write-Output "^""Successfully created the hosts file."^""; } catch { Write-Error "^""Failed to create the hosts file. Error: $_"^""; exit 1; }; }; foreach ($blockingEntry in $blockingHostsEntries) { Write-Output "^""Processing addition for $($blockingEntry.AddressType) entry."^""; try { $hostsFileContents = Get-Content -Path "^""$hostsFilePath"^"" -Raw -Encoding $hostsFileEncoding -ErrorAction Stop; } catch { Write-Error "^""Failed to read the hosts file. Error: $_"^""; continue; }; $hostsEntryLine = "^""$($blockingEntry.IPAddress)`t$domain $([char]35) $comment"^""; if ((-Not [String]::IsNullOrWhiteSpace($hostsFileContents)) -And ($hostsFileContents.Contains($hostsEntryLine))) { Write-Output 'Skipping, entry already exists.'; continue; }; try { Add-Content -Path $hostsFilePath -Value $hostsEntryLine -Encoding $hostsFileEncoding -ErrorAction Stop; Write-Output 'Successfully added the entry.'; } catch { Write-Error "^""Failed to add the entry. Error: $_"^""; continue; }; }"
:: Add hosts entries for dns.msftncsi.com
PowerShell -ExecutionPolicy Unrestricted -Command "$domain ='dns.msftncsi.com'; $hostsFilePath = "^""$env:SYSTEMROOT\System32\drivers\etc\hosts"^""; $comment = "^""managed by privacy.sexy"^""; $hostsFileEncoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Utf8; $blockingHostsEntries = @(; @{ AddressType = "^""IPv4"^"";  IPAddress = '0.0.0.0'; }; @{ AddressType = "^""IPv6"^"";  IPAddress = '::1'; }; ); try { $isHostsFilePresent = Test-Path -Path $hostsFilePath -PathType Leaf -ErrorAction Stop; } catch { Write-Error "^""Failed to check hosts file existence. Error: $_"^""; exit 1; }; if (-Not $isHostsFilePresent) { Write-Output "^""Creating a new hosts file at $hostsFilePath."^""; try { New-Item -Path $hostsFilePath -ItemType File -Force -ErrorAction Stop | Out-Null; Write-Output "^""Successfully created the hosts file."^""; } catch { Write-Error "^""Failed to create the hosts file. Error: $_"^""; exit 1; }; }; foreach ($blockingEntry in $blockingHostsEntries) { Write-Output "^""Processing addition for $($blockingEntry.AddressType) entry."^""; try { $hostsFileContents = Get-Content -Path "^""$hostsFilePath"^"" -Raw -Encoding $hostsFileEncoding -ErrorAction Stop; } catch { Write-Error "^""Failed to read the hosts file. Error: $_"^""; continue; }; $hostsEntryLine = "^""$($blockingEntry.IPAddress)`t$domain $([char]35) $comment"^""; if ((-Not [String]::IsNullOrWhiteSpace($hostsFileContents)) -And ($hostsFileContents.Contains($hostsEntryLine))) { Write-Output 'Skipping, entry already exists.'; continue; }; try { Add-Content -Path $hostsFilePath -Value $hostsEntryLine -Encoding $hostsFileEncoding -ErrorAction Stop; Write-Output 'Successfully added the entry.'; } catch { Write-Error "^""Failed to add the entry. Error: $_"^""; continue; }; }"
:: Add hosts entries for ipv6.msftncsi.com
PowerShell -ExecutionPolicy Unrestricted -Command "$domain ='ipv6.msftncsi.com'; $hostsFilePath = "^""$env:SYSTEMROOT\System32\drivers\etc\hosts"^""; $comment = "^""managed by privacy.sexy"^""; $hostsFileEncoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Utf8; $blockingHostsEntries = @(; @{ AddressType = "^""IPv4"^"";  IPAddress = '0.0.0.0'; }; @{ AddressType = "^""IPv6"^"";  IPAddress = '::1'; }; ); try { $isHostsFilePresent = Test-Path -Path $hostsFilePath -PathType Leaf -ErrorAction Stop; } catch { Write-Error "^""Failed to check hosts file existence. Error: $_"^""; exit 1; }; if (-Not $isHostsFilePresent) { Write-Output "^""Creating a new hosts file at $hostsFilePath."^""; try { New-Item -Path $hostsFilePath -ItemType File -Force -ErrorAction Stop | Out-Null; Write-Output "^""Successfully created the hosts file."^""; } catch { Write-Error "^""Failed to create the hosts file. Error: $_"^""; exit 1; }; }; foreach ($blockingEntry in $blockingHostsEntries) { Write-Output "^""Processing addition for $($blockingEntry.AddressType) entry."^""; try { $hostsFileContents = Get-Content -Path "^""$hostsFilePath"^"" -Raw -Encoding $hostsFileEncoding -ErrorAction Stop; } catch { Write-Error "^""Failed to read the hosts file. Error: $_"^""; continue; }; $hostsEntryLine = "^""$($blockingEntry.IPAddress)`t$domain $([char]35) $comment"^""; if ((-Not [String]::IsNullOrWhiteSpace($hostsFileContents)) -And ($hostsFileContents.Contains($hostsEntryLine))) { Write-Output 'Skipping, entry already exists.'; continue; }; try { Add-Content -Path $hostsFilePath -Value $hostsEntryLine -Encoding $hostsFileEncoding -ErrorAction Stop; Write-Output 'Successfully added the entry.'; } catch { Write-Error "^""Failed to add the entry. Error: $_"^""; continue; }; }"
:: Add hosts entries for msftconnecttest.com
PowerShell -ExecutionPolicy Unrestricted -Command "$domain ='msftconnecttest.com'; $hostsFilePath = "^""$env:SYSTEMROOT\System32\drivers\etc\hosts"^""; $comment = "^""managed by privacy.sexy"^""; $hostsFileEncoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Utf8; $blockingHostsEntries = @(; @{ AddressType = "^""IPv4"^"";  IPAddress = '0.0.0.0'; }; @{ AddressType = "^""IPv6"^"";  IPAddress = '::1'; }; ); try { $isHostsFilePresent = Test-Path -Path $hostsFilePath -PathType Leaf -ErrorAction Stop; } catch { Write-Error "^""Failed to check hosts file existence. Error: $_"^""; exit 1; }; if (-Not $isHostsFilePresent) { Write-Output "^""Creating a new hosts file at $hostsFilePath."^""; try { New-Item -Path $hostsFilePath -ItemType File -Force -ErrorAction Stop | Out-Null; Write-Output "^""Successfully created the hosts file."^""; } catch { Write-Error "^""Failed to create the hosts file. Error: $_"^""; exit 1; }; }; foreach ($blockingEntry in $blockingHostsEntries) { Write-Output "^""Processing addition for $($blockingEntry.AddressType) entry."^""; try { $hostsFileContents = Get-Content -Path "^""$hostsFilePath"^"" -Raw -Encoding $hostsFileEncoding -ErrorAction Stop; } catch { Write-Error "^""Failed to read the hosts file. Error: $_"^""; continue; }; $hostsEntryLine = "^""$($blockingEntry.IPAddress)`t$domain $([char]35) $comment"^""; if ((-Not [String]::IsNullOrWhiteSpace($hostsFileContents)) -And ($hostsFileContents.Contains($hostsEntryLine))) { Write-Output 'Skipping, entry already exists.'; continue; }; try { Add-Content -Path $hostsFilePath -Value $hostsEntryLine -Encoding $hostsFileEncoding -ErrorAction Stop; Write-Output 'Successfully added the entry.'; } catch { Write-Error "^""Failed to add the entry. Error: $_"^""; continue; }; }"
:: Add hosts entries for www.msftconnecttest.com
PowerShell -ExecutionPolicy Unrestricted -Command "$domain ='www.msftconnecttest.com'; $hostsFilePath = "^""$env:SYSTEMROOT\System32\drivers\etc\hosts"^""; $comment = "^""managed by privacy.sexy"^""; $hostsFileEncoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Utf8; $blockingHostsEntries = @(; @{ AddressType = "^""IPv4"^"";  IPAddress = '0.0.0.0'; }; @{ AddressType = "^""IPv6"^"";  IPAddress = '::1'; }; ); try { $isHostsFilePresent = Test-Path -Path $hostsFilePath -PathType Leaf -ErrorAction Stop; } catch { Write-Error "^""Failed to check hosts file existence. Error: $_"^""; exit 1; }; if (-Not $isHostsFilePresent) { Write-Output "^""Creating a new hosts file at $hostsFilePath."^""; try { New-Item -Path $hostsFilePath -ItemType File -Force -ErrorAction Stop | Out-Null; Write-Output "^""Successfully created the hosts file."^""; } catch { Write-Error "^""Failed to create the hosts file. Error: $_"^""; exit 1; }; }; foreach ($blockingEntry in $blockingHostsEntries) { Write-Output "^""Processing addition for $($blockingEntry.AddressType) entry."^""; try { $hostsFileContents = Get-Content -Path "^""$hostsFilePath"^"" -Raw -Encoding $hostsFileEncoding -ErrorAction Stop; } catch { Write-Error "^""Failed to read the hosts file. Error: $_"^""; continue; }; $hostsEntryLine = "^""$($blockingEntry.IPAddress)`t$domain $([char]35) $comment"^""; if ((-Not [String]::IsNullOrWhiteSpace($hostsFileContents)) -And ($hostsFileContents.Contains($hostsEntryLine))) { Write-Output 'Skipping, entry already exists.'; continue; }; try { Add-Content -Path $hostsFilePath -Value $hostsEntryLine -Encoding $hostsFileEncoding -ErrorAction Stop; Write-Output 'Successfully added the entry.'; } catch { Write-Error "^""Failed to add the entry. Error: $_"^""; continue; }; }"
:: Add hosts entries for ipv6.msftconnecttest.com
PowerShell -ExecutionPolicy Unrestricted -Command "$domain ='ipv6.msftconnecttest.com'; $hostsFilePath = "^""$env:SYSTEMROOT\System32\drivers\etc\hosts"^""; $comment = "^""managed by privacy.sexy"^""; $hostsFileEncoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Utf8; $blockingHostsEntries = @(; @{ AddressType = "^""IPv4"^"";  IPAddress = '0.0.0.0'; }; @{ AddressType = "^""IPv6"^"";  IPAddress = '::1'; }; ); try { $isHostsFilePresent = Test-Path -Path $hostsFilePath -PathType Leaf -ErrorAction Stop; } catch { Write-Error "^""Failed to check hosts file existence. Error: $_"^""; exit 1; }; if (-Not $isHostsFilePresent) { Write-Output "^""Creating a new hosts file at $hostsFilePath."^""; try { New-Item -Path $hostsFilePath -ItemType File -Force -ErrorAction Stop | Out-Null; Write-Output "^""Successfully created the hosts file."^""; } catch { Write-Error "^""Failed to create the hosts file. Error: $_"^""; exit 1; }; }; foreach ($blockingEntry in $blockingHostsEntries) { Write-Output "^""Processing addition for $($blockingEntry.AddressType) entry."^""; try { $hostsFileContents = Get-Content -Path "^""$hostsFilePath"^"" -Raw -Encoding $hostsFileEncoding -ErrorAction Stop; } catch { Write-Error "^""Failed to read the hosts file. Error: $_"^""; continue; }; $hostsEntryLine = "^""$($blockingEntry.IPAddress)`t$domain $([char]35) $comment"^""; if ((-Not [String]::IsNullOrWhiteSpace($hostsFileContents)) -And ($hostsFileContents.Contains($hostsEntryLine))) { Write-Output 'Skipping, entry already exists.'; continue; }; try { Add-Content -Path $hostsFilePath -Value $hostsEntryLine -Encoding $hostsFileEncoding -ErrorAction Stop; Write-Output 'Successfully added the entry.'; } catch { Write-Error "^""Failed to add the entry. Error: $_"^""; continue; }; }"
:: ----------------------------------------------------------


:: Disable "Network Location Awareness (NLA)" service (breaks auto-reconnect, connectivity status, network identification)
echo --- Disable "Network Location Awareness (NLA)" service (breaks auto-reconnect, connectivity status, network identification)
:: Disable service(s): `NlaSvc`
:: This operation will not run on Windows versions later than Windows10-MostRecent.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-MostRecent'; $buildNumber = switch ($versionName) { 'Windows11-21H2' { '10.0.22000' }; 'Windows10-MostRecent' { '10.0.19045' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1903' { '10.0.18362' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for maximum Windows '$versionName'"^""; }; }; $maxVersion=[System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -gt $maxVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is above maximum $maxVersion ($versionName)"^""; Exit 0; }; $serviceName = 'NlaSvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: Disable "Network List Service (NLS)" service (breaks connectivity status, network identification, network connection icon, connectivity with some Microsoft apps)
echo --- Disable "Network List Service (NLS)" service (breaks connectivity status, network identification, network connection icon, connectivity with some Microsoft apps)
:: Disable service(s): `netprofm`
:: This operation will not run on Windows versions later than Windows10-MostRecent.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-MostRecent'; $buildNumber = switch ($versionName) { 'Windows11-21H2' { '10.0.22000' }; 'Windows10-MostRecent' { '10.0.19045' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1903' { '10.0.18362' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for maximum Windows '$versionName'"^""; }; }; $maxVersion=[System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -gt $maxVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is above maximum $maxVersion ($versionName)"^""; Exit 0; }; $serviceName = 'netprofm'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable update and app peer downloads-----------
:: ----------------------------------------------------------
echo --- Disable update and app peer downloads
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization!DODownloadMode"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' /v 'DODownloadMode' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config!DODownloadMode"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' /v 'DODownloadMode' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings!DownloadMode"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings'; $data =  '0'; reg add 'HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' /v 'DownloadMode' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization!SystemSettingsDownloadMode"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization' /v 'SystemSettingsDownloadMode' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Delivery Optimization service (breaks Windows Update & Store downloads)
echo --- Disable Delivery Optimization service (breaks Windows Update ^& Store downloads)
:: Disable the service `DoSvc` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'DoSvc'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable search's access to location------------
:: ----------------------------------------------------------
echo --- Disable search's access to location
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!AllowSearchToUseLocation"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'AllowSearchToUseLocation' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search!AllowSearchToUseLocation"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; $data =  '1'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'AllowSearchToUseLocation' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable local search history (breaks recent suggestions)-
:: ----------------------------------------------------------
echo --- Disable local search history (breaks recent suggestions)
:: Set the registry value: "HKLM\Software\Policies\Microsoft\Windows\Explorer!DisableSearchHistory"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\Windows\Explorer'; $data =  '1'; reg add 'HKLM\Software\Policies\Microsoft\Windows\Explorer' /v 'DisableSearchHistory' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings!IsDeviceSearchHistoryEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; $data =  '1'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings' /v 'IsDeviceSearchHistoryEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Disable sharing personal search data with Microsoft----
:: ----------------------------------------------------------
echo --- Disable sharing personal search data with Microsoft
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!ConnectedSearchPrivacy"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '3'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'ConnectedSearchPrivacy' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable personal cloud content search in taskbar-----
:: ----------------------------------------------------------
echo --- Disable personal cloud content search in taskbar
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings!IsMSACloudSearchEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings' /v 'IsMSACloudSearchEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings!IsAADCloudSearchEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings' /v 'IsAADCloudSearchEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable ad customization with Advertising ID-------
:: ----------------------------------------------------------
echo --- Disable ad customization with Advertising ID
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo!DisabledByGroupPolicy"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' /v 'DisabledByGroupPolicy' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable suggested content in Settings app---------
:: ----------------------------------------------------------
echo --- Disable suggested content in Settings app
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager!SubscribedContent-338393Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-338393Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager!SubscribedContent-353694Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-353694Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager!SubscribedContent-353696Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-353696Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable "Windows Insider Service"-------------
:: ----------------------------------------------------------
echo --- Disable "Windows Insider Service"
:: Disable service(s): `wisvc`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wisvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Microsoft feature trials-------------
:: ----------------------------------------------------------
echo --- Disable Microsoft feature trials
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds!EnableExperimentation"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' /v 'EnableExperimentation' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds!EnableConfigFlighting"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' /v 'EnableConfigFlighting' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation!value"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation' /v 'value' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable receipt of Windows preview builds---------
:: ----------------------------------------------------------
echo --- Disable receipt of Windows preview builds
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds!AllowBuildPreview"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' /v 'AllowBuildPreview' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Remove "Windows Insider Program" from Settings------
:: ----------------------------------------------------------
echo --- Remove "Windows Insider Program" from Settings
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility!HideInsiderPage"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility' /v 'HideInsiderPage' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable automatic Software Quality Metrics (SQM) data transmission
echo --- Disable automatic Software Quality Metrics (SQM) data transmission
:: Disable scheduled task(s): `\Microsoft\Windows\Autochk\Proxy`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Autochk\'; $taskNamePattern='Proxy'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable kernel-level customer experience data collection-
:: ----------------------------------------------------------
echo --- Disable kernel-level customer experience data collection
:: Disable scheduled task(s): `\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Customer Experience Improvement Program\'; $taskNamePattern='KernelCeipTask'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Bluetooth usage data collection----------
:: ----------------------------------------------------------
echo --- Disable Bluetooth usage data collection
:: Disable scheduled task(s): `\Microsoft\Windows\Customer Experience Improvement Program\BthSQM`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Customer Experience Improvement Program\'; $taskNamePattern='BthSQM'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable disk diagnostic data collection----------
:: ----------------------------------------------------------
echo --- Disable disk diagnostic data collection
:: Disable scheduled task(s): `\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\DiskDiagnostic\'; $taskNamePattern='Microsoft-Windows-DiskDiagnosticDataCollector'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable disk diagnostic user notifications--------
:: ----------------------------------------------------------
echo --- Disable disk diagnostic user notifications
:: Disable scheduled task(s): `\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\DiskDiagnostic\'; $taskNamePattern='Microsoft-Windows-DiskDiagnosticResolver'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable USB data collection----------------
:: ----------------------------------------------------------
echo --- Disable USB data collection
:: Disable scheduled task(s): `\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Customer Experience Improvement Program\'; $taskNamePattern='UsbCeip'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable customer experience data consolidation------
:: ----------------------------------------------------------
echo --- Disable customer experience data consolidation
:: Disable scheduled task(s): `\Microsoft\Windows\Customer Experience Improvement Program\Consolidator`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Customer Experience Improvement Program\'; $taskNamePattern='Consolidator'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable customer experience data uploads---------
:: ----------------------------------------------------------
echo --- Disable customer experience data uploads
:: Disable scheduled task(s): `\Microsoft\Windows\Customer Experience Improvement Program\Uploader`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Customer Experience Improvement Program\'; $taskNamePattern='Uploader'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable server customer experience data assistant-----
:: ----------------------------------------------------------
echo --- Disable server customer experience data assistant
:: Disable scheduled task(s): `\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Customer Experience Improvement Program\Server\'; $taskNamePattern='ServerCeipAssistant'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable server role telemetry collection---------
:: ----------------------------------------------------------
echo --- Disable server role telemetry collection
:: Disable scheduled task(s): `\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleCollector`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Customer Experience Improvement Program\Server\'; $taskNamePattern='ServerRoleCollector'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable server role usage data collection---------
:: ----------------------------------------------------------
echo --- Disable server role usage data collection
:: Disable scheduled task(s): `\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleUsageCollector`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Customer Experience Improvement Program\Server\'; $taskNamePattern='ServerRoleUsageCollector'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: Disable daily compatibility data collection ("Microsoft Compatibility Appraiser" task)
echo --- Disable daily compatibility data collection ("Microsoft Compatibility Appraiser" task)
:: Disable scheduled task(s): `\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Application Experience\'; $taskNamePattern='Microsoft Compatibility Appraiser'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: Disable telemetry collector and sender process (`CompatTelRunner.exe`)
echo --- Disable telemetry collector and sender process (`CompatTelRunner.exe`)
:: Check and terminate the running process "CompatTelRunner.exe"
tasklist /fi "ImageName eq CompatTelRunner.exe" /fo csv 2>NUL | find /i "CompatTelRunner.exe">NUL && (
    echo CompatTelRunner.exe is running and will be killed.
    taskkill /f /im CompatTelRunner.exe
) || (
    echo Skipping, CompatTelRunner.exe is not running.
)
:: Configure termination of "CompatTelRunner.exe" immediately upon its startup
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe!Debugger"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe'; $data =  '%SYSTEMROOT%\System32\taskkill.exe'; reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe' /v 'Debugger' /t 'REG_SZ' /d "^""$data"^"" /f"
:: Add a rule to prevent the executable "CompatTelRunner.exe" from running via File Explorer
PowerShell -ExecutionPolicy Unrestricted -Command "$executableFilename='CompatTelRunner.exe'; try { $registryPathForDisallowRun='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'; $existingBlockEntries = Get-ItemProperty -Path "^""$registryPathForDisallowRun"^"" -ErrorAction Ignore; $nextFreeRuleIndex = 1; if ($existingBlockEntries) { $existingBlockingRuleForExecutable = $existingBlockEntries.PSObject.Properties | Where-Object { $_.Value -eq $executableFilename }; if ($existingBlockingRuleForExecutable) { $existingBlockingRuleIndexForExecutable = $existingBlockingRuleForExecutable.Name; Write-Output "^""Skipping, no action needed: '$executableFilename' is already blocked under rule index `"^""$existingBlockingRuleIndexForExecutable`"^""."^""; exit 0; }; $occupiedRuleIndexes = $existingBlockEntries.PSObject.Properties | Where-Object { $_.Name -Match '^\d+$' } | Select -ExpandProperty Name; if ($occupiedRuleIndexes) { while ($occupiedRuleIndexes -Contains $nextFreeRuleIndex) { $nextFreeRuleIndex += 1; }; }; }; Write-Output "^""Adding block rule for `"^""$executableFilename`"^"" under rule index `"^""$nextFreeRuleIndex`"^""."^""; if (!(Test-Path $registryPathForDisallowRun)) { New-Item -Path "^""$registryPathForDisallowRun"^"" -Force -ErrorAction Stop | Out-Null; }; New-ItemProperty -Path "^""$registryPathForDisallowRun"^"" -Name "^""$nextFreeRuleIndex"^"" -PropertyType String -Value "^""$executableFilename"^"" ` -ErrorAction Stop | Out-Null; Write-Output "^""Successfully blocked `"^""$executableFilename`"^"" with rule index `"^""$nextFreeRuleIndex`"^""."^""; } catch { Write-Error "^""Failed to block `"^""$executableFilename`"^"": $_"^""; Exit 1; }"
:: Activate the DisallowRun policy to block specified programs from running via File Explorer
PowerShell -ExecutionPolicy Unrestricted -Command "try { $fileExplorerDisallowRunRegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $currentDisallowRunPolicyValue = Get-ItemProperty -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Name 'DisallowRun' -ErrorAction Ignore | Select -ExpandProperty DisallowRun; if ([string]::IsNullOrEmpty($currentDisallowRunPolicyValue)) { Write-Output "^""Creating DisallowRun policy at `"^""$fileExplorerDisallowRunRegistryPath`"^""."^""; if (!(Test-Path $fileExplorerDisallowRunRegistryPath)) { New-Item -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Force -ErrorAction Stop | Out-Null; }; New-ItemProperty -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Name 'DisallowRun' -Value 1 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null; Write-Output 'Successfully activated DisallowRun policy.'; Exit 0; }; if ($currentDisallowRunPolicyValue -eq 1) { Write-Output 'Skipping, no action needed: DisallowRun policy is already in place.'; Exit 0; }; Write-Output 'Updating DisallowRun policy from unexpected value `"^""$currentDisallowRunPolicyValue`"^"" to `"^""1`"^"".'; Set-ItemProperty -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Name 'DisallowRun' -Value 1 -Type DWORD -Force -ErrorAction Stop | Out-Null; Write-Output 'Successfully activated DisallowRun policy.'; } catch { Write-Error "^""Failed to activate DisallowRun policy: $_"^""; Exit 1; }"
:: Soft delete files matching pattern: "%SYSTEMROOT%\System32\CompatTelRunner.exe" with additional permissions 
PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%SYSTEMROOT%\System32\CompatTelRunner.exe"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; $renamedCount   = 0; $skippedCount   = 0; $failedCount    = 0; Add-Type -TypeDefinition "^""using System;`r`nusing System.Runtime.InteropServices;`r`npublic class Privileges {`r`n    [DllImport(`"^""advapi32.dll`"^"", ExactSpelling = true, SetLastError = true)]`r`n    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,`r`n        ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);`r`n    [DllImport(`"^""advapi32.dll`"^"", ExactSpelling = true, SetLastError = true)]`r`n    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);`r`n    [DllImport(`"^""advapi32.dll`"^"", SetLastError = true)]`r`n    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);`r`n    [StructLayout(LayoutKind.Sequential, Pack = 1)]`r`n    internal struct TokPriv1Luid {`r`n        public int Count;`r`n        public long Luid;`r`n        public int Attr;`r`n    }`r`n    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;`r`n    internal const int TOKEN_QUERY = 0x00000008;`r`n    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;`r`n    public static bool AddPrivilege(string privilege) {`r`n        try {`r`n            bool retVal;`r`n            TokPriv1Luid tp;`r`n            IntPtr hproc = GetCurrentProcess();`r`n            IntPtr htok = IntPtr.Zero;`r`n            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);`r`n            tp.Count = 1;`r`n            tp.Luid = 0;`r`n            tp.Attr = SE_PRIVILEGE_ENABLED;`r`n            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);`r`n            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);`r`n            return retVal;`r`n        } catch (Exception ex) {`r`n            throw new Exception(`"^""Failed to adjust token privileges`"^"", ex);`r`n        }`r`n    }`r`n    public static bool RemovePrivilege(string privilege) {`r`n        try {`r`n            bool retVal;`r`n            TokPriv1Luid tp;`r`n            IntPtr hproc = GetCurrentProcess();`r`n            IntPtr htok = IntPtr.Zero;`r`n            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);`r`n            tp.Count = 1;`r`n            tp.Luid = 0;`r`n            tp.Attr = 0;  // This line is changed to revoke the privilege`r`n            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);`r`n            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);`r`n            return retVal;`r`n        } catch (Exception ex) {`r`n            throw new Exception(`"^""Failed to adjust token privileges`"^"", ex);`r`n        }`r`n    }`r`n    [DllImport(`"^""kernel32.dll`"^"", CharSet = CharSet.Auto)]`r`n    public static extern IntPtr GetCurrentProcess();`r`n}"^""; [Privileges]::AddPrivilege('SeRestorePrivilege') | Out-Null; [Privileges]::AddPrivilege('SeTakeOwnershipPrivilege') | Out-Null; $adminSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'; $adminAccount = $adminSid.Translate([System.Security.Principal.NTAccount]); $adminFullControlAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule( $adminAccount, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow ); $foundAbsolutePaths = @(); try { $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) { Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) { if (Test-Path -Path $path -PathType Container) { Write-Host "^""Skipping folder (not its contents): `"^""$path`"^""."^""; $skippedCount++; continue; }; if($revert -eq $true) { if (-not $path.EndsWith('.OLD')) { Write-Host "^""Skipping non-backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; } else { if ($path.EndsWith('.OLD')) { Write-Host "^""Skipping backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; }; $originalFilePath = $path; Write-Host "^""Processing file: `"^""$originalFilePath`"^""."^""; if (-Not (Test-Path $originalFilePath)) { Write-Host "^""Skipping, file `"^""$originalFilePath`"^"" not found."^""; $skippedCount++; exit 0; }; $originalAcl = Get-Acl -Path "^""$originalFilePath"^""; $accessGranted = $false; try { $acl = Get-Acl -Path "^""$originalFilePath"^""; $acl.SetOwner($adminAccount) <# Take Ownership (because file is owned by TrustedInstaller) #>; $acl.AddAccessRule($adminFullControlAccessRule) <# Grant rights to be able to move the file #>; Set-Acl -Path $originalFilePath -AclObject $acl -ErrorAction Stop; $accessGranted = $true; } catch { Write-Warning "^""Failed to grant access to `"^""$originalFilePath`"^"": $($_.Exception.Message)"^""; }; if ($revert -eq $true) { $newFilePath = $originalFilePath.Substring(0, $originalFilePath.Length - 4); } else { $newFilePath = "^""$($originalFilePath).OLD"^""; }; try { Move-Item -LiteralPath "^""$($originalFilePath)"^"" -Destination "^""$newFilePath"^"" -Force -ErrorAction Stop; Write-Host "^""Successfully processed `"^""$originalFilePath`"^""."^""; $renamedCount++; if ($accessGranted) { try { Set-Acl -Path $newFilePath -AclObject $originalAcl -ErrorAction Stop; } catch { Write-Warning "^""Failed to restore access on `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; }; }; } catch { Write-Error "^""Failed to rename `"^""$originalFilePath`"^"" to `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; $failedCount++; if ($accessGranted) { try { Set-Acl -Path $originalFilePath -AclObject $originalAcl -ErrorAction Stop; } catch { Write-Warning "^""Failed to restore access on `"^""$originalFilePath`"^"": $($_.Exception.Message)"^""; }; }; }; }; if (($renamedCount -gt 0) -or ($skippedCount -gt 0)) { Write-Host "^""Successfully processed $renamedCount items and skipped $skippedCount items."^""; }; if ($failedCount -gt 0) { Write-Warning "^""Failed to process $($failedCount) items."^""; }; [Privileges]::RemovePrivilege('SeRestorePrivilege') | Out-Null; [Privileges]::RemovePrivilege('SeTakeOwnershipPrivilege') | Out-Null"
:: ----------------------------------------------------------


:: Disable program data collection and reporting (`ProgramDataUpdater`)
echo --- Disable program data collection and reporting (`ProgramDataUpdater`)
:: Disable scheduled task(s): `\Microsoft\Windows\Application Experience\ProgramDataUpdater`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Application Experience\'; $taskNamePattern='ProgramDataUpdater'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable application usage tracking (`AitAgent`)------
:: ----------------------------------------------------------
echo --- Disable application usage tracking (`AitAgent`)
:: Disable scheduled task(s): `\Microsoft\Windows\Application Experience\AitAgent`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Application Experience\'; $taskNamePattern='AitAgent'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: Disable startup application data tracking (`StartupAppTask`)
echo --- Disable startup application data tracking (`StartupAppTask`)
:: Disable scheduled task(s): `\Microsoft\Windows\Application Experience\StartupAppTask`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Application Experience\'; $taskNamePattern='StartupAppTask'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Disable software compatibility updates (`PcaPatchDbTask`)-
:: ----------------------------------------------------------
echo --- Disable software compatibility updates (`PcaPatchDbTask`)
:: Disable scheduled task(s): `\Microsoft\Windows\Application Experience\PcaPatchDbTask`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Application Experience\'; $taskNamePattern='PcaPatchDbTask'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: Disable compatibility adjustment data sharing (`SdbinstMergeDbTask`)
echo --- Disable compatibility adjustment data sharing (`SdbinstMergeDbTask`)
:: Disable scheduled task(s): `\Microsoft\Windows\Application Experience\SdbinstMergeDbTask`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Application Experience\'; $taskNamePattern='SdbinstMergeDbTask'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; $taskFullPath = "^""$($task.TaskPath)$($task.TaskName)"^""; $adminSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'; $adminAccount = $adminSid.Translate([System.Security.Principal.NTAccount]); $taskFilePath="^""$($env:SYSTEMROOT)\System32\Tasks$($task.TaskPath)$($task.TaskName)"^""; $accessGranted = $false; try { $originalAcl= Get-Acl -Path $taskFilePath -ErrorAction Stop; $modifiedAcl= Get-Acl -Path $taskFilePath -ErrorAction Stop; $modifiedAcl.SetOwner($adminAccount); $taskFileAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule( $adminAccount, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow ); $modifiedAcl.SetAccessRule($taskFileAccessRule); Set-Acl -Path $taskFilePath -AclObject $modifiedAcl -ErrorAction Stop; Write-Host "^""Successfully granted permissions for `"^""$taskFullPath`"^"" ."^""; $accessGranted = $true; } catch { Write-Warning "^""Failed to grant access to `"^""$taskFullPath`"^"": $($_.Exception.Message)"^""; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; if ($accessGranted) { try { Set-Acl -Path $taskFilePath -AclObject $originalAcl -ErrorAction Stop; Write-Host "^""Successfully restored permissions for `"^""$taskFullPath`"^"" ."^""; } catch { Write-Warning "^""Failed to restore access on `"^""$taskFilePath`"^"": $($_.Exception.Message)"^""; }; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable application backup data gathering (`MareBackup`)-
:: ----------------------------------------------------------
echo --- Disable application backup data gathering (`MareBackup`)
:: Disable scheduled task(s): `\Microsoft\Windows\Application Experience\MareBackup`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Windows\Application Experience\'; $taskNamePattern='MareBackup'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable "Program Compatibility Assistant (PCA)" feature--
:: ----------------------------------------------------------
echo --- Disable "Program Compatibility Assistant (PCA)" feature
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat!DisablePCA"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'DisablePCA' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable "Program Compatibility Assistant Service" (`PcaSvc`)
echo --- Disable "Program Compatibility Assistant Service" (`PcaSvc`)
:: Disable service(s): `PcaSvc`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'PcaSvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Cortana during search---------------
:: ----------------------------------------------------------
echo --- Disable Cortana during search
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!AllowCortana"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'AllowCortana' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable Cortana experience----------------
:: ----------------------------------------------------------
echo --- Disable Cortana experience
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana!value"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana' /v 'value' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Cortana's access to cloud services such as OneDrive and SharePoint
echo --- Disable Cortana's access to cloud services such as OneDrive and SharePoint
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!AllowCloudSearch"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'AllowCloudSearch' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: Disable Cortana speech interaction while the system is locked
echo --- Disable Cortana speech interaction while the system is locked
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!AllowCortanaAboveLock"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'AllowCortanaAboveLock' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable participation in Cortana data collection-----
:: ----------------------------------------------------------
echo --- Disable participation in Cortana data collection
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\Search!CortanaConsent"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search' /v 'CortanaConsent' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable enabling of Cortana----------------
:: ----------------------------------------------------------
echo --- Disable enabling of Cortana
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\Search!CanCortanaBeEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search' /v 'CanCortanaBeEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Cortana in start menu---------------
:: ----------------------------------------------------------
echo --- Disable Cortana in start menu
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search!CortanaEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'CortanaEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search!CortanaEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'CortanaEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Remove "Cortana" icon from taskbar------------
:: ----------------------------------------------------------
echo --- Remove "Cortana" icon from taskbar
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced!ShowCortanaButton"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowCortanaButton' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Cortana in ambient mode--------------
:: ----------------------------------------------------------
echo --- Disable Cortana in ambient mode
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search!CortanaInAmbientMode"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'CortanaInAmbientMode' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable indexing of encrypted items------------
:: ----------------------------------------------------------
echo --- Disable indexing of encrypted items
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!AllowIndexingEncryptedStoresOrItems"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'AllowIndexingEncryptedStoresOrItems' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable automatic language detection when indexing----
:: ----------------------------------------------------------
echo --- Disable automatic language detection when indexing
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!AlwaysUseAutoLangDetection"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'AlwaysUseAutoLangDetection' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable remote access to search index-----------
:: ----------------------------------------------------------
echo --- Disable remote access to search index
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!PreventRemoteQueries"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'PreventRemoteQueries' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable iFilters and protocol handlers----------
:: ----------------------------------------------------------
echo --- Disable iFilters and protocol handlers
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!PreventUnwantedAddIns"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  ' '; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'PreventUnwantedAddIns' /t 'REG_SZ' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: Disable Bing search and recent search suggestions (breaks search history)
echo --- Disable Bing search and recent search suggestions (breaks search history)
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer!DisableSearchBoxSuggestions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableSearchBoxSuggestions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search!DisableSearchBoxSuggestions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; $data =  '1'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'DisableSearchBoxSuggestions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Bing search in start menu-------------
:: ----------------------------------------------------------
echo --- Disable Bing search in start menu
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search!BingSearchEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'BingSearchEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable web search in search bar-------------
:: ----------------------------------------------------------
echo --- Disable web search in search bar
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!DisableWebSearch"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'DisableWebSearch' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable web results in Windows Search-----------
:: ----------------------------------------------------------
echo --- Disable web results in Windows Search
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!ConnectedSearchUseWeb"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'ConnectedSearchUseWeb' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!ConnectedSearchUseWebOverMeteredConnections"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'ConnectedSearchUseWebOverMeteredConnections' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Windows search highlights-------------
:: ----------------------------------------------------------
echo --- Disable Windows search highlights
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search!EnableDynamicContentInWSB"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'EnableDynamicContentInWSB' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings!IsDynamicSearchBoxEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; $data =  '1'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings' /v 'IsDynamicSearchBoxEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Cortana's history display-------------
:: ----------------------------------------------------------
echo --- Disable Cortana's history display
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search!HistoryViewEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'HistoryViewEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Cortana's device history usage----------
:: ----------------------------------------------------------
echo --- Disable Cortana's device history usage
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search!DeviceHistoryEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'DeviceHistoryEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable "Hey Cortana" voice activation----------
:: ----------------------------------------------------------
echo --- Disable "Hey Cortana" voice activation
:: Set the registry value: "HKCU\Software\Microsoft\Speech_OneCore\Preferences!VoiceActivationOn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Speech_OneCore\Preferences'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Speech_OneCore\Preferences' /v 'VoiceActivationOn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\Software\Microsoft\Speech_OneCore\Preferences!VoiceActivationDefaultOn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Microsoft\Speech_OneCore\Preferences'; $data =  '0'; reg add 'HKLM\Software\Microsoft\Speech_OneCore\Preferences' /v 'VoiceActivationDefaultOn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Cortana keyboard shortcut (**Windows logo key** + **C**)
echo --- Disable Cortana keyboard shortcut (**Windows logo key** + **C**)
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search!VoiceShortcut"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' /v 'VoiceShortcut' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting explorer.exe for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'This script will not take effect until you restart explorer.exe. You can restart explorer.exe by restarting your computer or by running following on command prompt: `taskkill /f /im explorer.exe & start explorer`.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Cortana on locked device-------------
:: ----------------------------------------------------------
echo --- Disable Cortana on locked device
:: Set the registry value: "HKCU\Software\Microsoft\Speech_OneCore\Preferences!VoiceActivationEnableAboveLockscreen"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Speech_OneCore\Preferences'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Speech_OneCore\Preferences' /v 'VoiceActivationEnableAboveLockscreen' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable automatic update of speech data----------
:: ----------------------------------------------------------
echo --- Disable automatic update of speech data
:: Set the registry value: "HKCU\Software\Microsoft\Speech_OneCore\Preferences!ModelDownloadAllowed"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Speech_OneCore\Preferences'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Speech_OneCore\Preferences' /v 'ModelDownloadAllowed' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Cortana voice support during Windows setup----
:: ----------------------------------------------------------
echo --- Disable Cortana voice support during Windows setup
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE!DisableVoice"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v 'DisableVoice' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable Windows Tips-------------------
:: ----------------------------------------------------------
echo --- Disable Windows Tips
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent!DisableSoftLanding"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableSoftLanding' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Windows Spotlight (shows random wallpapers on lock screen)
echo --- Disable Windows Spotlight (shows random wallpapers on lock screen)
:: Set the registry value: "HKLM\Software\Policies\Microsoft\Windows\CloudContent!DisableWindowsSpotlightFeatures"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\Windows\CloudContent'; $data =  '1'; reg add 'HKLM\Software\Policies\Microsoft\Windows\CloudContent' /v 'DisableWindowsSpotlightFeatures' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Microsoft Consumer Experiences----------
:: ----------------------------------------------------------
echo --- Disable Microsoft Consumer Experiences
:: Set the registry value: "HKLM\Software\Policies\Microsoft\Windows\CloudContent!DisableWindowsConsumerFeatures"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\Windows\CloudContent'; $data =  '1'; reg add 'HKLM\Software\Policies\Microsoft\Windows\CloudContent' /v 'DisableWindowsConsumerFeatures' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable participation in Visual Studio Customer Experience Improvement Program (VSCEIP)
echo --- Disable participation in Visual Studio Customer Experience Improvement Program (VSCEIP)
:: Set the registry value: "HKLM\Software\Policies\Microsoft\VisualStudio\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\Software\Policies\Microsoft\VisualStudio\SQM'; $data =  '0'; reg add 'HKLM\Software\Policies\Microsoft\VisualStudio\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM!OptIn"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM' /v 'OptIn' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Visual Studio telemetry--------------
:: ----------------------------------------------------------
echo --- Disable Visual Studio telemetry
:: Set the registry value: "HKCU\Software\Microsoft\VisualStudio\Telemetry!TurnOffSwitch"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\VisualStudio\Telemetry'; $data =  '1'; reg add 'HKCU\Software\Microsoft\VisualStudio\Telemetry' /v 'TurnOffSwitch' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Visual Studio feedback--------------
:: ----------------------------------------------------------
echo --- Disable Visual Studio feedback
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback!DisableFeedbackDialog"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback' /v 'DisableFeedbackDialog' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback!DisableEmailInput"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback' /v 'DisableEmailInput' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback!DisableScreenshotCapture"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback' /v 'DisableScreenshotCapture' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable "Visual Studio Standard Collector Service"----
:: ----------------------------------------------------------
echo --- Disable "Visual Studio Standard Collector Service"
:: Disable service(s): `VSStandardCollectorService150`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'VSStandardCollectorService150'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Diagnostics Hub log collection----------
:: ----------------------------------------------------------
echo --- Disable Diagnostics Hub log collection
:: Delete the registry value "LogLevel" from the key "HKLM\Software\Microsoft\VisualStudio\DiagnosticsHub" 
PowerShell -ExecutionPolicy Unrestricted -Command "$keyName = 'HKLM\Software\Microsoft\VisualStudio\DiagnosticsHub'; $valueName = 'LogLevel'; $hive = $keyName.Split('\')[0]; $path = "^""$($hive):$($keyName.Substring($hive.Length))"^""; Write-Host "^""Removing the registry value '$valueName' from '$path'."^""; if (-Not (Test-Path -LiteralPath $path)) { Write-Host 'Skipping, no action needed, registry key does not exist.'; Exit 0; }; $existingValueNames = (Get-ItemProperty -LiteralPath $path).PSObject.Properties.Name; if (-Not ($existingValueNames -Contains $valueName)) { Write-Host 'Skipping, no action needed, registry value does not exist.'; Exit 0; }; try { if ($valueName -ieq '(default)') { Write-Host 'Removing the default value.'; $(Get-Item -LiteralPath $path).OpenSubKey('', $true).DeleteValue(''); } else { Remove-ItemProperty -LiteralPath $path -Name $valueName -Force -ErrorAction Stop; }; Write-Host 'Successfully removed the registry value.'; } catch { Write-Error "^""Failed to remove the registry value: $($_.Exception.Message)"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Disable participation in IntelliCode data collection---
:: ----------------------------------------------------------
echo --- Disable participation in IntelliCode data collection
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode!DisableRemoteAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode' /v 'DisableRemoteAnalysis' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode!DisableRemoteAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode'; $data =  '1'; reg add 'HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode' /v 'DisableRemoteAnalysis' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode!DisableRemoteAnalysis"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode'; $data =  '1'; reg add 'HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode' /v 'DisableRemoteAnalysis' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Remove Nvidia telemetry packages-------------
:: ----------------------------------------------------------
echo --- Remove Nvidia telemetry packages
if exist "%ProgramFiles%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Remove Nvidia telemetry components------------
:: ----------------------------------------------------------
echo --- Remove Nvidia telemetry components
:: Soft delete files matching pattern: "%PROGRAMFILES(X86)%\NVIDIA Corporation\NvTelemetry\*"  
PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%PROGRAMFILES(X86)%\NVIDIA Corporation\NvTelemetry\*"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; $renamedCount   = 0; $skippedCount   = 0; $failedCount    = 0; $foundAbsolutePaths = @(); Write-Host 'Iterating files and directories recursively.'; try { $foundAbsolutePaths += @(; Get-ChildItem -Path $expandedPath -Force -Recurse -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; try { $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) { Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) { if (Test-Path -Path $path -PathType Container) { Write-Host "^""Skipping folder (not its contents): `"^""$path`"^""."^""; $skippedCount++; continue; }; if($revert -eq $true) { if (-not $path.EndsWith('.OLD')) { Write-Host "^""Skipping non-backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; } else { if ($path.EndsWith('.OLD')) { Write-Host "^""Skipping backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; }; $originalFilePath = $path; Write-Host "^""Processing file: `"^""$originalFilePath`"^""."^""; if (-Not (Test-Path $originalFilePath)) { Write-Host "^""Skipping, file `"^""$originalFilePath`"^"" not found."^""; $skippedCount++; exit 0; }; if ($revert -eq $true) { $newFilePath = $originalFilePath.Substring(0, $originalFilePath.Length - 4); } else { $newFilePath = "^""$($originalFilePath).OLD"^""; }; try { Move-Item -LiteralPath "^""$($originalFilePath)"^"" -Destination "^""$newFilePath"^"" -Force -ErrorAction Stop; Write-Host "^""Successfully processed `"^""$originalFilePath`"^""."^""; $renamedCount++; } catch { Write-Error "^""Failed to rename `"^""$originalFilePath`"^"" to `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; $failedCount++; }; }; if (($renamedCount -gt 0) -or ($skippedCount -gt 0)) { Write-Host "^""Successfully processed $renamedCount items and skipped $skippedCount items."^""; }; if ($failedCount -gt 0) { Write-Warning "^""Failed to process $($failedCount) items."^""; }"
:: Soft delete files matching pattern: "%PROGRAMFILES%\NVIDIA Corporation\NvTelemetry\*"  
PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%PROGRAMFILES%\NVIDIA Corporation\NvTelemetry\*"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; $renamedCount   = 0; $skippedCount   = 0; $failedCount    = 0; $foundAbsolutePaths = @(); Write-Host 'Iterating files and directories recursively.'; try { $foundAbsolutePaths += @(; Get-ChildItem -Path $expandedPath -Force -Recurse -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; try { $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) { Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) { if (Test-Path -Path $path -PathType Container) { Write-Host "^""Skipping folder (not its contents): `"^""$path`"^""."^""; $skippedCount++; continue; }; if($revert -eq $true) { if (-not $path.EndsWith('.OLD')) { Write-Host "^""Skipping non-backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; } else { if ($path.EndsWith('.OLD')) { Write-Host "^""Skipping backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; }; $originalFilePath = $path; Write-Host "^""Processing file: `"^""$originalFilePath`"^""."^""; if (-Not (Test-Path $originalFilePath)) { Write-Host "^""Skipping, file `"^""$originalFilePath`"^"" not found."^""; $skippedCount++; exit 0; }; if ($revert -eq $true) { $newFilePath = $originalFilePath.Substring(0, $originalFilePath.Length - 4); } else { $newFilePath = "^""$($originalFilePath).OLD"^""; }; try { Move-Item -LiteralPath "^""$($originalFilePath)"^"" -Destination "^""$newFilePath"^"" -Force -ErrorAction Stop; Write-Host "^""Successfully processed `"^""$originalFilePath`"^""."^""; $renamedCount++; } catch { Write-Error "^""Failed to rename `"^""$originalFilePath`"^"" to `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; $failedCount++; }; }; if (($renamedCount -gt 0) -or ($skippedCount -gt 0)) { Write-Host "^""Successfully processed $renamedCount items and skipped $skippedCount items."^""; }; if ($failedCount -gt 0) { Write-Warning "^""Failed to process $($failedCount) items."^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Nvidia telemetry drivers-------------
:: ----------------------------------------------------------
echo --- Disable Nvidia telemetry drivers
:: Soft delete files matching pattern: "%SYSTEMROOT%\System32\DriverStore\FileRepository\NvTelemetry*.dll"  
PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%SYSTEMROOT%\System32\DriverStore\FileRepository\NvTelemetry*.dll"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; $renamedCount   = 0; $skippedCount   = 0; $failedCount    = 0; $foundAbsolutePaths = @(); Write-Host 'Iterating files and directories recursively.'; try { $foundAbsolutePaths += @(; Get-ChildItem -Path $expandedPath -Force -Recurse -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; try { $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) { Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) { if (Test-Path -Path $path -PathType Container) { Write-Host "^""Skipping folder (not its contents): `"^""$path`"^""."^""; $skippedCount++; continue; }; if($revert -eq $true) { if (-not $path.EndsWith('.OLD')) { Write-Host "^""Skipping non-backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; } else { if ($path.EndsWith('.OLD')) { Write-Host "^""Skipping backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; }; $originalFilePath = $path; Write-Host "^""Processing file: `"^""$originalFilePath`"^""."^""; if (-Not (Test-Path $originalFilePath)) { Write-Host "^""Skipping, file `"^""$originalFilePath`"^"" not found."^""; $skippedCount++; exit 0; }; if ($revert -eq $true) { $newFilePath = $originalFilePath.Substring(0, $originalFilePath.Length - 4); } else { $newFilePath = "^""$($originalFilePath).OLD"^""; }; try { Move-Item -LiteralPath "^""$($originalFilePath)"^"" -Destination "^""$newFilePath"^"" -Force -ErrorAction Stop; Write-Host "^""Successfully processed `"^""$originalFilePath`"^""."^""; $renamedCount++; } catch { Write-Error "^""Failed to rename `"^""$originalFilePath`"^"" to `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; $failedCount++; }; }; if (($renamedCount -gt 0) -or ($skippedCount -gt 0)) { Write-Host "^""Successfully processed $renamedCount items and skipped $skippedCount items."^""; }; if ($failedCount -gt 0) { Write-Warning "^""Failed to process $($failedCount) items."^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable participation in Nvidia telemetry---------
:: ----------------------------------------------------------
echo --- Disable participation in Nvidia telemetry
:: Set the registry value: "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client!OptInOrOutPreference"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client'; $data =  '0'; reg add 'HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client' /v 'OptInOrOutPreference' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS!EnableRID44231"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS'; $data =  '0'; reg add 'HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS' /v 'EnableRID44231' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS!EnableRID64640"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS'; $data =  '0'; reg add 'HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS' /v 'EnableRID64640' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS!EnableRID66610"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS'; $data =  '0'; reg add 'HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS' /v 'EnableRID66610' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup!SendTelemetryData"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup' /v 'SendTelemetryData' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable "Nvidia Telemetry Container" service-------
:: ----------------------------------------------------------
echo --- Disable "Nvidia Telemetry Container" service
:: Disable service(s): `NvTelemetryContainer`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'NvTelemetryContainer'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Visual Studio Code telemetry-----------
:: ----------------------------------------------------------
echo --- Disable Visual Studio Code telemetry
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='telemetry.enableTelemetry'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) { Write-Host "^""Skipping, no updates. Settings file was not at `"^""$jsonFilePath`"^""."^""; exit 0; }; try { $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch { throw "^""Error, failed to read the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) { Write-Host "^""Settings file is empty. Treating it as default empty JSON object."^""; $fileContent = "^""{}"^""; }; try { $json = $fileContent | ConvertFrom-Json; } catch { throw "^""Error, invalid JSON format in the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) { Write-Host "^""Skipping, `"^""$settingKey`"^"" is already configured as `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Successfully applied the setting to the file: `"^""$jsonFilePath`"^""."^"""
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Visual Studio Code crash reporting--------
:: ----------------------------------------------------------
echo --- Disable Visual Studio Code crash reporting
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='telemetry.enableCrashReporter'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) { Write-Host "^""Skipping, no updates. Settings file was not at `"^""$jsonFilePath`"^""."^""; exit 0; }; try { $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch { throw "^""Error, failed to read the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) { Write-Host "^""Settings file is empty. Treating it as default empty JSON object."^""; $fileContent = "^""{}"^""; }; try { $json = $fileContent | ConvertFrom-Json; } catch { throw "^""Error, invalid JSON format in the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) { Write-Host "^""Skipping, `"^""$settingKey`"^"" is already configured as `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Successfully applied the setting to the file: `"^""$jsonFilePath`"^""."^"""
:: ----------------------------------------------------------


:: Disable online experiments by Microsoft in Visual Studio Code
echo --- Disable online experiments by Microsoft in Visual Studio Code
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='workbench.enableExperiments'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) { Write-Host "^""Skipping, no updates. Settings file was not at `"^""$jsonFilePath`"^""."^""; exit 0; }; try { $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch { throw "^""Error, failed to read the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) { Write-Host "^""Settings file is empty. Treating it as default empty JSON object."^""; $fileContent = "^""{}"^""; }; try { $json = $fileContent | ConvertFrom-Json; } catch { throw "^""Error, invalid JSON format in the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) { Write-Host "^""Skipping, `"^""$settingKey`"^"" is already configured as `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Successfully applied the setting to the file: `"^""$jsonFilePath`"^""."^"""
:: ----------------------------------------------------------


:: Disable Visual Studio Code automatic updates in favor of manual updates
echo --- Disable Visual Studio Code automatic updates in favor of manual updates
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='update.mode'; $settingValue='manual'; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) { Write-Host "^""Skipping, no updates. Settings file was not at `"^""$jsonFilePath`"^""."^""; exit 0; }; try { $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch { throw "^""Error, failed to read the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) { Write-Host "^""Settings file is empty. Treating it as default empty JSON object."^""; $fileContent = "^""{}"^""; }; try { $json = $fileContent | ConvertFrom-Json; } catch { throw "^""Error, invalid JSON format in the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) { Write-Host "^""Skipping, `"^""$settingKey`"^"" is already configured as `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Successfully applied the setting to the file: `"^""$jsonFilePath`"^""."^"""
:: ----------------------------------------------------------


:: Disable fetching release notes from Microsoft servers after an update
echo --- Disable fetching release notes from Microsoft servers after an update
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='update.showReleaseNotes'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) { Write-Host "^""Skipping, no updates. Settings file was not at `"^""$jsonFilePath`"^""."^""; exit 0; }; try { $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch { throw "^""Error, failed to read the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) { Write-Host "^""Settings file is empty. Treating it as default empty JSON object."^""; $fileContent = "^""{}"^""; }; try { $json = $fileContent | ConvertFrom-Json; } catch { throw "^""Error, invalid JSON format in the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) { Write-Host "^""Skipping, `"^""$settingKey`"^"" is already configured as `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Successfully applied the setting to the file: `"^""$jsonFilePath`"^""."^"""
:: ----------------------------------------------------------


:: Automatically check extensions from Microsoft online service
echo --- Automatically check extensions from Microsoft online service
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='extensions.autoCheckUpdates'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) { Write-Host "^""Skipping, no updates. Settings file was not at `"^""$jsonFilePath`"^""."^""; exit 0; }; try { $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch { throw "^""Error, failed to read the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) { Write-Host "^""Settings file is empty. Treating it as default empty JSON object."^""; $fileContent = "^""{}"^""; }; try { $json = $fileContent | ConvertFrom-Json; } catch { throw "^""Error, invalid JSON format in the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) { Write-Host "^""Skipping, `"^""$settingKey`"^"" is already configured as `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Successfully applied the setting to the file: `"^""$jsonFilePath`"^""."^"""
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Fetch recommendations from Microsoft only on demand----
:: ----------------------------------------------------------
echo --- Fetch recommendations from Microsoft only on demand
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='extensions.showRecommendationsOnlyOnDemand'; $settingValue=$true; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) { Write-Host "^""Skipping, no updates. Settings file was not at `"^""$jsonFilePath`"^""."^""; exit 0; }; try { $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch { throw "^""Error, failed to read the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) { Write-Host "^""Settings file is empty. Treating it as default empty JSON object."^""; $fileContent = "^""{}"^""; }; try { $json = $fileContent | ConvertFrom-Json; } catch { throw "^""Error, invalid JSON format in the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) { Write-Host "^""Skipping, `"^""$settingKey`"^"" is already configured as `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Successfully applied the setting to the file: `"^""$jsonFilePath`"^""."^"""
:: ----------------------------------------------------------


:: Disable automatic fetching of remote repositories in Visual Studio Code
echo --- Disable automatic fetching of remote repositories in Visual Studio Code
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='git.autofetch'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) { Write-Host "^""Skipping, no updates. Settings file was not at `"^""$jsonFilePath`"^""."^""; exit 0; }; try { $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch { throw "^""Error, failed to read the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) { Write-Host "^""Settings file is empty. Treating it as default empty JSON object."^""; $fileContent = "^""{}"^""; }; try { $json = $fileContent | ConvertFrom-Json; } catch { throw "^""Error, invalid JSON format in the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) { Write-Host "^""Skipping, `"^""$settingKey`"^"" is already configured as `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Successfully applied the setting to the file: `"^""$jsonFilePath`"^""."^"""
:: ----------------------------------------------------------


:: Disable fetching package information from NPM and Bower in Visual Studio Code
echo --- Disable fetching package information from NPM and Bower in Visual Studio Code
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='npm.fetchOnlinePackageInfo'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) { Write-Host "^""Skipping, no updates. Settings file was not at `"^""$jsonFilePath`"^""."^""; exit 0; }; try { $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch { throw "^""Error, failed to read the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) { Write-Host "^""Settings file is empty. Treating it as default empty JSON object."^""; $fileContent = "^""{}"^""; }; try { $json = $fileContent | ConvertFrom-Json; } catch { throw "^""Error, invalid JSON format in the settings file: `"^""$jsonFilePath`"^"". Error: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) { Write-Host "^""Skipping, `"^""$settingKey`"^"" is already configured as `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Successfully applied the setting to the file: `"^""$jsonFilePath`"^""."^"""
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Microsoft Office logging-------------
:: ----------------------------------------------------------
echo --- Disable Microsoft Office logging
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail!EnableLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail' /v 'EnableLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail!EnableLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail' /v 'EnableLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar!EnableCalendarLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar' /v 'EnableCalendarLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar!EnableCalendarLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar' /v 'EnableCalendarLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options!EnableLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options' /v 'EnableLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options!EnableLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options' /v 'EnableLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM!EnableLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM'; $data =  '0'; reg add 'HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM' /v 'EnableLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM!EnableLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM'; $data =  '0'; reg add 'HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM' /v 'EnableLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM!EnableUpload"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM'; $data =  '0'; reg add 'HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM' /v 'EnableUpload' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM!EnableUpload"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM'; $data =  '0'; reg add 'HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM' /v 'EnableUpload' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Microsoft Office client telemetry---------
:: ----------------------------------------------------------
echo --- Disable Microsoft Office client telemetry
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry!DisableTelemetry"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry'; $data =  '1'; reg add 'HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry' /v 'DisableTelemetry' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\ClientTelemetry!DisableTelemetry"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\15.0\Common\ClientTelemetry'; $data =  '1'; reg add 'HKCU\SOFTWARE\Microsoft\Office\15.0\Common\ClientTelemetry' /v 'DisableTelemetry' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry!DisableTelemetry"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry'; $data =  '1'; reg add 'HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry' /v 'DisableTelemetry' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry!VerboseLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry' /v 'VerboseLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\ClientTelemetry!VerboseLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\15.0\Common\ClientTelemetry'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\15.0\Common\ClientTelemetry' /v 'VerboseLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry!VerboseLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry' /v 'VerboseLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable user participation in Office Customer Experience Improvement Program (CEIP)
echo --- Disable user participation in Office Customer Experience Improvement Program (CEIP)
:: Set the registry value: "HKCU\Software\Policies\Microsoft\Office\15.0\Common!QMEnable"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Policies\Microsoft\Office\15.0\Common'; $data =  '0'; reg add 'HKCU\Software\Policies\Microsoft\Office\15.0\Common' /v 'QMEnable' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Policies\Microsoft\Office\16.0\Common!QMEnable"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Policies\Microsoft\Office\16.0\Common'; $data =  '0'; reg add 'HKCU\Software\Policies\Microsoft\Office\16.0\Common' /v 'QMEnable' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Microsoft Office feedback-------------
:: ----------------------------------------------------------
echo --- Disable Microsoft Office feedback
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Microsoft Office telemetry agent---------
:: ----------------------------------------------------------
echo --- Disable Microsoft Office telemetry agent
:: Disable scheduled task(s): `\Microsoft\Office\OfficeTelemetryAgentFallBack`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Office\'; $taskNamePattern='OfficeTelemetryAgentFallBack'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\Microsoft\Office\OfficeTelemetryAgentFallBack2016`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Office\'; $taskNamePattern='OfficeTelemetryAgentFallBack2016'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\Microsoft\Office\OfficeTelemetryAgentLogOn`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Office\'; $taskNamePattern='OfficeTelemetryAgentLogOn'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\Microsoft\Office\OfficeTelemetryAgentLogOn2016`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Office\'; $taskNamePattern='OfficeTelemetryAgentLogOn2016'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable "Microsoft Office Subscription Heartbeat" task--
:: ----------------------------------------------------------
echo --- Disable "Microsoft Office Subscription Heartbeat" task
:: Disable scheduled task(s): `\Microsoft\Office\Office 15 Subscription Heartbeat`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Microsoft\Office\'; $taskNamePattern='Office 15 Subscription Heartbeat'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable "Google Update Service" services---------
:: ----------------------------------------------------------
echo --- Disable "Google Update Service" services
:: Disable service(s): `gupdate`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'gupdate'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: Disable service(s): `gupdatem`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'gupdatem'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: Disable Google automatic updates scheduled tasks (breaks Google Credential Provider)
echo --- Disable Google automatic updates scheduled tasks (breaks Google Credential Provider)
:: Disable scheduled task(s): `\GoogleUpdateTaskMachineCore`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='GoogleUpdateTaskMachineCore'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\GoogleUpdateTaskMachineUA`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='GoogleUpdateTaskMachineUA'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\GoogleUpdateTaskMachineCore{*}`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='GoogleUpdateTaskMachineCore{*}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\GoogleUpdateTaskMachineUA{*}`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='GoogleUpdateTaskMachineUA{*}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable "Adobe Acrobat Update Service" service------
:: ----------------------------------------------------------
echo --- Disable "Adobe Acrobat Update Service" service
:: Disable service(s): `AdobeARMservice`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'AdobeARMservice'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable "Adobe Update Service" service----------
:: ----------------------------------------------------------
echo --- Disable "Adobe Update Service" service
:: Disable service(s): `adobeupdateservice`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'adobeupdateservice'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable "Adobe Acrobat Update Task" scheduled task----
:: ----------------------------------------------------------
echo --- Disable "Adobe Acrobat Update Task" scheduled task
:: Disable scheduled task(s): `\Adobe Acrobat Update Task`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='Adobe Acrobat Update Task'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable "Dropbox Update Service" services---------
:: ----------------------------------------------------------
echo --- Disable "Dropbox Update Service" services
:: Disable service(s): `dbupdate`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'dbupdate'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: Disable service(s): `dbupdatem`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'dbupdatem'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Dropbox automatic updates scheduled tasks-----
:: ----------------------------------------------------------
echo --- Disable Dropbox automatic updates scheduled tasks
:: Disable scheduled task(s): `\DropboxUpdateTaskMachineUA`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='DropboxUpdateTaskMachineUA'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\DropboxUpdateTaskMachineCore`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='DropboxUpdateTaskMachineCore'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable sending Windows Media Player statistics------
:: ----------------------------------------------------------
echo --- Disable sending Windows Media Player statistics
:: Set the registry value: "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences!UsageTracking"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences'; $data =  '0'; reg add 'HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences' /v 'UsageTracking' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable metadata retrieval----------------
:: ----------------------------------------------------------
echo --- Disable metadata retrieval
:: Set the registry value: "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer!PreventCDDVDMetadataRetrieval"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Policies\Microsoft\WindowsMediaPlayer'; $data =  '1'; reg add 'HKCU\Software\Policies\Microsoft\WindowsMediaPlayer' /v 'PreventCDDVDMetadataRetrieval' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer!PreventMusicFileMetadataRetrieval"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Policies\Microsoft\WindowsMediaPlayer'; $data =  '1'; reg add 'HKCU\Software\Policies\Microsoft\WindowsMediaPlayer' /v 'PreventMusicFileMetadataRetrieval' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer!PreventRadioPresetsRetrieval"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Policies\Microsoft\WindowsMediaPlayer'; $data =  '1'; reg add 'HKCU\Software\Policies\Microsoft\WindowsMediaPlayer' /v 'PreventRadioPresetsRetrieval' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\WMDRM!DisableOnline"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\WMDRM'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\WMDRM' /v 'DisableOnline' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable "Windows Media Player Network Sharing Service" (`WMPNetworkSvc`)
echo --- Disable "Windows Media Player Network Sharing Service" (`WMPNetworkSvc`)
:: Disable service(s): `WMPNetworkSvc`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'WMPNetworkSvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable "NVIDIA Telemetry Report" task----------
:: ----------------------------------------------------------
echo --- Disable "NVIDIA Telemetry Report" task
:: Disable scheduled task(s): `\NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable "NVIDIA Telemetry Report on Logon" task------
:: ----------------------------------------------------------
echo --- Disable "NVIDIA Telemetry Report on Logon" task
:: Disable scheduled task(s): `\NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable "NVIDIA telemetry monitor" task----------
:: ----------------------------------------------------------
echo --- Disable "NVIDIA telemetry monitor" task
:: Disable scheduled task(s): `\NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable Edge Follow feature----------------
:: ----------------------------------------------------------
echo --- Disable Edge Follow feature
:: Configure "EdgeFollowEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeFollowEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeFollowEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Edge Shopping Assistant--------------
:: ----------------------------------------------------------
echo --- Disable Edge Shopping Assistant
:: Configure "EdgeShoppingAssistantEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeShoppingAssistantEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeShoppingAssistantEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Edge Search bar on desktop------------
:: ----------------------------------------------------------
echo --- Disable Edge Search bar on desktop
:: Configure "WebWidgetAllowed" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!WebWidgetAllowed"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'WebWidgetAllowed' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "WebWidgetIsEnabledOnStartup" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!WebWidgetIsEnabledOnStartup"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'WebWidgetIsEnabledOnStartup' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "SearchbarAllowed" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SearchbarAllowed"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SearchbarAllowed' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "SearchbarIsEnabledOnStartup" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SearchbarIsEnabledOnStartup"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SearchbarIsEnabledOnStartup' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Edge Microsoft Rewards--------------
:: ----------------------------------------------------------
echo --- Disable Edge Microsoft Rewards
:: Configure "ShowMicrosoftRewards" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ShowMicrosoftRewards"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ShowMicrosoftRewards' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge Bing suggestions in address bar-------
:: ----------------------------------------------------------
echo --- Disable Edge Bing suggestions in address bar
:: Configure "AddressBarMicrosoftSearchInBingProviderEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AddressBarMicrosoftSearchInBingProviderEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AddressBarMicrosoftSearchInBingProviderEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge "Find on Page" data collection--------
:: ----------------------------------------------------------
echo --- Disable Edge "Find on Page" data collection
:: Configure "RelatedMatchesCloudServiceEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!RelatedMatchesCloudServiceEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'RelatedMatchesCloudServiceEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge sign-in prompt on new tab page--------
:: ----------------------------------------------------------
echo --- Disable Edge sign-in prompt on new tab page
:: Configure "SignInCtaOnNtpEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SignInCtaOnNtpEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SignInCtaOnNtpEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Edge search and site suggestions---------
:: ----------------------------------------------------------
echo --- Disable Edge search and site suggestions
:: Configure "SearchSuggestEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SearchSuggestEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SearchSuggestEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable outdated Edge automatic image enhancement-----
:: ----------------------------------------------------------
echo --- Disable outdated Edge automatic image enhancement
:: Configure "EdgeEnhanceImagesEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeEnhanceImagesEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeEnhanceImagesEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge quick links on the new tab page-------
:: ----------------------------------------------------------
echo --- Disable Edge quick links on the new tab page
:: Configure "NewTabPageQuickLinksEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!NewTabPageQuickLinksEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'NewTabPageQuickLinksEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable Edge remote background images on new tab page---
:: ----------------------------------------------------------
echo --- Disable Edge remote background images on new tab page
:: Configure "NewTabPageAllowedBackgroundTypes" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!NewTabPageAllowedBackgroundTypes"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'NewTabPageAllowedBackgroundTypes' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Edge Collections feature-------------
:: ----------------------------------------------------------
echo --- Disable Edge Collections feature
:: Configure "EdgeCollectionsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeCollectionsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeCollectionsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable Edge failed page data collection and suggestions-
:: ----------------------------------------------------------
echo --- Disable Edge failed page data collection and suggestions
:: Configure "AlternateErrorPagesEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AlternateErrorPagesEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AlternateErrorPagesEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable outdated Edge games menu-------------
:: ----------------------------------------------------------
echo --- Disable outdated Edge games menu
:: Configure "AllowGamesMenu" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AllowGamesMenu"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AllowGamesMenu' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable Edge in-app support----------------
:: ----------------------------------------------------------
echo --- Disable Edge in-app support
:: Configure "InAppSupportEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!InAppSupportEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'InAppSupportEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Edge payment data storage and ads---------
:: ----------------------------------------------------------
echo --- Disable Edge payment data storage and ads
:: Configure "AutofillCreditCardEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AutofillCreditCardEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AutofillCreditCardEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Edge address data storage-------------
:: ----------------------------------------------------------
echo --- Disable Edge address data storage
:: Configure "AutofillAddressEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!AutofillAddressEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AutofillAddressEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable Edge experimentation and remote configuration---
:: ----------------------------------------------------------
echo --- Disable Edge experimentation and remote configuration
:: Configure "ExperimentationAndConfigurationServiceControl" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ExperimentationAndConfigurationServiceControl"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ExperimentationAndConfigurationServiceControl' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Edge automatic startup--------------
:: ----------------------------------------------------------
echo --- Disable Edge automatic startup
:: Configure "StartupBoostEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!StartupBoostEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'StartupBoostEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Edge external connectivity checks---------
:: ----------------------------------------------------------
echo --- Disable Edge external connectivity checks
:: Configure "ResolveNavigationErrorsUseWebService" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ResolveNavigationErrorsUseWebService"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ResolveNavigationErrorsUseWebService' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Edge Family Safety settings------------
:: ----------------------------------------------------------
echo --- Disable Edge Family Safety settings
:: Configure "FamilySafetySettingsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!FamilySafetySettingsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'FamilySafetySettingsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Edge site information gathering from Bing-----
:: ----------------------------------------------------------
echo --- Disable Edge site information gathering from Bing
:: Configure "SiteSafetyServicesEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SiteSafetyServicesEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SiteSafetyServicesEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Edge (Legacy) Live Tile data collection------
:: ----------------------------------------------------------
echo --- Disable Edge (Legacy) Live Tile data collection
:: Configure "PreventLiveTileDataCollection" Edge (Legacy) policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main!PreventLiveTileDataCollection"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' /v 'PreventLiveTileDataCollection' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main!PreventLiveTileDataCollection"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main'; $data =  '1'; reg add 'HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main' /v 'PreventLiveTileDataCollection' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Edge (Legacy) search suggestions---------
:: ----------------------------------------------------------
echo --- Disable Edge (Legacy) search suggestions
:: Configure "ShowSearchSuggestionsGlobal" Edge (Legacy) policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes!ShowSearchSuggestionsGlobal"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes' /v 'ShowSearchSuggestionsGlobal' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\SearchScopes!ShowSearchSuggestionsGlobal"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\SearchScopes'; $data =  '0'; reg add 'HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\SearchScopes' /v 'ShowSearchSuggestionsGlobal' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Edge (Legacy) Books telemetry-----------
:: ----------------------------------------------------------
echo --- Disable Edge (Legacy) Books telemetry
:: Configure "EnableExtendedBooksTelemetry" Edge (Legacy) policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary!EnableExtendedBooksTelemetry"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary' /v 'EnableExtendedBooksTelemetry' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\BooksLibrary!EnableExtendedBooksTelemetry"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\BooksLibrary'; $data =  '0'; reg add 'HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\BooksLibrary' /v 'EnableExtendedBooksTelemetry' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Internet Explorer geolocation-----------
:: ----------------------------------------------------------
echo --- Disable Internet Explorer geolocation
:: Set the registry value: "HKCU\Software\Policies\Microsoft\Internet Explorer\Geolocation!PolicyDisableGeolocation"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Policies\Microsoft\Internet Explorer\Geolocation'; $data =  '1'; reg add 'HKCU\Software\Policies\Microsoft\Internet Explorer\Geolocation' /v 'PolicyDisableGeolocation' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Internet Explorer InPrivate logging--------
:: ----------------------------------------------------------
echo --- Disable Internet Explorer InPrivate logging
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE!DisableLogging"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE' /v 'DisableLogging' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Internet Explorer Customer Experience Improvement Program (CEIP) participation
echo --- Disable Internet Explorer Customer Experience Improvement Program (CEIP) participation
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM!DisableCustomerImprovementProgram"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM' /v 'DisableCustomerImprovementProgram' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable legacy WCM policy calls--------------
:: ----------------------------------------------------------
echo --- Disable legacy WCM policy calls
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings!CallLegacyWCMPolicies"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' /v 'CallLegacyWCMPolicies' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable SSLv3 fallback------------------
:: ----------------------------------------------------------
echo --- Disable SSLv3 fallback
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings!EnableSSL3Fallback"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' /v 'EnableSSL3Fallback' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable certificate error ignoring------------
:: ----------------------------------------------------------
echo --- Disable certificate error ignoring
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings!PreventIgnoreCertErrors"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' /v 'PreventIgnoreCertErrors' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable outdated Chrome Software Reporter Tool------
:: ----------------------------------------------------------
echo --- Disable outdated Chrome Software Reporter Tool
:: Check and terminate the running process "software_reporter_tool.exe"
tasklist /fi "ImageName eq software_reporter_tool.exe" /fo csv 2>NUL | find /i "software_reporter_tool.exe">NUL && (
    echo software_reporter_tool.exe is running and will be killed.
    taskkill /f /im software_reporter_tool.exe
) || (
    echo Skipping, software_reporter_tool.exe is not running.
)
:: Configure termination of "software_reporter_tool.exe" immediately upon its startup
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe!Debugger"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe'; $data =  '%SYSTEMROOT%\System32\taskkill.exe'; reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe' /v 'Debugger' /t 'REG_SZ' /d "^""$data"^"" /f"
:: Add a rule to prevent the executable "software_reporter_tool.exe" from running via File Explorer
PowerShell -ExecutionPolicy Unrestricted -Command "$executableFilename='software_reporter_tool.exe'; try { $registryPathForDisallowRun='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'; $existingBlockEntries = Get-ItemProperty -Path "^""$registryPathForDisallowRun"^"" -ErrorAction Ignore; $nextFreeRuleIndex = 1; if ($existingBlockEntries) { $existingBlockingRuleForExecutable = $existingBlockEntries.PSObject.Properties | Where-Object { $_.Value -eq $executableFilename }; if ($existingBlockingRuleForExecutable) { $existingBlockingRuleIndexForExecutable = $existingBlockingRuleForExecutable.Name; Write-Output "^""Skipping, no action needed: '$executableFilename' is already blocked under rule index `"^""$existingBlockingRuleIndexForExecutable`"^""."^""; exit 0; }; $occupiedRuleIndexes = $existingBlockEntries.PSObject.Properties | Where-Object { $_.Name -Match '^\d+$' } | Select -ExpandProperty Name; if ($occupiedRuleIndexes) { while ($occupiedRuleIndexes -Contains $nextFreeRuleIndex) { $nextFreeRuleIndex += 1; }; }; }; Write-Output "^""Adding block rule for `"^""$executableFilename`"^"" under rule index `"^""$nextFreeRuleIndex`"^""."^""; if (!(Test-Path $registryPathForDisallowRun)) { New-Item -Path "^""$registryPathForDisallowRun"^"" -Force -ErrorAction Stop | Out-Null; }; New-ItemProperty -Path "^""$registryPathForDisallowRun"^"" -Name "^""$nextFreeRuleIndex"^"" -PropertyType String -Value "^""$executableFilename"^"" ` -ErrorAction Stop | Out-Null; Write-Output "^""Successfully blocked `"^""$executableFilename`"^"" with rule index `"^""$nextFreeRuleIndex`"^""."^""; } catch { Write-Error "^""Failed to block `"^""$executableFilename`"^"": $_"^""; Exit 1; }"
:: Activate the DisallowRun policy to block specified programs from running via File Explorer
PowerShell -ExecutionPolicy Unrestricted -Command "try { $fileExplorerDisallowRunRegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $currentDisallowRunPolicyValue = Get-ItemProperty -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Name 'DisallowRun' -ErrorAction Ignore | Select -ExpandProperty DisallowRun; if ([string]::IsNullOrEmpty($currentDisallowRunPolicyValue)) { Write-Output "^""Creating DisallowRun policy at `"^""$fileExplorerDisallowRunRegistryPath`"^""."^""; if (!(Test-Path $fileExplorerDisallowRunRegistryPath)) { New-Item -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Force -ErrorAction Stop | Out-Null; }; New-ItemProperty -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Name 'DisallowRun' -Value 1 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null; Write-Output 'Successfully activated DisallowRun policy.'; Exit 0; }; if ($currentDisallowRunPolicyValue -eq 1) { Write-Output 'Skipping, no action needed: DisallowRun policy is already in place.'; Exit 0; }; Write-Output 'Updating DisallowRun policy from unexpected value `"^""$currentDisallowRunPolicyValue`"^"" to `"^""1`"^"".'; Set-ItemProperty -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Name 'DisallowRun' -Value 1 -Type DWORD -Force -ErrorAction Stop | Out-Null; Write-Output 'Successfully activated DisallowRun policy.'; } catch { Write-Error "^""Failed to activate DisallowRun policy: $_"^""; Exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Chrome metrics reporting-------------
:: ----------------------------------------------------------
echo --- Disable Chrome metrics reporting
:: Configure "MetricsReportingEnabled" Chrome policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Google\Chrome!MetricsReportingEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Google\Chrome'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'MetricsReportingEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Chrome for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Google Chrome.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Disable Firefox default browser and system data reporting-
:: ----------------------------------------------------------
echo --- Disable Firefox default browser and system data reporting
:: Set the registry value: "HKLM\SOFTWARE\Policies\Mozilla\Firefox!DisableDefaultBrowserAgent"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Mozilla\Firefox'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Mozilla\Firefox' /v 'DisableDefaultBrowserAgent' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Firefox background browser checks---------
:: ----------------------------------------------------------
echo --- Disable Firefox background browser checks
:: Disable scheduled task(s): `\Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Mozilla\'; $taskNamePattern='Firefox Default Browser Agent 308046B0AF4A39CB'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\Mozilla\Firefox Default Browser Agent D2CEEC440E2074BD`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\Mozilla\'; $taskNamePattern='Firefox Default Browser Agent D2CEEC440E2074BD'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Firefox telemetry data collection---------
:: ----------------------------------------------------------
echo --- Disable Firefox telemetry data collection
:: Set the registry value: "HKLM\SOFTWARE\Policies\Mozilla\Firefox!DisableTelemetry"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Mozilla\Firefox'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Mozilla\Firefox' /v 'DisableTelemetry' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Edge diagnostic data sending-----------
:: ----------------------------------------------------------
echo --- Disable Edge diagnostic data sending
:: Configure "DiagnosticData" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!DiagnosticData"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'DiagnosticData' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable outdated Edge metrics data sending--------
:: ----------------------------------------------------------
echo --- Disable outdated Edge metrics data sending
:: Configure "MetricsReportingEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!MetricsReportingEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'MetricsReportingEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable outdated Edge site information sending------
:: ----------------------------------------------------------
echo --- Disable outdated Edge site information sending
:: Configure "SendSiteInfoToImproveServices" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SendSiteInfoToImproveServices"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SendSiteInfoToImproveServices' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable Edge Feedback-------------------
:: ----------------------------------------------------------
echo --- Disable Edge Feedback
:: Configure "UserFeedbackAllowed" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!UserFeedbackAllowed"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'UserFeedbackAllowed' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Edge automatic update services----------
:: ----------------------------------------------------------
echo --- Disable Edge automatic update services
:: Disable service(s): `edgeupdate`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'edgeupdate'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: Disable service(s): `edgeupdatem`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'edgeupdatem'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable Edge automatic update scheduled tasks-------
:: ----------------------------------------------------------
echo --- Disable Edge automatic update scheduled tasks
:: Disable scheduled task(s): `\MicrosoftEdgeUpdateTaskMachineCore{*}`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='MicrosoftEdgeUpdateTaskMachineCore{*}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: Disable scheduled task(s): `\MicrosoftEdgeUpdateTaskMachineUA{*}`
PowerShell -ExecutionPolicy Unrestricted -Command "$taskPathPattern='\'; $taskNamePattern='MicrosoftEdgeUpdateTaskMachineUA{*}'; Write-Output "^""Disabling tasks matching pattern `"^""$taskNamePattern`"^""."^""; $tasks = @(Get-ScheduledTask -TaskPath $taskPathPattern -TaskName $taskNamePattern -ErrorAction Ignore); if (-Not $tasks) { Write-Output "^""Skipping, no tasks matching pattern `"^""$taskNamePattern`"^"" found, no action needed."^""; exit 0; }; $operationFailed = $false; foreach ($task in $tasks) { $taskName = $task.TaskName; if ($task.State -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Disabled) { Write-Output "^""Skipping, task `"^""$taskName`"^"" is already disabled, no action needed."^""; continue; }; try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Output "^""Successfully disabled task `"^""$taskName`"^""."^""; } catch { Write-Error "^""Failed to disable task `"^""$taskName`"^"": $($_.Exception.Message)"^""; $operationFailed = $true; }; }; if ($operationFailed) { Write-Output 'Failed to disable some tasks. Check error messages above.'; exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Edge update executable--------------
:: ----------------------------------------------------------
echo --- Disable Edge update executable
:: Check and terminate the running process "MicrosoftEdgeUpdate.exe"
tasklist /fi "ImageName eq MicrosoftEdgeUpdate.exe" /fo csv 2>NUL | find /i "MicrosoftEdgeUpdate.exe">NUL && (
    echo MicrosoftEdgeUpdate.exe is running and will be killed.
    taskkill /f /im MicrosoftEdgeUpdate.exe
) || (
    echo Skipping, MicrosoftEdgeUpdate.exe is not running.
)
:: Configure termination of "MicrosoftEdgeUpdate.exe" immediately upon its startup
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe!Debugger"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe'; $data =  '%SYSTEMROOT%\System32\taskkill.exe'; reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe' /v 'Debugger' /t 'REG_SZ' /d "^""$data"^"" /f"
:: Add a rule to prevent the executable "MicrosoftEdgeUpdate.exe" from running via File Explorer
PowerShell -ExecutionPolicy Unrestricted -Command "$executableFilename='MicrosoftEdgeUpdate.exe'; try { $registryPathForDisallowRun='HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'; $existingBlockEntries = Get-ItemProperty -Path "^""$registryPathForDisallowRun"^"" -ErrorAction Ignore; $nextFreeRuleIndex = 1; if ($existingBlockEntries) { $existingBlockingRuleForExecutable = $existingBlockEntries.PSObject.Properties | Where-Object { $_.Value -eq $executableFilename }; if ($existingBlockingRuleForExecutable) { $existingBlockingRuleIndexForExecutable = $existingBlockingRuleForExecutable.Name; Write-Output "^""Skipping, no action needed: '$executableFilename' is already blocked under rule index `"^""$existingBlockingRuleIndexForExecutable`"^""."^""; exit 0; }; $occupiedRuleIndexes = $existingBlockEntries.PSObject.Properties | Where-Object { $_.Name -Match '^\d+$' } | Select -ExpandProperty Name; if ($occupiedRuleIndexes) { while ($occupiedRuleIndexes -Contains $nextFreeRuleIndex) { $nextFreeRuleIndex += 1; }; }; }; Write-Output "^""Adding block rule for `"^""$executableFilename`"^"" under rule index `"^""$nextFreeRuleIndex`"^""."^""; if (!(Test-Path $registryPathForDisallowRun)) { New-Item -Path "^""$registryPathForDisallowRun"^"" -Force -ErrorAction Stop | Out-Null; }; New-ItemProperty -Path "^""$registryPathForDisallowRun"^"" -Name "^""$nextFreeRuleIndex"^"" -PropertyType String -Value "^""$executableFilename"^"" ` -ErrorAction Stop | Out-Null; Write-Output "^""Successfully blocked `"^""$executableFilename`"^"" with rule index `"^""$nextFreeRuleIndex`"^""."^""; } catch { Write-Error "^""Failed to block `"^""$executableFilename`"^"": $_"^""; Exit 1; }"
:: Activate the DisallowRun policy to block specified programs from running via File Explorer
PowerShell -ExecutionPolicy Unrestricted -Command "try { $fileExplorerDisallowRunRegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $currentDisallowRunPolicyValue = Get-ItemProperty -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Name 'DisallowRun' -ErrorAction Ignore | Select -ExpandProperty DisallowRun; if ([string]::IsNullOrEmpty($currentDisallowRunPolicyValue)) { Write-Output "^""Creating DisallowRun policy at `"^""$fileExplorerDisallowRunRegistryPath`"^""."^""; if (!(Test-Path $fileExplorerDisallowRunRegistryPath)) { New-Item -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Force -ErrorAction Stop | Out-Null; }; New-ItemProperty -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Name 'DisallowRun' -Value 1 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null; Write-Output 'Successfully activated DisallowRun policy.'; Exit 0; }; if ($currentDisallowRunPolicyValue -eq 1) { Write-Output 'Skipping, no action needed: DisallowRun policy is already in place.'; Exit 0; }; Write-Output 'Updating DisallowRun policy from unexpected value `"^""$currentDisallowRunPolicyValue`"^"" to `"^""1`"^"".'; Set-ItemProperty -Path "^""$fileExplorerDisallowRunRegistryPath"^"" -Name 'DisallowRun' -Value 1 -Type DWORD -Force -ErrorAction Stop | Out-Null; Write-Output 'Successfully activated DisallowRun policy.'; } catch { Write-Error "^""Failed to activate DisallowRun policy: $_"^""; Exit 1; }"
:: Soft delete files matching pattern: "%PROGRAMFILES(x86)%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"  
PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%PROGRAMFILES(x86)%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; $renamedCount   = 0; $skippedCount   = 0; $failedCount    = 0; $foundAbsolutePaths = @(); try { $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) { Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) { if (Test-Path -Path $path -PathType Container) { Write-Host "^""Skipping folder (not its contents): `"^""$path`"^""."^""; $skippedCount++; continue; }; if($revert -eq $true) { if (-not $path.EndsWith('.OLD')) { Write-Host "^""Skipping non-backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; } else { if ($path.EndsWith('.OLD')) { Write-Host "^""Skipping backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; }; $originalFilePath = $path; Write-Host "^""Processing file: `"^""$originalFilePath`"^""."^""; if (-Not (Test-Path $originalFilePath)) { Write-Host "^""Skipping, file `"^""$originalFilePath`"^"" not found."^""; $skippedCount++; exit 0; }; if ($revert -eq $true) { $newFilePath = $originalFilePath.Substring(0, $originalFilePath.Length - 4); } else { $newFilePath = "^""$($originalFilePath).OLD"^""; }; try { Move-Item -LiteralPath "^""$($originalFilePath)"^"" -Destination "^""$newFilePath"^"" -Force -ErrorAction Stop; Write-Host "^""Successfully processed `"^""$originalFilePath`"^""."^""; $renamedCount++; } catch { Write-Error "^""Failed to rename `"^""$originalFilePath`"^"" to `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; $failedCount++; }; }; if (($renamedCount -gt 0) -or ($skippedCount -gt 0)) { Write-Host "^""Successfully processed $renamedCount items and skipped $skippedCount items."^""; }; if ($failedCount -gt 0) { Write-Warning "^""Failed to process $($failedCount) items."^""; }"
:: Soft delete files matching pattern: "%PROGRAMFILES(x86)%\Microsoft\EdgeUpdate\*\MicrosoftEdgeUpdate.exe"  
PowerShell -ExecutionPolicy Unrestricted -Command "$pathGlobPattern = "^""%PROGRAMFILES(x86)%\Microsoft\EdgeUpdate\*\MicrosoftEdgeUpdate.exe"^""; $expandedPath = [System.Environment]::ExpandEnvironmentVariables($pathGlobPattern); Write-Host "^""Searching for items matching pattern: `"^""$($expandedPath)`"^""."^""; $renamedCount   = 0; $skippedCount   = 0; $failedCount    = 0; $foundAbsolutePaths = @(); try { $foundAbsolutePaths += @(; Get-Item -Path $expandedPath -ErrorAction Stop | Select-Object -ExpandProperty FullName; ); } catch [System.Management.Automation.ItemNotFoundException] { <# Swallow, do not run `Test-Path` before, it's unreliable for globs requiring extra permissions #>; }; $foundAbsolutePaths = $foundAbsolutePaths | Select-Object -Unique | Sort-Object -Property { $_.Length } -Descending; if (!$foundAbsolutePaths) { Write-Host 'Skipping, no items available.'; exit 0; }; Write-Host "^""Initiating processing of $($foundAbsolutePaths.Count) items from `"^""$expandedPath`"^""."^""; foreach ($path in $foundAbsolutePaths) { if (Test-Path -Path $path -PathType Container) { Write-Host "^""Skipping folder (not its contents): `"^""$path`"^""."^""; $skippedCount++; continue; }; if($revert -eq $true) { if (-not $path.EndsWith('.OLD')) { Write-Host "^""Skipping non-backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; } else { if ($path.EndsWith('.OLD')) { Write-Host "^""Skipping backup file: `"^""$path`"^""."^""; $skippedCount++; continue; }; }; $originalFilePath = $path; Write-Host "^""Processing file: `"^""$originalFilePath`"^""."^""; if (-Not (Test-Path $originalFilePath)) { Write-Host "^""Skipping, file `"^""$originalFilePath`"^"" not found."^""; $skippedCount++; exit 0; }; if ($revert -eq $true) { $newFilePath = $originalFilePath.Substring(0, $originalFilePath.Length - 4); } else { $newFilePath = "^""$($originalFilePath).OLD"^""; }; try { Move-Item -LiteralPath "^""$($originalFilePath)"^"" -Destination "^""$newFilePath"^"" -Force -ErrorAction Stop; Write-Host "^""Successfully processed `"^""$originalFilePath`"^""."^""; $renamedCount++; } catch { Write-Error "^""Failed to rename `"^""$originalFilePath`"^"" to `"^""$newFilePath`"^"": $($_.Exception.Message)"^""; $failedCount++; }; }; if (($renamedCount -gt 0) -or ($skippedCount -gt 0)) { Write-Host "^""Successfully processed $renamedCount items and skipped $skippedCount items."^""; }; if ($failedCount -gt 0) { Write-Warning "^""Failed to process $($failedCount) items."^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Edge automatic updates across all channels----
:: ----------------------------------------------------------
echo --- Disable Edge automatic updates across all channels
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!UpdateDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'UpdateDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Edge WebView and WebView2 updates---------
:: ----------------------------------------------------------
echo --- Disable Edge WebView and WebView2 updates
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Edge automatic update checks-----------
:: ----------------------------------------------------------
echo --- Disable Edge automatic update checks
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!AutoUpdateCheckPeriodMinutes"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'AutoUpdateCheckPeriodMinutes' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Maximize Edge update suppression duration---------
:: ----------------------------------------------------------
echo --- Maximize Edge update suppression duration
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!UpdatesSuppressedDurationMin"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '1440'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'UpdatesSuppressedDurationMin' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!UpdatesSuppressedStartHour"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'UpdatesSuppressedStartHour' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!UpdatesSuppressedStartMin"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'UpdatesSuppressedStartMin' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Edge Copilot and Hubs Sidebar-----------
:: ----------------------------------------------------------
echo --- Disable Edge Copilot and Hubs Sidebar
:: Configure "HubsSidebarEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!HubsSidebarEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'HubsSidebarEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "StandaloneHubsSidebarEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!StandaloneHubsSidebarEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'StandaloneHubsSidebarEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable Edge Copilot browsing data collection-------
:: ----------------------------------------------------------
echo --- Disable Edge Copilot browsing data collection
:: Configure "DiscoverPageContextEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!DiscoverPageContextEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'DiscoverPageContextEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "CopilotPageContext" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!CopilotPageContext"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotPageContext' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Configure "CopilotCDPPageContext" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!CopilotCDPPageContext"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotCDPPageContext' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge Copilot access on new tab page--------
:: ----------------------------------------------------------
echo --- Disable Edge Copilot access on new tab page
:: Configure "NewTabPageBingChatEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!NewTabPageBingChatEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'NewTabPageBingChatEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable outdated Edge Discover button-----------
:: ----------------------------------------------------------
echo --- Disable outdated Edge Discover button
:: Configure "EdgeDiscoverEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!EdgeDiscoverEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeDiscoverEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Edge spotlight recommendations----------
:: ----------------------------------------------------------
echo --- Disable Edge spotlight recommendations
:: Configure "SpotlightExperiencesAndRecommendationsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!SpotlightExperiencesAndRecommendationsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'SpotlightExperiencesAndRecommendationsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable Edge feature ads-----------------
:: ----------------------------------------------------------
echo --- Disable Edge feature ads
:: Configure "ShowRecommendationsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ShowRecommendationsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ShowRecommendationsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable Edge Bing ads-------------------
:: ----------------------------------------------------------
echo --- Disable Edge Bing ads
:: Configure "BingAdsSuppression" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!BingAdsSuppression"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'BingAdsSuppression' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Edge for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Microsoft Edge.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Edge promotional pages--------------
:: ----------------------------------------------------------
echo --- Disable Edge promotional pages
:: Configure "PromotionalTabsEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!PromotionalTabsEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'PromotionalTabsEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Edge browsing history collection for ads-----
:: ----------------------------------------------------------
echo --- Disable Edge browsing history collection for ads
:: Configure "PersonalizationReportingEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!PersonalizationReportingEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'PersonalizationReportingEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable Edge Insider ads-----------------
:: ----------------------------------------------------------
echo --- Disable Edge Insider ads
:: Configure "MicrosoftEdgeInsiderPromotionEnabled" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!MicrosoftEdgeInsiderPromotionEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'MicrosoftEdgeInsiderPromotionEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Edge Adobe Acrobat subscription ads--------
:: ----------------------------------------------------------
echo --- Disable Edge Adobe Acrobat subscription ads
:: Configure "ShowAcrobatSubscriptionButton" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ShowAcrobatSubscriptionButton"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ShowAcrobatSubscriptionButton' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable Edge top sites and sponsored links on new tab page
echo --- Disable Edge top sites and sponsored links on new tab page
:: Configure "NewTabPageHideDefaultTopSites" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!NewTabPageHideDefaultTopSites"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'NewTabPageHideDefaultTopSites' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Enable Edge tracking prevention--------------
:: ----------------------------------------------------------
echo --- Enable Edge tracking prevention
:: Configure "TrackingPrevention" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!TrackingPrevention"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '3'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'TrackingPrevention' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Block Edge third party cookies--------------
:: ----------------------------------------------------------
echo --- Block Edge third party cookies
:: Configure "BlockThirdPartyCookies" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!BlockThirdPartyCookies"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'BlockThirdPartyCookies' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Enable Do Not Track requests---------------
:: ----------------------------------------------------------
echo --- Enable Do Not Track requests
:: Configure "ConfigureDoNotTrack" Edge policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Edge!ConfigureDoNotTrack"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'; $data =  '1'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ConfigureDoNotTrack' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable automatic installation of Edge----------
:: ----------------------------------------------------------
echo --- Disable automatic installation of Edge
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\EdgeUpdate!DoNotUpdateToEdgeWithChromium"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\EdgeUpdate'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\EdgeUpdate' /v 'DoNotUpdateToEdgeWithChromium' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable automatic installation of Edge across all channels
echo --- Disable automatic installation of Edge across all channels
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!InstallDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'InstallDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable automatic installation of WebView and WebView2--
:: ----------------------------------------------------------
echo --- Disable automatic installation of WebView and WebView2
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate!Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v 'Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable sharing scanned software data with Google-----
:: ----------------------------------------------------------
echo --- Disable sharing scanned software data with Google
:: Configure "ChromeCleanupReportingEnabled" Chrome policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Google\Chrome!ChromeCleanupReportingEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Google\Chrome'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'ChromeCleanupReportingEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Chrome system cleanup scans------------
:: ----------------------------------------------------------
echo --- Disable Chrome system cleanup scans
:: Configure "ChromeCleanupEnabled" Chrome policy
:: Set the registry value: "HKLM\SOFTWARE\Policies\Google\Chrome!ChromeCleanupEnabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Google\Chrome'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Google\Chrome' /v 'ChromeCleanupEnabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting Chrome for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart Google Chrome.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Cloud Clipboard (breaks clipboard sync)------
:: ----------------------------------------------------------
echo --- Disable Cloud Clipboard (breaks clipboard sync)
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\System!AllowCrossDeviceClipboard"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'AllowCrossDeviceClipboard' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKCU\Software\Microsoft\Clipboard!CloudClipboardAutomaticUpload"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Clipboard'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Clipboard' /v 'CloudClipboardAutomaticUpload' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable clipboard history-----------------
:: ----------------------------------------------------------
echo --- Disable clipboard history
:: Set the registry value: "HKCU\Software\Microsoft\Clipboard!EnableClipboardHistory"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Clipboard'; $data =  '0'; reg add 'HKCU\Software\Microsoft\Clipboard' /v 'EnableClipboardHistory' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\System!AllowClipboardHistory"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'AllowClipboardHistory' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable background clipboard data collection (`cbdhsvc`) (breaks clipboard history and sync)
echo --- Disable background clipboard data collection (`cbdhsvc`) (breaks clipboard history and sync)
:: Disable per-user "cbdhsvc" service for all users
:: Disable the service `cbdhsvc` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'cbdhsvc'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: Disable per-user "cbdhsvc" service for individual user accounts
:: Disable the service `cbdhsvc_*` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'cbdhsvc_*'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: ----------------------------------------------------------


:: Mitigate Spectre Variant 2 and Meltdown in host operating system
echo --- Mitigate Spectre Variant 2 and Meltdown in host operating system
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management!FeatureSettingsOverrideMask"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; $data =  '3'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v 'FeatureSettingsOverrideMask' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management!FeatureSettingsOverride"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v 'FeatureSettingsOverride' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management!FeatureSettingsOverride"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; $data =  '64'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v 'FeatureSettingsOverride' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Mitigate Spectre Variant 2 and Meltdown in Hyper-V----
:: ----------------------------------------------------------
echo --- Mitigate Spectre Variant 2 and Meltdown in Hyper-V
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization!MinVmVersionForCpuBasedMitigations"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'; $data =  '1.0'; reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' /v 'MinVmVersionForCpuBasedMitigations' /t 'REG_SZ' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Enable strong Diffie-Hellman key requirement-------
:: ----------------------------------------------------------
echo --- Enable strong Diffie-Hellman key requirement
:: Require "Diffie-Hellman" key exchange algorithm to have at "2048" least bits keys for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman!ServerMinKeyBitLength"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'; $data =  '2048'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' /v 'ServerMinKeyBitLength' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman!ClientMinKeyBitLength"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'; $data =  '2048'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' /v 'ClientMinKeyBitLength' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Enable strong RSA key requirement (breaks Hyper-V VMs)--
:: ----------------------------------------------------------
echo --- Enable strong RSA key requirement (breaks Hyper-V VMs)
:: Require "PKCS" key exchange algorithm to have at "2048" least bits keys for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS!ServerMinKeyBitLength"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS'; $data =  '2048'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' /v 'ServerMinKeyBitLength' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS!ClientMinKeyBitLength"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS'; $data =  '2048'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' /v 'ClientMinKeyBitLength' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure renegotiation--------------
:: ----------------------------------------------------------
echo --- Disable insecure renegotiation
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!AllowInsecureRenegoClients"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'AllowInsecureRenegoClients' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!AllowInsecureRenegoServers"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'AllowInsecureRenegoServers' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!DisableRenegoOnServer"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'DisableRenegoOnServer' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!DisableRenegoOnClient"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'DisableRenegoOnClient' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!UseScsvForTls"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'UseScsvForTls' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable insecure connections from .NET apps--------
:: ----------------------------------------------------------
echo --- Disable insecure connections from .NET apps
:: Configure "SchUseStrongCrypto" for .NET applications
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727!SchUseStrongCrypto"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727!SchUseStrongCrypto"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'; $data =  '1'; reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319!SchUseStrongCrypto"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319!SchUseStrongCrypto"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; $data =  '1'; reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting computer for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart your computer.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Enable secure "DTLS 1.2" protocol-------------
:: ----------------------------------------------------------
echo --- Enable secure "DTLS 1.2" protocol
:: Enable "DTLS 1.2" protocol as default for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server!Enabled"
:: This operation will not run on Windows versions earlier than Windows10-1607.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1607'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server!DisabledByDefault"
:: This operation will not run on Windows versions earlier than Windows10-1607.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1607'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client!Enabled"
:: This operation will not run on Windows versions earlier than Windows10-1607.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1607'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client!DisabledByDefault"
:: This operation will not run on Windows versions earlier than Windows10-1607.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1607'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Enable secure "TLS 1.3" protocol-------------
:: ----------------------------------------------------------
echo --- Enable secure "TLS 1.3" protocol
:: Enable "TLS 1.3" protocol as default for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server!Enabled"
:: This operation will not run on Windows versions earlier than Windows11-FirstRelease.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows11-FirstRelease'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server!DisabledByDefault"
:: This operation will not run on Windows versions earlier than Windows11-FirstRelease.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows11-FirstRelease'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client!Enabled"
:: This operation will not run on Windows versions earlier than Windows11-FirstRelease.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows11-FirstRelease'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client!DisabledByDefault"
:: This operation will not run on Windows versions earlier than Windows11-FirstRelease.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows11-FirstRelease'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Enable secure connections for legacy .NET apps------
:: ----------------------------------------------------------
echo --- Enable secure connections for legacy .NET apps
:: Configure "SystemDefaultTlsVersions" for .NET applications
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727!SystemDefaultTlsVersions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' /v 'SystemDefaultTlsVersions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727!SystemDefaultTlsVersions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'; $data =  '1'; reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' /v 'SystemDefaultTlsVersions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319!SystemDefaultTlsVersions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' /v 'SystemDefaultTlsVersions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319!SystemDefaultTlsVersions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; $data =  '1'; reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' /v 'SystemDefaultTlsVersions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable basic authentication in WinRM-----------
:: ----------------------------------------------------------
echo --- Disable basic authentication in WinRM
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client!AllowBasic"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' /v 'AllowBasic' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable unauthorized user account discovery (anonymous SAM enumeration)
echo --- Disable unauthorized user account discovery (anonymous SAM enumeration)
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Lsa!restrictanonymoussam"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'restrictanonymoussam' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable anonymous access to named pipes and shares----
:: ----------------------------------------------------------
echo --- Disable anonymous access to named pipes and shares
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters!restrictnullsessaccess"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' /v 'restrictnullsessaccess' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable hidden remote file access via administrative shares (breaks remote system management software)
echo --- Disable hidden remote file access via administrative shares (breaks remote system management software)
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters!AutoShareWks"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v 'AutoShareWks' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable anonymous enumeration of shares----------
:: ----------------------------------------------------------
echo --- Disable anonymous enumeration of shares
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\LSA!restrictanonymous"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\LSA'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\LSA' /v 'restrictanonymous' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable "Telnet Client" feature--------------
:: ----------------------------------------------------------
echo --- Disable "Telnet Client" feature
:: Disable the "TelnetClient" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'TelnetClient'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: Remove "RAS Connection Manager Administration Kit (CMAK)" capability
echo --- Remove "RAS Connection Manager Administration Kit (CMAK)" capability
PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'RasCMAK.Client*' | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Remote Assistance feature---------
:: ----------------------------------------------------------
echo --- Disable Windows Remote Assistance feature
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance!fAllowToGetHelp"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance' /v 'fAllowToGetHelp' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance!fAllowFullControl"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance' /v 'fAllowFullControl' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services!AllowBasic"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' /v 'AllowBasic' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable "Net.TCP Port Sharing" feature----------
:: ----------------------------------------------------------
echo --- Disable "Net.TCP Port Sharing" feature
:: Disable the "WCF-TCP-PortSharing45" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'WCF-TCP-PortSharing45'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable "SMB Direct" feature---------------
:: ----------------------------------------------------------
echo --- Disable "SMB Direct" feature
:: Disable the "SmbDirect" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'SmbDirect'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable "TFTP Client" feature---------------
:: ----------------------------------------------------------
echo --- Disable "TFTP Client" feature
:: Disable the "TFTP" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'TFTP'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Remove "RIP Listener" capability-------------
:: ----------------------------------------------------------
echo --- Remove "RIP Listener" capability
PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'RIP.Listener*' | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: Remove "Simple Network Management Protocol (SNMP)" capability
echo --- Remove "Simple Network Management Protocol (SNMP)" capability
PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'SNMP.Client*' | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Remove "SNMP WMI Provider" capability-----------
:: ----------------------------------------------------------
echo --- Remove "SNMP WMI Provider" capability
PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'WMI-SNMP-Provider.Client*' | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "RC2" ciphers--------------
:: ----------------------------------------------------------
echo --- Disable insecure "RC2" ciphers
:: Disable the use of "RC2 40/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC2 56/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC2 128/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "RC4" ciphers--------------
:: ----------------------------------------------------------
echo --- Disable insecure "RC4" ciphers
:: Disable the use of "RC4 128/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC4 64/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC4 56/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC4 40/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "DES" cipher---------------
:: ----------------------------------------------------------
echo --- Disable insecure "DES" cipher
:: Disable the use of "DES 56/56" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "Triple DES" cipher-----------
:: ----------------------------------------------------------
echo --- Disable insecure "Triple DES" cipher
:: Disable the use of "Triple DES 168" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "Triple DES 168/168" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "NULL" cipher--------------
:: ----------------------------------------------------------
echo --- Disable insecure "NULL" cipher
:: Disable the use of "NULL" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable insecure "MD5" hash----------------
:: ----------------------------------------------------------
echo --- Disable insecure "MD5" hash
:: Disable usage of "MD5" hash algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "SHA-1" hash---------------
:: ----------------------------------------------------------
echo --- Disable insecure "SHA-1" hash
:: Disable usage of "SHA" hash algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable insecure "SMBv1" protocol-------------
:: ----------------------------------------------------------
echo --- Disable insecure "SMBv1" protocol
:: Disable the "SMB1Protocol" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'SMB1Protocol'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: Disable the "SMB1Protocol-Client" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'SMB1Protocol-Client'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: Disable the "SMB1Protocol-Server" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'SMB1Protocol-Server'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: Disable service(s): `mrxsmb10`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'mrxsmb10'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters!SMBv1"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v 'SMBv1' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting computer for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart your computer.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "NetBios" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "NetBios" protocol
PowerShell -ExecutionPolicy Unrestricted -Command "$key = 'HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces'; Get-ChildItem $key | ForEach { Set-ItemProperty -Path "^""$key\$($_.PSChildName)"^"" -Name NetbiosOptions -Value 2 -Verbose; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "SSL 2.0" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "SSL 2.0" protocol
:: Disable usage of "SSL 2.0" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "SSL 3.0" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "SSL 3.0" protocol
:: Disable usage of "SSL 3.0" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "TLS 1.0" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "TLS 1.0" protocol
:: Disable usage of "TLS 1.0" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "TLS 1.1" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "TLS 1.1" protocol
:: Disable usage of "TLS 1.1" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "DTLS 1.0" protocol-----------
:: ----------------------------------------------------------
echo --- Disable insecure "DTLS 1.0" protocol
:: Disable usage of "DTLS 1.0" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable insecure "LM & NTLM" protocols----------
:: ----------------------------------------------------------
echo --- Disable insecure "LM ^& NTLM" protocols
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Lsa!LmCompatibilityLevel"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; $data =  '5'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'LmCompatibilityLevel' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable online tips--------------------
:: ----------------------------------------------------------
echo --- Disable online tips
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\System!AllowOnlineTips"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'AllowOnlineTips' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable "Internet File Association" service--------
:: ----------------------------------------------------------
echo --- Disable "Internet File Association" service
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoInternetOpenWith"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoInternetOpenWith' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable "Order Prints" picture task------------
:: ----------------------------------------------------------
echo --- Disable "Order Prints" picture task
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoOnlinePrintsWizard"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoOnlinePrintsWizard' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable "Publish to Web" option for files and folders---
:: ----------------------------------------------------------
echo --- Disable "Publish to Web" option for files and folders
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoPublishingWizard"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoPublishingWizard' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable provider list downloads for wizards--------
:: ----------------------------------------------------------
echo --- Disable provider list downloads for wizards
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoWebServices"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoWebServices' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable history of recently opened documents-------
:: ----------------------------------------------------------
echo --- Disable history of recently opened documents
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer!NoRecentDocsHistory"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoRecentDocsHistory' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Clear recently opened document history upon exit-----
:: ----------------------------------------------------------
echo --- Clear recently opened document history upon exit
:: Set the registry value: "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer!ClearRecentDocsOnExit"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; $data =  '1'; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'ClearRecentDocsOnExit' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Location Provider (revert)--------
:: ----------------------------------------------------------
echo --- Disable Windows Location Provider (revert)
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors!DisableWindowsLocationProvider"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' /v 'DisableWindowsLocationProvider' /f 2>$null"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable location scripting (revert)------------
:: ----------------------------------------------------------
echo --- Disable location scripting (revert)
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors!DisableLocationScripting"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' /v 'DisableLocationScripting' /f 2>$null"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable location (revert)-----------------
:: ----------------------------------------------------------
echo --- Disable location (revert)
:: Delete the registry value "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors!DisableLocation"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' /v 'DisableLocation' /f 2>$null"
:: Delete the registry value "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}!Value"
PowerShell -ExecutionPolicy Unrestricted -Command "reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' /v 'Value' /f 2>$null"
:: Set the registry value "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}!SensorPermissionState"
PowerShell -ExecutionPolicy Unrestricted -Command "$revertData =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' /v 'SensorPermissionState' /t 'REG_DWORD' /d "^""$revertData"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable User Data Storage-----------------
:: ----------------------------------------------------------
echo --- Disable User Data Storage
:: Disable per-user "UnistoreSvc" service for all users
:: Disable the service `UnistoreSvc` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'UnistoreSvc'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: Disable per-user "UnistoreSvc" service for individual user accounts
:: Disable the service `UnistoreSvc_*` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'UnistoreSvc_*'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Disable Sync Host---------------------
:: ----------------------------------------------------------
echo --- Disable Sync Host
:: Disable per-user "OneSyncSvc" service for all users
:: Disable the service `OneSyncSvc` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'OneSyncSvc'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: Disable per-user "OneSyncSvc" service for individual user accounts
:: Disable the service `OneSyncSvc_*` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'OneSyncSvc_*'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: ----------------------------------------------------------


:: Disable Microsoft Account Sign-in Assistant (breaks Microsoft Store and Microsoft Account sign-in)
echo --- Disable Microsoft Account Sign-in Assistant (breaks Microsoft Store and Microsoft Account sign-in)
:: Disable service(s): `wlidsvc`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wlidsvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Downloaded Maps Manager--------------
:: ----------------------------------------------------------
echo --- Disable Downloaded Maps Manager
:: Disable service(s): `MapsBroker`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'MapsBroker'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Microsoft Retail Demo---------------
:: ----------------------------------------------------------
echo --- Disable Microsoft Retail Demo
:: Disable service(s): `RetailDemo`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'RetailDemo'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable User Data Access-----------------
:: ----------------------------------------------------------
echo --- Disable User Data Access
:: Disable per-user "UserDataSvc" service for all users
:: Disable the service `UserDataSvc` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'UserDataSvc'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: Disable per-user "UserDataSvc" service for individual user accounts
:: Disable the service `UserDataSvc_*` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'UserDataSvc_*'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable Messaging Service-----------------
:: ----------------------------------------------------------
echo --- Disable Messaging Service
:: Disable per-user "MessagingService" service for all users
:: Disable the service `MessagingService` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'MessagingService'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: Disable per-user "MessagingService" service for individual user accounts
:: Disable the service `MessagingService_*` 
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'MessagingService_*'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Windows Push Notifications------------
:: ----------------------------------------------------------
echo --- Disable Windows Push Notifications
:: Disable service(s): `WpnService`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'WpnService'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: Disable per-user "WpnUserService" service for all users
:: Disable the service `WpnUserService` 
:: This operation will not run on Windows versions later than Windows10-1909.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1909'; $buildNumber = switch ($versionName) { 'Windows11-21H2' { '10.0.22000' }; 'Windows10-MostRecent' { '10.0.19045' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1903' { '10.0.18362' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for maximum Windows '$versionName'"^""; }; }; $maxVersion=[System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -gt $maxVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is above maximum $maxVersion ($versionName)"^""; Exit 0; }; $serviceQuery = 'WpnUserService'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: Disable per-user "WpnUserService" service for individual user accounts
:: Disable the service `WpnUserService_*` 
:: This operation will not run on Windows versions later than Windows10-1909.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1909'; $buildNumber = switch ($versionName) { 'Windows11-21H2' { '10.0.22000' }; 'Windows10-MostRecent' { '10.0.19045' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1903' { '10.0.18362' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for maximum Windows '$versionName'"^""; }; }; $maxVersion=[System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -gt $maxVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is above maximum $maxVersion ($versionName)"^""; Exit 0; }; $serviceQuery = 'WpnUserService_*'; $stopWithDependencies= $false; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service query `"^""$serviceQuery`"^"" did not yield any results, no need to disable it."^""; Exit 0; }; $serviceName = $service.Name; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, attempting to stop it."^""; try { Write-Host "^""Stopping the service `"^""$serviceName`"^""."^""; $stopParams = @{ Name = $ServiceName; Force = $true; ErrorAction = 'Stop'; }; if (-not $stopWithDependencies) { $stopParams['NoWait'] = $true; }; Stop-Service @stopParams; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { if ($_.FullyQualifiedErrorId -eq 'CouldNotStopService,Microsoft.PowerShell.Commands.StopServiceCommand') { Write-Warning "^""The service `"^""$serviceName`"^"" does not accept a stop command and may need to be stopped manually or on reboot."^""; } else { Write-Warning "^""Failed to stop service `"^""$ServiceName`"^"". It will be stopped after reboot. Error: $($_.Exception.Message)"^""; }; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = "^""HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"^""; if (-Not (Test-Path $registryKey)) { Write-Host "^""`"^""$registryKey`"^"" is not found in registry, cannot enable it."^""; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path "^""$registryKey"^"").Start -eq 4) { Write-Host "^""`"^""$serviceName`"^"" is already disabled from start, no further action is needed."^""; Exit 0; }; <# -- 5. Disable service #>; try { Set-ItemProperty -LiteralPath $registryKey -Name "^""Start"^"" -Value 4 -ErrorAction Stop; Write-Host 'Successfully disabled the service. It will not start automatically on next boot.'; } catch { Write-Error "^""Failed to disable the service. Error: $($_.Exception.Message)"^""; Exit 1; }"
:: ----------------------------------------------------------


:: Disable Shadow Copy (breaks System Restore and Windows Backup)
echo --- Disable Shadow Copy (breaks System Restore and Windows Backup)
:: Disable service(s): `VSS`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'VSS'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
:: ----------------------------------------------------------
