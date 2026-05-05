# ==============================
# Trivor Installer - Detection.ps1
# ==============================

#region Winget
function Get-WingetAppState {
    param([Parameter(Mandatory)] [string]$WingetId)

    if (-not $global:TrivorWingetDetectionCache) {
        $global:TrivorWingetDetectionCache = @{}
    }

    if ($global:TrivorWingetDetectionCache.ContainsKey($WingetId)) {
        return $global:TrivorWingetDetectionCache[$WingetId]
    }

    $state = [pscustomobject]@{
        Installed = $false
        Source    = $null
        Version   = $null
        RawOutput = $null
    }

    try {
        $result = $null
        $output = $null
        $source = "Winget"

        if (Get-Command Invoke-WingetAsUser -ErrorAction SilentlyContinue) {
            $result = Invoke-WingetAsUser `
                -Arguments "list --id `"$WingetId`" --exact --source winget --accept-source-agreements --disable-interactivity" `
                -OperationName "detect_$WingetId"

            if ($result -and $result.StdOut -and (Test-Path $result.StdOut)) {
                $output = Get-Content $result.StdOut -Raw -ErrorAction SilentlyContinue
                if (Get-Command Test-TrivorSystemContext -ErrorAction SilentlyContinue) {
                    if (Test-TrivorSystemContext) { $source = "Winget(User)" }
                }
            }
        }
        else {
            $output = winget list --id $WingetId --exact --source winget --accept-source-agreements --disable-interactivity 2>$null | Out-String
        }

        $state.RawOutput = $output

        if (-not [string]::IsNullOrWhiteSpace($output) -and $output -match [regex]::Escape($WingetId)) {
            $version = $null
            $lines = $output -split "`r?`n"
            $matchLine = $lines | Where-Object { $_ -match [regex]::Escape($WingetId) } | Select-Object -First 1

            if ($matchLine) {
                $normalized = ($matchLine -replace '\s+', ' ').Trim()
                $parts = $normalized.Split(' ')

                $idIndex = -1
                for ($idx = 0; $idx -lt $parts.Count; $idx++) {
                    if ($parts[$idx] -eq $WingetId) {
                        $idIndex = $idx
                        break
                    }
                }

                if ($idIndex -ge 0 -and ($idIndex + 1) -lt $parts.Count) {
                    $version = $parts[$idIndex + 1]
                }
            }

            $state = [pscustomobject]@{
                Installed = $true
                Source    = $source
                Version   = $version
                RawOutput = $output
            }

            Write-Log ("{0} detected: {1}" -f $source, $WingetId) "INFO"
        }
    }
    catch {
        Write-Log ("Winget detection failed for {0}: {1}" -f $WingetId, $_.Exception.Message) "WARN"
    }

    $global:TrivorWingetDetectionCache[$WingetId] = $state
    return $state
}

function Test-WingetApp {
    param([Parameter(Mandatory)] [string]$WingetId)
    $state = Get-WingetAppState -WingetId $WingetId
    return [bool]$state.Installed
}
#endregion

#region Registry
function Test-RegistryApp {
    param([Parameter(Mandatory)] [string]$DisplayName)

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        $app = Get-ItemProperty $path -ErrorAction SilentlyContinue |
               Where-Object { $_.DisplayName -like "*$DisplayName*" }
        if ($app) {
            Write-Log "Registry detected: $DisplayName" "INFO"
            return $true
        }
    }
    return $false
}

function Get-RegistryAppVersion {
    param([Parameter(Mandatory)] [string]$DisplayName)

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*$DisplayName*" }
        foreach ($a in $apps) {
            if ($a.DisplayVersion) { return [string]$a.DisplayVersion }
        }
    }
    return $null
}
#endregion

#region EXE
function Test-ExeApp {
    param([Parameter(Mandatory)] [string]$Path, [string]$MinVersion)

    if (-not (Test-Path $Path)) { return $false }

    if (-not $MinVersion) {
        Write-Log "Exe detected: $Path" "INFO"
        return $true
    }

    try {
        $fileVersion = (Get-Item $Path).VersionInfo.FileVersion
        if ($fileVersion) {
            if ([version]$fileVersion -ge [version]$MinVersion) {
                Write-Log "Exe detected (version ok): $Path ($fileVersion >= $MinVersion)" "INFO"
                return $true
            } else {
                Write-Log "Exe detected but version is old: $Path ($fileVersion < $MinVersion)" "WARN"
                return $false
            }
        }
    } catch {
        Write-Log "Exe detected (version check failed): $Path" "WARN"
        return $true
    }

    return $true
}
#endregion

#region Service
function Test-ServiceApp {
    param([string]$ServiceName, [string]$DisplayName)

    try {
        if ($ServiceName) {
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc) { Write-Log "Service detected: $ServiceName" "INFO"; return $true }
        }
        if ($DisplayName) {
            $svc2 = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($svc2) { Write-Log "Service detected by DisplayName: $DisplayName" "INFO"; return $true }
        }
    } catch {}
    return $false
}
#endregion


#region RegistryKey
function Test-RegistryKey {
    param(
        [Parameter(Mandatory)] [string]$KeyPath
    )

    try {
        $key = Get-Item -Path $KeyPath -ErrorAction SilentlyContinue
        if ($key) {
            Write-Log "RegistryKey detected: $KeyPath" "INFO"
            return $true
        }
    } catch {}

    return $false
}
#endregion

#region State
function Get-ApplicationState {
    param([Parameter(Mandatory)] $App)

    $state = @{ Installed = $false; Source = $null; Version = $null }

    if ($App.PSObject.Properties.Match("WingetId").Count -gt 0 -and $App.WingetId) {
        $wingetState = Get-WingetAppState -WingetId $App.WingetId
        if ($wingetState -and $wingetState.Installed) {
            $state.Installed = $true
            if ($wingetState.Source) { $state.Source = $wingetState.Source } else { $state.Source = "Winget" }
            $state.Version = $wingetState.Version
            return $state
        }
    }

    if ($App.PSObject.Properties.Match("Detection").Count -eq 0 -or -not $App.Detection) { return $state }

    $d = $App.Detection
    $method = $d.Method

    if ($method -eq "Hybrid") {
        if ($d.RegistryDisplayName -and (Test-RegistryApp -DisplayName $d.RegistryDisplayName)) {
            $state.Installed = $true; $state.Source = "Registry"
            $state.Version = Get-RegistryAppVersion -DisplayName $d.RegistryDisplayName
            return $state
        }
        if (($d.ServiceName -or $d.ServiceDisplayName) -and (Test-ServiceApp -ServiceName $d.ServiceName -DisplayName $d.ServiceDisplayName)) {
            $state.Installed = $true; $state.Source = "Service"; return $state
        }
        return $state
    }

    if ($method -eq "Registry" -and $d.DisplayName) {
        if (Test-RegistryApp -DisplayName $d.DisplayName) {
            $state.Installed = $true; $state.Source = "Registry"
            $state.Version = Get-RegistryAppVersion -DisplayName $d.DisplayName
        }
        return $state
    }

    if ($method -eq "Exe" -and $d.Path) {
        if (Test-ExeApp -Path $d.Path -MinVersion $d.MinVersion) {
            $state.Installed = $true; $state.Source = "Exe"
        }
        return $state
    }

    if ($method -eq "Service") {
        if (Test-ServiceApp -ServiceName $d.ServiceName -DisplayName $d.ServiceDisplayName) {
            $state.Installed = $true; $state.Source = "Service"
        }
        return $state
    }


    # 7) RegistryKey — verifica existencia de uma chave de registry
    if ($method -eq "RegistryKey" -and $d.KeyPath) {
        if (Test-RegistryKey -KeyPath $d.KeyPath) {
            $state.Installed = $true
            $state.Source    = "RegistryKey"
        }
        return $state
    }

    return $state
}

function Test-ApplicationInstalled {
    param([Parameter(Mandatory)] $App)
    return [bool](Get-ApplicationState -App $App).Installed
}
#endregion
