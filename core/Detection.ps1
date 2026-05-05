# ==============================
# Trivor Installer - Detection.ps1
# ==============================

#region Winget
function Test-WingetApp {
    param([Parameter(Mandatory)] [string]$WingetId)
    try {
        $result = winget list --id $WingetId --exact --accept-source-agreements 2>$null
        if ($result -match [regex]::Escape($WingetId)) {
            Write-Log "Winget detected: $WingetId" "DEBUG"
            return $true
        }
    } catch {}
    return $false
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
            Write-Log "Registry detected: $DisplayName" "DEBUG"
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
        Write-Log "Exe detected: $Path" "DEBUG"
        return $true
    }

    try {
        $fileVersion = (Get-Item $Path).VersionInfo.FileVersion
        if ($fileVersion) {
            if ([version]$fileVersion -ge [version]$MinVersion) {
                Write-Log "Exe detected (version ok): $Path ($fileVersion >= $MinVersion)" "DEBUG"
                return $true
            } else {
                Write-Log "Exe detected but version is old: $Path ($fileVersion < $MinVersion)" "DEBUG"
                return $false
            }
        }
    } catch {
        Write-Log "Exe detected (version check failed): $Path" "DEBUG"
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
            if ($svc) { Write-Log "Service detected: $ServiceName" "DEBUG"; return $true }
        }
        if ($DisplayName) {
            $svc2 = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($svc2) { Write-Log "Service detected by DisplayName: $DisplayName" "DEBUG"; return $true }
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
            Write-Log "RegistryKey detected: $KeyPath" "DEBUG"
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
        if (Test-WingetApp -WingetId $App.WingetId) {
            $state.Installed = $true; $state.Source = "Winget"; return $state
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