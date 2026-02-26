# ==============================
# Trivor Installer - Detection.ps1
# Supports: Winget, Registry (with version), EXE (with optional MinVersion), Service, Hybrid (Registry OR Service)
# ==============================

#region Winget
function Test-WingetApp {
    param (
        [Parameter(Mandatory)]
        [string]$WingetId
    )

    try {
        $result = winget list --id $WingetId --exact --accept-source-agreements 2>$null
        if ($result -match [regex]::Escape($WingetId)) {
            Write-Log "Winget detected: $WingetId" "INFO"
            return $true
        }
    } catch {}

    return $false
}
#endregion

#region Registry
function Test-RegistryApp {
    param (
        [Parameter(Mandatory)]
        [string]$DisplayName
    )

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
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*$DisplayName*" }

        foreach ($a in $apps) {
            if ($a.DisplayVersion) {
                return [string]$a.DisplayVersion
            }
        }
    }

    return $null
}
#endregion

#region EXE
function Test-ExeApp {
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$MinVersion
    )

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
        # If version read fails, consider installed to avoid loops
        Write-Log "Exe detected (version check failed): $Path" "WARN"
        return $true
    }

    Write-Log "Exe detected: $Path" "INFO"
    return $true
}
#endregion

#region Service
function Test-ServiceApp {
    param(
        [string]$ServiceName,
        [string]$DisplayName
    )

    try {
        if ($ServiceName) {
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc) {
                Write-Log "Service detected: $ServiceName" "INFO"
                return $true
            }
        }

        if ($DisplayName) {
            $svc2 = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($svc2) {
                Write-Log "Service detected by DisplayName: $DisplayName" "INFO"
                return $true
            }
        }
    } catch {}

    return $false
}
#endregion

#region State
function Get-ApplicationState {
    param(
        [Parameter(Mandatory)]
        $App
    )

    $state = @{
        Installed = $false
        Source    = $null
        Version   = $null
    }

    # 1) Winget priority
    if ($App.PSObject.Properties.Match("WingetId").Count -gt 0 -and $App.WingetId) {
        if (Test-WingetApp -WingetId $App.WingetId) {
            $state.Installed = $true
            $state.Source    = "Winget"
            return $state
        }
    }

    # 2) No detection block
    if ($App.PSObject.Properties.Match("Detection").Count -eq 0 -or -not $App.Detection) {
        return $state
    }

    $d = $App.Detection
    $method = $d.Method

    # 3) Hybrid: Registry OR Service
    if ($method -eq "Hybrid") {

        if ($d.RegistryDisplayName) {
            if (Test-RegistryApp -DisplayName $d.RegistryDisplayName) {
                $state.Installed = $true
                $state.Source    = "Registry"
                $state.Version   = Get-RegistryAppVersion -DisplayName $d.RegistryDisplayName
                return $state
            }
        }

        if ($d.ServiceName -or $d.ServiceDisplayName) {
            if (Test-ServiceApp -ServiceName $d.ServiceName -DisplayName $d.ServiceDisplayName) {
                $state.Installed = $true
                $state.Source    = "Service"
                return $state
            }
        }

        return $state
    }

    # 4) Registry
    if ($method -eq "Registry" -and $d.DisplayName) {
        if (Test-RegistryApp -DisplayName $d.DisplayName) {
            $state.Installed = $true
            $state.Source    = "Registry"
            $state.Version   = Get-RegistryAppVersion -DisplayName $d.DisplayName
            return $state
        }
        return $state
    }

    # 5) Exe
    if ($method -eq "Exe" -and $d.Path) {
        if (Test-ExeApp -Path $d.Path -MinVersion $d.MinVersion) {
            $state.Installed = $true
            $state.Source    = "Exe"
            return $state
        }
        return $state
    }

    # 6) Service
    if ($method -eq "Service") {
        if (Test-ServiceApp -ServiceName $d.ServiceName -DisplayName $d.ServiceDisplayName) {
            $state.Installed = $true
            $state.Source    = "Service"
            return $state
        }
        return $state
    }

    return $state
}

function Test-ApplicationInstalled {
    param(
        [Parameter(Mandatory)]
        $App
    )
    $s = Get-ApplicationState -App $App
    return [bool]$s.Installed
}
#endregion
