# ==============================
# Trivor Installer - Detection.ps1
# ==============================

#region Winget
function Test-WingetApp {
    param([Parameter(Mandatory)] [string]$WingetId)
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

function Get-WingetState {
    param(
        [Parameter(Mandatory)]
        [string]$WingetId
    )

    try {
        $result = Invoke-WingetAsUser `
            -Arguments "list --id `"$WingetId`" --exact --source winget --accept-source-agreements --disable-interactivity" `
            -OperationName "detect_$WingetId"

        if (-not $result.Success) { return $null }
        if (-not $result.StdOut -or -not (Test-Path $result.StdOut)) { return $null }

        $output = Get-Content $result.StdOut -Raw -ErrorAction SilentlyContinue

        if ([string]::IsNullOrWhiteSpace($output)) { return $null }

        if ($output -match $WingetId) {

            $lines = $output -split "`n"
            $matchLine = $lines | Where-Object { $_ -match $WingetId } | Select-Object -First 1

            $version = $null
            if ($matchLine) {
                $parts = ($matchLine -replace '\s+', ' ').Trim().Split(' ')
                if ($parts.Count -ge 3) {
                    $version = $parts[2]
                }
            }

            return [pscustomobject]@{
                Installed = $true
                Source    = "Winget(User)"
                Version   = $version
            }
        }

        return $null
    }
    catch {
        Write-Log ("Erro Winget detection: {0}" -f $_.Exception.Message) "WARN"
        return $null
    }
}