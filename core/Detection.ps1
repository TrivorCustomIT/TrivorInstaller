# ==============================
# Trivor Installer - Detection.ps1
# ==============================

#region Helpers para contexto SYSTEM/RMM

function Get-TrivorLoggedOnUserSID {
    # Retorna o SID do usuario interativo logado (para acessar HKU\<SID> no contexto SYSTEM)
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $userName = $cs.UserName
        if ([string]::IsNullOrWhiteSpace($userName)) { return $null }

        # userName = "DOMINIO\usuario" ou "MAQUINA\usuario"
        $parts = $userName -split '\\'
        $domain = if ($parts.Count -ge 2) { $parts[0] } else { $env:COMPUTERNAME }
        $user   = if ($parts.Count -ge 2) { $parts[1] } else { $parts[0] }

        $objUser = New-Object System.Security.Principal.NTAccount($domain, $user)
        $sid = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
        return $sid
    }
    catch {
        Write-Log "Falha ao obter SID do usuario logado: $($_.Exception.Message)" "DEBUG"
        return $null
    }
}

function Get-RegistryUninstallPaths {
    # Retorna os caminhos de Uninstall a serem verificados,
    # incluindo o hive do usuario logado quando rodando como SYSTEM/RMM
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    # Contexto interativo normal: inclui HKCU do processo atual
    if (-not (Test-TrivorSystemContext)) {
        $paths += "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        return $paths
    }

    # Contexto SYSTEM/RMM: tenta carregar HKU\<SID> do usuario logado
    $sid = Get-TrivorLoggedOnUserSID
    if ($sid) {
        $huPath = "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $huPathWow = "Registry::HKU\$sid\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $paths += $huPath
        $paths += $huPathWow
        Write-Log "Registry: incluindo hive do usuario logado SID=$sid" "DEBUG"
    }

    return $paths
}

#endregion

#region Winget
function Test-WingetApp {
    param([Parameter(Mandatory)] [string]$WingetId)

    # Contexto SYSTEM/RMM: executa winget list como usuario logado via Scheduled Task
    if (Test-TrivorSystemContext) {
        $result = Invoke-WingetAsUser `
            -Arguments "list --id `"$WingetId`" --exact --accept-source-agreements" `
            -OperationName "detect_$WingetId"

        if ($result.Success -or $result.ExitCode -eq 0) {
            # Verifica no stdout se o app realmente apareceu
            $out = ""
            if ($result.StdOut -and (Test-Path $result.StdOut)) {
                try { $out = Get-Content $result.StdOut -Raw -ErrorAction SilentlyContinue } catch {}
            }
            if ($out -match [regex]::Escape($WingetId)) {
                Write-Log "Winget detected (RMM): $WingetId" "DEBUG"
                return $true
            }
        }
        return $false
    }

    # Contexto normal: chama winget diretamente
    try {
        $wingetExe = $global:TrivorWingetExe
        if (-not $wingetExe) {
            $wingetExe = Get-Command winget.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        }
        if (-not $wingetExe) { return $false }

        $result = & $wingetExe list --id $WingetId --exact --accept-source-agreements 2>$null
        if ($result -match [regex]::Escape($WingetId)) {
            Write-Log "Winget detected: $WingetId" "DEBUG"
            return $true
        }
    } catch {}
    return $false
}

function Get-WingetAppVersion {
    param([Parameter(Mandatory)] [string]$WingetId)

    try {
        $wingetExe = $global:TrivorWingetExe
        if (-not $wingetExe -and -not (Test-TrivorSystemContext)) {
            $wingetExe = Get-Command winget.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        }
        if (-not $wingetExe) { return $null }

        $lines = & $wingetExe list --id $WingetId --exact --accept-source-agreements 2>$null
        foreach ($line in $lines) {
            if ($line -match [regex]::Escape($WingetId)) {
                # Tenta extrair versao da saida tabular do winget
                $parts = $line -split '\s{2,}'
                if ($parts.Count -ge 3) { return $parts[2].Trim() }
            }
        }
    } catch {}
    return $null
}
#endregion

#region Registry
function Test-RegistryApp {
    param([Parameter(Mandatory)] [string]$DisplayName)

    $paths = Get-RegistryUninstallPaths

    foreach ($path in $paths) {
        try {
            $app = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($app) {
                Write-Log "Registry detected: $DisplayName" "DEBUG"
                return $true
            }
        } catch {}
    }
    return $false
}

function Get-RegistryAppVersion {
    param([Parameter(Mandatory)] [string]$DisplayName)

    $paths = Get-RegistryUninstallPaths

    foreach ($path in $paths) {
        try {
            $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like "*$DisplayName*" }
            foreach ($a in $apps) {
                if ($a.DisplayVersion) { return [string]$a.DisplayVersion }
            }
        } catch {}
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
    param([Parameter(Mandatory)] [string]$KeyPath)

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
            $state.Installed = $true
            $state.Source    = "Winget"
            $v = Get-WingetAppVersion -WingetId $App.WingetId
            if ($v) { $state.Version = $v }
            return $state
        }
    }

    if ($App.PSObject.Properties.Match("Detection").Count -eq 0 -or -not $App.Detection) { return $state }

    $d      = $App.Detection
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