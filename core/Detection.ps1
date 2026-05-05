# ==============================
# Trivor Installer - Detection.ps1
# ==============================

#region Registry helpers

function Get-TrivorLoggedOnUserSID {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $userName = $cs.UserName
        if ([string]::IsNullOrWhiteSpace($userName)) { return $null }
        $parts  = $userName -split '\\'
        $domain = if ($parts.Count -ge 2) { $parts[0] } else { $env:COMPUTERNAME }
        $user   = if ($parts.Count -ge 2) { $parts[1] } else { $parts[0] }
        $sid = (New-Object System.Security.Principal.NTAccount($domain, $user)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        return $sid
    }
    catch {
        Write-Log "Falha ao obter SID do usuario logado: $($_.Exception.Message)" "DEBUG"
        return $null
    }
}

function Get-RegistryUninstallPaths {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    if (-not (Test-TrivorSystemContext)) {
        $paths += "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        return $paths
    }

    # Contexto SYSTEM: adiciona hive do usuario logado via SID
    $sid = Get-TrivorLoggedOnUserSID
    if ($sid) {
        $paths += "Registry::HKU\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $paths += "Registry::HKU\$sid\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    return $paths
}

function Find-AppInRegistry {
    # Retorna o objeto de registro do app ou $null
    param([Parameter(Mandatory)] [string]$DisplayName)
    foreach ($path in (Get-RegistryUninstallPaths)) {
        try {
            $app = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*$DisplayName*" } |
                   Select-Object -First 1
            if ($app) { return $app }
        } catch {}
    }
    return $null
}

#endregion

#region Winget (cache em lote — executado UMA vez por sessao)

$global:TrivorWingetListCache      = $null
$global:TrivorWingetListCacheReady = $false

function Initialize-WingetListCache {
    if ($global:TrivorWingetListCacheReady) { return }

    $global:TrivorWingetListCacheReady = $true  # marca antes para evitar loop

    if (Test-TrivorSystemContext) {
        # RMM/SYSTEM: roda winget list como usuario logado (1 task para tudo)
        Write-Log "Carregando lista winget via usuario logado (RMM)..." "INFO"
        $result = Invoke-WingetAsUser -Arguments "list --accept-source-agreements" -OperationName "list_all_detect"

        if ($result.StdOut -and (Test-Path $result.StdOut)) {
            try {
                $global:TrivorWingetListCache = Get-Content $result.StdOut -Raw -ErrorAction SilentlyContinue
                Write-Log "Lista winget carregada ($($global:TrivorWingetListCache.Length) bytes)" "INFO"
            } catch {
                Write-Log "Falha ao ler lista winget: $($_.Exception.Message)" "WARN"
            }
        } else {
            Write-Log "Winget indisponivel no contexto RMM. Usando apenas Registry para deteccao." "WARN"
        }
        return
    }

    # Contexto normal: winget direto
    $wingetExe = $global:TrivorWingetExe
    if (-not $wingetExe) {
        $wingetExe = Get-Command winget.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    }
    if (-not $wingetExe) {
        Write-Log "Winget nao encontrado. Usando apenas Registry para deteccao." "WARN"
        return
    }

    try {
        Write-Log "Carregando lista winget..." "INFO"
        $global:TrivorWingetListCache = (& $wingetExe list --accept-source-agreements 2>$null) -join "`n"
        Write-Log "Lista winget carregada." "INFO"
    } catch {
        Write-Log "Falha ao carregar lista winget: $($_.Exception.Message)" "WARN"
    }
}

function Test-WingetInCache {
    param([string]$WingetId)
    if ([string]::IsNullOrWhiteSpace($global:TrivorWingetListCache)) { return $false }
    return ($global:TrivorWingetListCache -match [regex]::Escape($WingetId))
}

function Get-WingetVersionFromCache {
    param([string]$WingetId)
    if ([string]::IsNullOrWhiteSpace($global:TrivorWingetListCache)) { return $null }
    foreach ($line in ($global:TrivorWingetListCache -split "`n")) {
        if ($line -match [regex]::Escape($WingetId)) {
            $parts = $line -split '\s{2,}'
            if ($parts.Count -ge 3) { return $parts[2].Trim() }
        }
    }
    return $null
}

#endregion

#region Registry detection

function Test-RegistryApp {
    param([Parameter(Mandatory)] [string]$DisplayName)
    $app = Find-AppInRegistry -DisplayName $DisplayName
    if ($app) { Write-Log "Registry detected: $DisplayName" "DEBUG"; return $true }
    return $false
}

function Get-RegistryAppVersion {
    param([Parameter(Mandatory)] [string]$DisplayName)
    $app = Find-AppInRegistry -DisplayName $DisplayName
    if ($app -and $app.DisplayVersion) { return [string]$app.DisplayVersion }
    return $null
}

#endregion

#region EXE

function Test-ExeApp {
    param([Parameter(Mandatory)] [string]$Path, [string]$MinVersion)

    if (-not (Test-Path $Path)) { return $false }
    if (-not $MinVersion) { Write-Log "Exe detected: $Path" "DEBUG"; return $true }

    try {
        $fv = (Get-Item $Path).VersionInfo.FileVersion
        if ($fv) {
            if ([version]$fv -ge [version]$MinVersion) {
                Write-Log "Exe detected (ok): $Path ($fv)" "DEBUG"; return $true
            }
            Write-Log "Exe versao antiga: $Path ($fv < $MinVersion)" "DEBUG"; return $false
        }
    } catch {
        Write-Log "Exe detected (sem versao): $Path" "DEBUG"; return $true
    }
    return $true
}

#endregion

#region Service

function Test-ServiceApp {
    param([string]$ServiceName, [string]$DisplayName)
    try {
        if ($ServiceName) {
            if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
                Write-Log "Service detected: $ServiceName" "DEBUG"; return $true
            }
        }
        if ($DisplayName) {
            if (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$DisplayName*" }) {
                Write-Log "Service detected: $DisplayName" "DEBUG"; return $true
            }
        }
    } catch {}
    return $false
}

#endregion

#region RegistryKey

function Test-RegistryKey {
    param([Parameter(Mandatory)] [string]$KeyPath)
    try {
        if (Get-Item -Path $KeyPath -ErrorAction SilentlyContinue) {
            Write-Log "RegistryKey detected: $KeyPath" "DEBUG"; return $true
        }
    } catch {}
    return $false
}

#endregion

#region State

function Get-ApplicationState {
    param([Parameter(Mandatory)] $App)

    $state = @{ Installed = $false; Source = $null; Version = $null }

    $hasWingetId = ($App.PSObject.Properties.Match("WingetId").Count -gt 0 -and $App.WingetId)

    # --- 1) Tenta deteccao via winget (cache) ---
    if ($hasWingetId) {
        Initialize-WingetListCache

        if (Test-WingetInCache -WingetId $App.WingetId) {
            $state.Installed = $true
            $state.Source    = "Winget"
            $v = Get-WingetVersionFromCache -WingetId $App.WingetId
            if ($v) { $state.Version = $v }
            return $state
        }
    }

    # --- 2) Fallback registry por nome do app (sempre tenta, mesmo sem Detection) ---
    # Util quando winget nao esta disponivel no contexto de execucao (RMM/SYSTEM)
    if ($hasWingetId -or ($App.PSObject.Properties.Match("Detection").Count -eq 0 -or -not $App.Detection)) {
        $appName = $App.Name
        if (-not [string]::IsNullOrWhiteSpace($appName)) {
            $regApp = Find-AppInRegistry -DisplayName $appName
            if ($regApp) {
                Write-Log "Registry fallback detected: $appName" "DEBUG"
                $state.Installed = $true
                $state.Source    = "Registry"
                if ($regApp.DisplayVersion) { $state.Version = [string]$regApp.DisplayVersion }
                return $state
            }
        }
    }

    # --- 3) Sem Detection definida, nao ha mais o que tentar ---
    if ($App.PSObject.Properties.Match("Detection").Count -eq 0 -or -not $App.Detection) {
        return $state
    }

    # --- 4) Detection explicita ---
    $d      = $App.Detection
    $method = $d.Method

    if ($method -eq "Hybrid") {
        if ($d.RegistryDisplayName -and (Test-RegistryApp -DisplayName $d.RegistryDisplayName)) {
            $state.Installed = $true; $state.Source = "Registry"
            $state.Version = Get-RegistryAppVersion -DisplayName $d.RegistryDisplayName
            return $state
        }
        if (($d.ServiceName -or $d.ServiceDisplayName) -and
            (Test-ServiceApp -ServiceName $d.ServiceName -DisplayName $d.ServiceDisplayName)) {
            $state.Installed = $true; $state.Source = "Service"
            return $state
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
            $state.Installed = $true; $state.Source = "RegistryKey"
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