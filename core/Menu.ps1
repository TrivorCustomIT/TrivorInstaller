# ==============================
# Trivor Installer - Menu.ps1
# ==============================

function Wait-Enter {
    Read-Host "Pressione Enter para continuar" | Out-Null
}

function Get-ClientsPath {
    return Join-Path $env:TEMP "TrivorInstaller\Clientes"
}

function Get-ClientList {
    $clientsPath = Get-ClientsPath

    if (-not (Test-Path $clientsPath)) {
        Write-Log "Clients folder not found: $clientsPath" "ERROR"
        return @()
    }

    $files = Get-ChildItem $clientsPath -Filter *.json | Sort-Object Name
    return $files | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }
}

function Get-ClientConfigByName {
    param([Parameter(Mandatory)] [string]$ClientName)

    $clientsPath = Get-ClientsPath
    $file = Join-Path $clientsPath "$ClientName.json"

    if (-not (Test-Path $file)) {
        Write-Log "Client config not found: $file" "ERROR"
        return $null
    }

    try {
        $content = Get-Content $file -Raw -Encoding UTF8
        return $content | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Host "[ERROR] Falha ao ler JSON do cliente '${ClientName}':" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "Arquivo: $file" -ForegroundColor Yellow
        Write-Host ""
        Wait-Enter
        return $null
    }
}

function Get-AppManualMenuStatus {
    param([Parameter(Mandatory)] $App)

    $result = [ordered]@{
        Installed = $false
        Source    = ""
        Version   = ""
        Status    = "NAO INSTALADO"
        Marker    = "--"
        Color     = "Red"
    }

    try {
        $state = Get-ApplicationState -App $App

        if ($state) {
            $result.Installed = [bool]$state.Installed
            if ($state.Source)  { $result.Source  = [string]$state.Source }
            if ($state.Version) { $result.Version = [string]$state.Version }

            if ($result.Installed) {
                $result.Status = "INSTALADO"
                $result.Marker = "OK"
                $result.Color  = "Green"

                try {
                    if (Get-Command Should-ForceReinstallByVersion -ErrorAction SilentlyContinue) {
                        if (Should-ForceReinstallByVersion -App $App -State $state) {
                            $result.Status = "VERSAO ANTIGA"
                            $result.Marker = "!!"
                            $result.Color  = "Yellow"
                        }
                    }
                }
                catch {}
            }
        }
    }
    catch {
        $result.Status = "ERRO DETECCAO"
        $result.Marker = "??"
        $result.Color  = "DarkYellow"
        try { Write-Log "Erro ao detectar status de $($App.Name): $($_.Exception.Message)" "WARN" } catch {}
    }

    return [pscustomobject]$result
}

function Show-AppGrid {
    param([Parameter(Mandatory)] [array]$Apps)

    Write-Host "Apps disponiveis:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Legenda: [OK] Instalado | [--] Nao instalado | [!!] Versao antiga" -ForegroundColor DarkGray
    Write-Host ""

    $global:TrivorManualStatusCache = @{}

    $header = "{0,4}  {1,-4} {2,-48} {3,-16} {4,-12} {5}" -f "Num", "St", "Aplicacao", "Status", "Fonte", "Versao"
    Write-Host $header -ForegroundColor DarkCyan
    Write-Host ("-" * ([Math]::Min($header.Length, 118))) -ForegroundColor DarkGray

    for ($idx = 0; $idx -lt $Apps.Count; $idx++) {
        $app = $Apps[$idx]
        $status = Get-AppManualMenuStatus -App $app

        $key = if ($app.Id) { [string]$app.Id } else { [string]($idx + 1) }
        $global:TrivorManualStatusCache[$key] = $status

        $source = if ($status.Source) { $status.Source } else { "-" }
        $version = if ($status.Version) { $status.Version } else { "-" }

        $line = "[{0,2}]  [{1}] {2,-48} {3,-16} {4,-12} {5}" -f ($idx + 1), $status.Marker, $app.Name, $status.Status, $source, $version
        Write-Host $line -ForegroundColor $status.Color
    }

    Write-Host ""
    Write-Host "  [0] Cancelar" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-ClientMenu {
    param([Parameter(Mandatory)] [string]$ClientName)

    while ($true) {
        Clear-Host
        Show-Banner

        Write-Host "Cliente: $ClientName" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1 - Modo automatico (renomear + instalar tudo)"
        Write-Host "2 - Modo manual (confirmar cada app)"
        Write-Host "3 - Update todos os programas (Winget)"
        Write-Host "4 - Renomear hostname"
        Write-Host "5 - Voltar ao menu principal"
        Write-Host ""

        $choice = Read-Host "Selecione uma opcao"

        if ($choice -eq "5") { return }

        $cfg = Get-ClientConfigByName -ClientName $ClientName
        if (-not $cfg) { return }

        if ($choice -eq "1") {
            Invoke-HostnameCheck -ClientConfig $cfg
            Invoke-ClientInstallation -ClientConfig $cfg
            Write-Host ""
            Write-Host "Concluido." -ForegroundColor Green
            Wait-Enter
            continue
        }

        if ($choice -eq "2") {
            Clear-Host
            Show-Banner
            Write-Host "Cliente: $ClientName" -ForegroundColor Cyan
            Write-Host ""

            $apps = $cfg.Applications
            if (-not $apps -or $apps.Count -eq 0) {
                Write-Host "Nenhum app encontrado para este cliente." -ForegroundColor Yellow
                Wait-Enter
                continue
            }

            Show-AppGrid -Apps $apps

            $appChoice = Read-Host "Digite o numero do app (ou 0 para cancelar)"

            if ($appChoice -eq "0") { continue }

            $appNum = 0
            if (-not [int]::TryParse($appChoice, [ref]$appNum) -or $appNum -lt 1 -or $appNum -gt $apps.Count) {
                Write-Host "Opcao invalida." -ForegroundColor Red
                Wait-Enter
                continue
            }

            $selectedApp = $apps[$appNum - 1]
            Write-Host ""
            Invoke-AppActionManual -App $selectedApp | Out-Null
            Write-Host ""
            Wait-Enter
            continue
        }

        if ($choice -eq "3") {
            Invoke-ClientUpdateOnly -ClientConfig $cfg
            Write-Host ""
            Write-Host "Concluido." -ForegroundColor Green
            Wait-Enter
            continue
        }

        if ($choice -eq "4") {
            Invoke-HostnameCheck -ClientConfig $cfg
            Write-Host ""
            Wait-Enter
            continue
        }

        Write-Host "Opcao invalida." -ForegroundColor Red
        Wait-Enter
    }
}

function Show-ClientGrid {
    param([Parameter(Mandatory)] [array]$Clients)

    $cols      = 3
    $termWidth = $Host.UI.RawUI.WindowSize.Width
    $colWidth  = [math]::Floor(($termWidth - 4) / $cols)

    $total = $clients.Count
    $rows  = [math]::Ceiling($total / $cols)

    Write-Host "Selecione um cliente:" -ForegroundColor Cyan
    Write-Host ""

    for ($row = 0; $row -lt $rows; $row++) {
        $line = ""
        for ($col = 0; $col -lt $cols; $col++) {
            $idx = $row + ($col * $rows)
            if ($idx -lt $total) {
                $num  = $idx + 1
                $name = $clients[$idx]
                $cell = "[{0,2}] {1}" -f $num, $name
                $line += $cell.PadRight($colWidth)
            }
        }
        Write-Host $line
    }

    Write-Host ""
    Write-Host "  [0] Sair" -ForegroundColor DarkGray
    Write-Host ""
}

function Start-MainMenu {
    while ($true) {
        Clear-Host
        Show-Banner

        $clients = Get-ClientList
        if ($clients.Count -eq 0) {
            Write-Host "Nenhum cliente encontrado na pasta Clientes." -ForegroundColor Red
            Wait-Enter
            return
        }

        Show-ClientGrid -Clients $clients

        $choice = Read-Host "Digite o numero"

        if ($choice -eq "0") {
            Invoke-Cleanup
            return
        }

        $num = 0
        if (-not [int]::TryParse($choice, [ref]$num) -or $num -lt 1 -or $num -gt $clients.Count) {
            Write-Host "Opcao invalida." -ForegroundColor Red
            Wait-Enter
            continue
        }

        $selected = $clients[$num - 1]
        Show-ClientMenu -ClientName $selected
    }
}
