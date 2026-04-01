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

function Show-ClientMenu {
    param([Parameter(Mandatory)] [string]$ClientName)

    while ($true) {
        Clear-Host
        Show-Banner

        Write-Host "Cliente: $ClientName" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1 - Modo automatico (instalar tudo)"
        Write-Host "2 - Modo manual (confirmar cada app)"
        Write-Host "3 - Update todos os programas (Winget)"
        Write-Host "4 - Voltar ao menu principal"
        Write-Host ""

        $choice = Read-Host "Selecione uma opcao"

        if ($choice -eq "4") { return }

        $cfg = Get-ClientConfigByName -ClientName $ClientName
        if (-not $cfg) { return }

        if ($choice -eq "1") {
            Invoke-ClientInstallation -ClientConfig $cfg
            Write-Host ""
            Write-Host "Concluido." -ForegroundColor Green
            Wait-Enter
            continue
        }

        if ($choice -eq "2") {
            Invoke-ClientManualInstall -ClientConfig $cfg
            Write-Host ""
            Write-Host "Concluido." -ForegroundColor Green
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
