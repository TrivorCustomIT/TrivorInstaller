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

    $files = Get-ChildItem $clientsPath -Filter *.json | Where-Object { $_.Name -ne "_manifest.json" } | Sort-Object Name
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

    return Get-Content $file -Raw | ConvertFrom-Json
}

function Show-ClientSubMenu {
    param([Parameter(Mandatory)] [string]$ClientName)

    while ($true) {
        Clear-Host
        Show-Banner

        Write-Host "Cliente: $ClientName"
        Write-Host ""
        Write-Host "1 - Modo automatico (instalar e atualizar tudo)"
        Write-Host "2 - Modo manual (confirmar cada app)"
        Write-Host "3 - Voltar ao menu principal"
        Write-Host ""

        $choice = Read-Host "Selecione uma opcao"

        if ($choice -eq "3") { return }

        $cfg = Get-ClientConfigByName -ClientName $ClientName
        if (-not $cfg) {
            Write-Host "Configuracao do cliente nao encontrada."
            Wait-Enter
            return
        }

        if ($choice -eq "1") {
            Invoke-ClientInstallation -ClientConfig $cfg
            Write-Host ""
            Write-Host "Concluido."
            Wait-Enter
            continue
        }

        if ($choice -eq "2") {
            Invoke-ClientManualInstall -ClientConfig $cfg
            Write-Host ""
            Write-Host "Concluido."
            Wait-Enter
            continue
        }

        Write-Host "Opcao invalida."
        Wait-Enter
    }
}

function Start-MainMenu {
    while ($true) {
        Clear-Host
        Show-Banner

        $clients = Get-ClientList
        if ($clients.Count -eq 0) {
            Write-Host "Nenhum cliente encontrado na pasta Clientes."
            Wait-Enter
            return
        }

        Write-Host "Selecione um cliente:"
        Write-Host ""

        $map = @{}
        $i = 1
        foreach ($c in $clients) {
            Write-Host ("[{0}] {1}" -f $i, $c)
            $map[$i] = $c
            $i++
        }

        Write-Host ""
        Write-Host "[0] Sair"
        Write-Host ""

        $choice = Read-Host "Digite o numero"

        if ($choice -eq "0") { return }

        $num = 0
        if (-not [int]::TryParse($choice, [ref]$num) -or -not $map.ContainsKey($num)) {
            Write-Host "Opcao invalida."
            Wait-Enter
            continue
        }

        Show-ClientSubMenu -ClientName $map[$num]
    }
}
