# ==============================
# Trivor Installer - Menu.ps1
# ==============================

function Wait-Enter {
    Read-Host "Pressione Enter para continuar" | Out-Null
}

function Get-ClientsPath {
    return Join-Path $global:TrivorBasePath "Clientes"
}

function Get-ClientList {
    if ($global:TrivorClientNames -and $global:TrivorClientNames.Count -gt 0) {
        return $global:TrivorClientNames
    }
    # Fallback: read from local cache
    $clientsPath = Get-ClientsPath
    if (-not (Test-Path $clientsPath)) {
        Write-Log "Clients folder not found: $clientsPath" "ERROR"
        return @()
    }
    $files = Get-ChildItem $clientsPath -Filter *.json | Sort-Object Name
    return $files | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }
}

function Test-ClientConfig {
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string]$ClientName
    )

    $errors = @()

    if ([string]::IsNullOrWhiteSpace($Config.Client)) {
        $errors += "Campo 'Client' ausente ou vazio"
    }

    if ($null -eq $Config.PSObject.Properties['Applications']) {
        $errors += "Campo 'Applications' ausente"
    }

    if ($errors.Count -gt 0) {
        Write-Host ""
        Write-Host "[ERROR] JSON do cliente '${ClientName}' com estrutura invalida:" -ForegroundColor Red
        foreach ($e in $errors) {
            Write-Host "  - $e" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Log "JSON invalido para cliente '${ClientName}': $($errors -join '; ')" "ERROR"
        return $false
    }

    return $true
}

function Get-ClientConfigByName {
    param([Parameter(Mandatory)] [string]$ClientName)

    $clientsPath = Get-ClientsPath
    $file = Join-Path $clientsPath "$ClientName.json"

    if (-not (Test-Path $file)) {
        if ($global:TrivorOwner -and $global:TrivorRepo -and $global:TrivorBranch) {
            $url = "https://raw.githubusercontent.com/$($global:TrivorOwner)/$($global:TrivorRepo)/$($global:TrivorBranch)/Clientes/$ClientName.json"
            try {
                New-Item -ItemType Directory -Force -Path $clientsPath | Out-Null
                Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing -ErrorAction Stop
                Write-Log "Downloaded client config: $ClientName" "INFO"
            }
            catch {
                Write-Host ""
                Write-Host "[ERROR] Falha ao baixar config do cliente '${ClientName}' do GitHub:" -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                Write-Host ""
                Wait-Enter
                return $null
            }
        } else {
            Write-Log "Client config not found: $file" "ERROR"
            return $null
        }
    }

    try {
        $content = Get-Content $file -Raw -Encoding UTF8
        $cfg = $content | ConvertFrom-Json -ErrorAction Stop
        if (-not (Test-ClientConfig -Config $cfg -ClientName $ClientName)) {
            Wait-Enter
            return $null
        }
        return $cfg
    }
    catch {
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

    $header = "{0,4}  {1,-4} {2,-48} {3,-16} {4,-12} {5}" -f "Num", "St", "Aplicacao", "Status", "Fonte", "Versao"
    Write-Host $header -ForegroundColor DarkCyan
    Write-Host ("-" * ([Math]::Min($header.Length, 118))) -ForegroundColor DarkGray

    for ($idx = 0; $idx -lt $Apps.Count; $idx++) {
        $app = $Apps[$idx]
        $status = Get-AppManualMenuStatus -App $app

        $source = if ($status.Source) { $status.Source } else { "-" }
        $version = if ($status.Version) { $status.Version } else { "-" }

        $line = "[{0,2}]  [{1}] {2,-48} {3,-16} {4,-12} {5}" -f ($idx + 1), $status.Marker, $app.Name, $status.Status, $source, $version
        Write-Host $line -ForegroundColor $status.Color
    }

    Write-Host ""
    Write-Host "  [0] Voltar" -ForegroundColor DarkGray
    Write-Host ""
}

#region Protecoes contra erro do analista (Guard.ps1)

$global:TrivorConfirmedClients = @{}

function Confirm-TrivorClientChoiceConsole {
    # Maquina parece de outro cliente (ou de mais de um): exige digitar o nome do cliente escolhido.
    param([Parameter(Mandatory)] [string]$ClientName)

    if (-not (Get-Command Test-TrivorClientChoice -ErrorAction SilentlyContinue)) { return $true }
    $check = Test-TrivorClientChoice -Selected $ClientName -Match $global:TrivorClientMatch
    if ($check -eq 'Ok' -or $global:TrivorConfirmedClients[$ClientName]) { return $true }

    $m = $global:TrivorClientMatch
    Write-Host ""
    Write-Host "==================== ATENCAO ====================" -ForegroundColor Yellow
    if ($check -eq 'Mismatch') {
        Write-Host ("Esta maquina parece ser do cliente {0}" -f $m.Client) -ForegroundColor Yellow
        Write-Host ("  motivo: {0}" -f ($m.Reasons -join '; ')) -ForegroundColor Yellow
    } else {
        Write-Host ("Mais de um cliente corresponde a esta maquina: {0}" -f ($m.Clients -join ', ')) -ForegroundColor Yellow
    }
    Write-Host ("Voce escolheu: {0}" -f $ClientName) -ForegroundColor Yellow
    Write-Host "Aplicar o cliente errado instala o agente RMM e renomeia o hostname para outro cliente." -ForegroundColor Yellow
    Write-Host "=================================================" -ForegroundColor Yellow
    $typed = Read-Host ("Para continuar com {0}, digite o nome do cliente (Enter cancela)" -f $ClientName)

    if ($typed -and $typed.Trim() -eq $ClientName) {
        $global:TrivorConfirmedClients[$ClientName] = $true
        Write-Log ("Analista confirmou cliente {0} apesar da deteccao ({1})." -f $ClientName, $check) "WARN"
        return $true
    }
    Write-Host "Nome nao confere. Voltando ao menu de clientes." -ForegroundColor Red
    Write-Log ("Cliente {0} nao confirmado pelo analista ({1}). Nada foi executado." -f $ClientName, $check) "INFO"
    return $false
}

function Confirm-TrivorRunPlanConsole {
    # Resumo do que sera feito antes de executar.
    param([Parameter(Mandatory)] $Plan)

    $label = switch ($Plan.Mode) { 'PostFormat' { 'Pos-Formatacao' } 'Compliance' { 'Compliance' } 'Update' { 'Winget update dos apps do cliente' } 'Hostname' { 'Renomear hostname' } }
    $hostText = switch ($Plan.HostAction) {
        'Renomear'       { "{0} -> {1} (exige reiniciar)" -f $Plan.CurrentHostname, $Plan.ExpectedHostname }
        'JaCorreto'      { "{0} (ja esta correto)" -f $Plan.CurrentHostname }
        'SemPrefixo'     { "mantido (cliente sem prefixo)" }
        'SerialInvalido' { "mantido (serial invalido, ver log)" }
        default          { "mantido" }
    }
    Write-Host ""
    Write-Host "------------- Resumo antes de executar -------------" -ForegroundColor Cyan
    Write-Host ("Cliente : {0}" -f $Plan.ClientName)
    Write-Host ("Modo    : {0}" -f $label)
    if ($Plan.Mode -ne 'Hostname') { Write-Host ("Apps    : {0} ({1})" -f $Plan.AppCount, ($Plan.AppNames -join ', ')) }
    Write-Host ("Hostname: {0}" -f $hostText)
    if ($Plan.RemoveAppx) { Write-Host "Windows : remover apps desnecessarios (lista padrao)" }
    Write-Host "----------------------------------------------------" -ForegroundColor Cyan
    $ok = (Read-Host "Confirmar? (S/N)") -match '^(S|s|Y|y)$'
    if (-not $ok) { Write-Host "Cancelado. Nada foi executado." -ForegroundColor Yellow }
    return $ok
}

function Get-TrivorPostFormatGuardConsole {
    # Pos-Formatacao em maquina que ja parece configurada: sugere o Compliance.
    # Retorna PostFormat, Compliance ou Cancel.
    param([Parameter(Mandatory)] $Config)

    if (-not (Get-Command Get-TrivorPostFormatAssessment -ErrorAction SilentlyContinue)) { return 'PostFormat' }
    Write-Host "Verificando o que ja esta instalado..." -ForegroundColor DarkGray
    $states = @(foreach ($app in @($Config.Applications)) {
        try { $s = Get-ApplicationState -App $app; [pscustomobject]@{ Installed = [bool]$s.Installed; Error = $null } }
        catch { [pscustomobject]@{ Installed = $false; Error = $_.Exception.Message } }
    })
    $a = Get-TrivorPostFormatAssessment -States $states
    if (-not $a.LooksConfigured) { return 'PostFormat' }

    Write-Host ""
    Write-Host ("Esta maquina nao parece recem-formatada: {0} de {1} apps ja estao instalados." -f $a.Installed, $a.Total) -ForegroundColor Yellow
    Write-Host "A Pos-Formatacao reinstala tudo sem verificar. O Compliance instala so o que falta e atualiza o resto." -ForegroundColor Yellow
    $c = Read-Host "[C] Compliance (recomendado)  [P] Pos-Formatacao mesmo assim  [X] Cancelar"
    switch -Regex ($c) {
        '^(C|c)$' { Write-Log "Pos-Formatacao trocada por Compliance (maquina ja configurada)." "INFO"; return 'Compliance' }
        '^(P|p)$' { Write-Log ("Pos-Formatacao mantida pelo analista em maquina com {0}/{1} apps instalados." -f $a.Installed, $a.Total) "WARN"; return 'PostFormat' }
        default   { Write-Host "Cancelado. Nada foi executado." -ForegroundColor Yellow; return 'Cancel' }
    }
}

function Get-TrivorExpectedHostnameFor {
    param($Config)
    if ($Config.PSObject.Properties.Match('HostnamePrefix').Count -gt 0 -and $Config.HostnamePrefix) {
        return Get-ExpectedHostname -Prefix ([string]$Config.HostnamePrefix).ToUpper()
    }
    return $null
}

#endregion

function Show-ClientMenu {
    param([Parameter(Mandatory)] [string]$ClientName)

    if (-not (Confirm-TrivorClientChoiceConsole -ClientName $ClientName)) { Wait-Enter; return }

    while ($true) {
        Clear-Host
        Show-Banner

        Write-Host "Cliente: $ClientName" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1 - Pos-Formatacao  (hostname + instalar tudo por prioridade)"
        Write-Host "2 - Compliance      (verificar + instalar faltando + atualizar)"
        Write-Host "3 - Modo manual     (confirmar cada app)"
        Write-Host "4 - Winget update   (update rapido dos apps do cliente)"
        Write-Host "5 - Renomear hostname"
        Write-Host "6 - Winget upgrade --all (todos os apps da maquina)"
        Write-Host "7 - Voltar ao menu principal"
        Write-Host ""

        $choice = Read-Host "Selecione uma opcao"

        if ($choice -eq "7") { return }

        $cfg = Get-ClientConfigByName -ClientName $ClientName
        if (-not $cfg) { return }

        if ($choice -eq "1") {
            $mode = Get-TrivorPostFormatGuardConsole -Config $cfg
            if ($mode -eq 'Cancel') { Wait-Enter; continue }
            $plan = Get-TrivorRunPlan -Mode $mode -ClientName $ClientName -Config $cfg -ExpectedHostname (Get-TrivorExpectedHostnameFor $cfg)
            if (-not (Confirm-TrivorRunPlanConsole -Plan $plan)) { Wait-Enter; continue }
            Invoke-HostnameCheck -ClientConfig $cfg
            if ($mode -eq 'Compliance') { Invoke-ClientInstallation -ClientConfig $cfg }
            else { Invoke-PostFormatInstallation -ClientConfig $cfg }
            Write-Host ""
            Write-Host "Concluido." -ForegroundColor Green
            Wait-Enter
            continue
        }

        if ($choice -eq "2") {
            $plan = Get-TrivorRunPlan -Mode Compliance -ClientName $ClientName -Config $cfg -ExpectedHostname (Get-TrivorExpectedHostnameFor $cfg)
            if (-not (Confirm-TrivorRunPlanConsole -Plan $plan)) { Wait-Enter; continue }
            Invoke-HostnameCheck -ClientConfig $cfg
            Invoke-ClientInstallation -ClientConfig $cfg
            Write-Host ""
            Write-Host "Concluido." -ForegroundColor Green
            Wait-Enter
            continue
        }

        if ($choice -eq "3") {
            $apps = $cfg.Applications
            if (-not $apps -or $apps.Count -eq 0) {
                Write-Host "Nenhum app encontrado para este cliente." -ForegroundColor Yellow
                Wait-Enter
                continue
            }

            while ($true) {
                Clear-Host
                Show-Banner
                Write-Host "Cliente: $ClientName" -ForegroundColor Cyan
                Write-Host ""
                Show-AppGrid -Apps $apps

                $appChoice = Read-Host "Digite o numero do app (ou 0 para voltar)"

                if ($appChoice -eq "0") { break }

                $appNum = 0
                if (-not [int]::TryParse($appChoice, [ref]$appNum) -or $appNum -lt 1 -or $appNum -gt $apps.Count) {
                    Write-Host "Opcao invalida." -ForegroundColor Red
                    Start-Sleep -Seconds 1
                    continue
                }

                $selectedApp = $apps[$appNum - 1]
                Write-Host ""
                $manualResult = Invoke-AppActionManual -App $selectedApp
                Write-Host ""

                if ($manualResult -eq "QUIT") { break }

                Wait-Enter
            }
            continue
        }

        if ($choice -eq "4") {
            $plan = Get-TrivorRunPlan -Mode Update -ClientName $ClientName -Config $cfg
            if (-not (Confirm-TrivorRunPlanConsole -Plan $plan)) { Wait-Enter; continue }
            Invoke-ClientUpdateOnly -ClientConfig $cfg
            Write-Host ""
            Write-Host "Concluido." -ForegroundColor Green
            Wait-Enter
            continue
        }

        if ($choice -eq "5") {
            $plan = Get-TrivorRunPlan -Mode Hostname -ClientName $ClientName -Config $cfg -ExpectedHostname (Get-TrivorExpectedHostnameFor $cfg)
            if (-not (Confirm-TrivorRunPlanConsole -Plan $plan)) { Wait-Enter; continue }
            Invoke-HostnameCheck -ClientConfig $cfg
            Write-Host ""
            Wait-Enter
            continue
        }

        if ($choice -eq "6") {
            Invoke-WingetUpgradeAllWithDisplay
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
    $match = $null
    if (Get-Command Initialize-TrivorClientDetection -ErrorAction SilentlyContinue) {
        Write-Host "Identificando o cliente desta maquina..." -ForegroundColor DarkGray
        try { $match = Initialize-TrivorClientDetection -Names @(Get-ClientList) -ClientsPath (Get-ClientsPath) }
        catch { Write-Log "Deteccao de cliente indisponivel: $($_.Exception.Message)" "WARN" }
    }
    $firstPrompt = $true

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

        $prompt = "Digite o numero"
        if ($match -and $match.Status -eq 'Single') {
            Write-Host ("Cliente detectado nesta maquina: {0}  ({1})" -f $match.Client, ($match.Reasons -join '; ')) -ForegroundColor Green
            Write-Host ""
            $prompt = "Digite o numero (Enter = {0})" -f $match.Client
        }
        elseif ($match -and $match.Status -eq 'Conflict') {
            Write-Host ("ATENCAO: mais de um cliente corresponde a esta maquina: {0}. Confira antes de escolher." -f ($match.Clients -join ', ')) -ForegroundColor Yellow
            Write-Host ""
        }

        if ($firstPrompt) {
            # Tempo-limite so na primeira pergunta: o script e interativo e nao deve
            # ficar travado se for disparado sem ninguem no terminal.
            $firstPrompt = $false
            $answer = Read-TrivorFirstInput -Prompt $prompt
            if ($answer.Status -ne 'Ok') {
                $why = if ($answer.Status -eq 'Timeout') { "Nenhuma resposta em $([int]($global:TrivorFirstInputTimeoutSeconds / 60)) minutos" } else { "Entrada do console fechada (nenhum operador conectado)" }
                Write-Host ""
                Write-Host "$why. O Trivor Installer e interativo e nao deve ser usado como tarefa agendada. Encerrando sem executar nada." -ForegroundColor Red
                Write-Log "$why. Encerrando sem executar nada (exit 1)." "ERROR"
                $global:TrivorExitCode = 1
                return
            }
            $choice = $answer.Text
        }
        else {
            $choice = Read-Host $prompt
        }

        if ($choice -eq "0") {
            Invoke-Cleanup
            return
        }

        if ([string]::IsNullOrWhiteSpace($choice) -and $match -and $match.Status -eq 'Single') {
            Show-ClientMenu -ClientName $match.Client
            continue
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
