# ==============================
# Trivor Installer - Guard.ps1
# ==============================
# Protecoes contra erro do analista (uso sob demanda):
#  - sugere o cliente da maquina (prefixo do hostname, dominio AD, tenant Entra)
#  - alerta quando o cliente escolhido nao bate com a maquina
#  - avisa Pos-Formatacao em maquina que ja parece configurada
#  - resumo do que sera feito antes de executar
#  - tempo-limite na primeira pergunta do console (script e interativo)
# Regra: a deteccao so SUGERE quando aponta para UM unico cliente. Nunca adivinha.

$global:TrivorFirstInputTimeoutSeconds = 600

#region Identidade da maquina

function Get-TrivorHostnamePrefix {
    # "FMC-8H2K93L" -> "FMC". Sem hifen -> $null.
    param([string]$Hostname)
    if ([string]::IsNullOrWhiteSpace($Hostname)) { return $null }
    if ($Hostname -match '^([A-Za-z0-9]+)-') { return $Matches[1].ToUpper() }
    return $null
}

function Get-TrivorEntraTenantId {
    # TenantId do Entra ID a partir do dsregcmd (Windows 10/11). $null se nao ingressada.
    try {
        $out = & dsregcmd.exe /status 2>$null
        if (-not $out) { return $null }
        $joined = $out | Where-Object { $_ -match '^\s*AzureAdJoined\s*:\s*YES' }
        if (-not $joined) { return $null }
        $line = $out | Where-Object { $_ -match '^\s*TenantId\s*:\s*([0-9a-fA-F-]{36})' } | Select-Object -First 1
        if ($line -and $line -match '([0-9a-fA-F-]{36})') { return $Matches[1].ToLower() }
    } catch {
        Write-Log "dsregcmd indisponivel: $($_.Exception.Message)" "DEBUG"
    }
    return $null
}

function Get-TrivorMachineIdentity {
    $domain = $null
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain -and $cs.Domain) { $domain = ([string]$cs.Domain).ToLower() }
    } catch {
        Write-Log "Dominio da maquina nao identificado: $($_.Exception.Message)" "DEBUG"
    }
    return [pscustomobject]@{
        Hostname      = [string]$env:COMPUTERNAME
        Prefix        = Get-TrivorHostnamePrefix -Hostname $env:COMPUTERNAME
        Domain        = $domain
        EntraTenantId = Get-TrivorEntraTenantId
    }
}

#endregion

#region Indice de clientes

function Get-TrivorClientIndex {
    # Baixa em paralelo os JSONs que ainda nao estao na sessao e devolve os campos de
    # identificacao de cada cliente. Falhas de download nao interrompem: o cliente
    # fica fora do indice (a deteccao pode ficar incompleta, nunca errada).
    param(
        [Parameter(Mandatory)] [string[]]$Names,
        [Parameter(Mandatory)] [string]$ClientsPath,
        [string]$Owner = $global:TrivorOwner,
        [string]$Repo = $global:TrivorRepo,
        [string]$Branch = $global:TrivorBranch,
        [int]$TimeoutSeconds = 30
    )

    $valid = @($Names | Where-Object { $_ -match '^[A-Za-z0-9_\-]{1,80}$' })
    New-Item -ItemType Directory -Force -Path $ClientsPath | Out-Null
    $missing = @($valid | Where-Object { -not (Test-Path -LiteralPath (Join-Path $ClientsPath "$_.json")) })

    if ($missing.Count -gt 0) {
        try {
            Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
            $http = New-Object System.Net.Http.HttpClient
            $http.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
            $tasks = @{}
            foreach ($n in $missing) {
                $tasks[$n] = $http.GetByteArrayAsync("https://raw.githubusercontent.com/$Owner/$Repo/$Branch/Clientes/$n.json")
            }
            try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($tasks.Values), [TimeSpan]::FromSeconds($TimeoutSeconds)) } catch { Write-Log "Download parcial dos clientes: $($_.Exception.InnerException.Message)" "WARN" }
            foreach ($n in $tasks.Keys) {
                $t = $tasks[$n]
                if ($t.Status -eq 'RanToCompletion') { [System.IO.File]::WriteAllBytes((Join-Path $ClientsPath "$n.json"), $t.Result) }
                else { Write-Log "Cliente $n nao baixado para o indice ($($t.Status))." "WARN" }
            }
            $http.Dispose()
        } catch {
            Write-Log "Falha ao montar indice de clientes: $($_.Exception.Message)" "WARN"
        }
    }

    $index = New-Object System.Collections.ArrayList
    foreach ($n in $valid) {
        $file = Join-Path $ClientsPath "$n.json"
        if (-not (Test-Path -LiteralPath $file)) { continue }
        try {
            $cfg = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            $get = { param($p) if ($cfg.PSObject.Properties.Match($p).Count -gt 0 -and $cfg.$p) { [string]$cfg.$p } else { $null } }
            $prefix = & $get 'HostnamePrefix'
            if ($prefix) { $prefix = ($prefix -replace '[^A-Za-z0-9-]', '').Trim('-').ToUpper() }
            $dom = & $get 'Domain'
            $ten = & $get 'EntraTenantId'
            [void]$index.Add([pscustomobject]@{
                Name          = $n
                HostnamePrefix = $prefix
                Domain        = $(if ($dom) { $dom.ToLower() } else { $null })
                EntraTenantId = $(if ($ten) { $ten.ToLower() } else { $null })
            })
        } catch {
            Write-Log "JSON do cliente $n ignorado no indice: $($_.Exception.Message)" "WARN"
        }
    }
    return $index.ToArray()
}

#endregion

#region Deteccao e conferencia

function Find-TrivorClientMatch {
    # Status: Single (1 cliente), Conflict (mais de 1), None.
    param($Identity, $Index)

    $hits = @{}
    $add = { param($name, $reason) if (-not $hits.ContainsKey($name)) { $hits[$name] = New-Object System.Collections.ArrayList }; [void]$hits[$name].Add($reason) }

    foreach ($c in @($Index)) {
        if ($Identity.Prefix -and $c.HostnamePrefix -and $c.HostnamePrefix -eq $Identity.Prefix) { & $add $c.Name "prefixo do hostname ($($Identity.Hostname))" }
        if ($Identity.Domain -and $c.Domain -and $c.Domain -eq $Identity.Domain) { & $add $c.Name "dominio $($Identity.Domain)" }
        if ($Identity.EntraTenantId -and $c.EntraTenantId -and $c.EntraTenantId -eq $Identity.EntraTenantId) { & $add $c.Name 'tenant do Entra ID' }
    }

    $names = @($hits.Keys | Sort-Object)
    if ($names.Count -eq 0) { return [pscustomobject]@{ Status = 'None'; Client = $null; Clients = @(); Reasons = @() } }
    if ($names.Count -eq 1) { return [pscustomobject]@{ Status = 'Single'; Client = $names[0]; Clients = $names; Reasons = @($hits[$names[0]]) } }
    return [pscustomobject]@{ Status = 'Conflict'; Client = $null; Clients = $names; Reasons = @() }
}

function Test-TrivorClientChoice {
    # Confere o cliente escolhido contra a deteccao.
    # Ok = sem deteccao ou bate; Mismatch = maquina parece de outro cliente;
    # Conflict = mais de um cliente bate com a maquina (escolhido incluso ou nao).
    param([Parameter(Mandatory)] [string]$Selected, $Match)
    if (-not $Match -or $Match.Status -eq 'None') { return 'Ok' }
    if ($Match.Status -eq 'Single') { if ($Match.Client -eq $Selected) { return 'Ok' } else { return 'Mismatch' } }
    return 'Conflict'
}

function Get-TrivorPostFormatAssessment {
    # Maquina "ja configurada": metade ou mais dos apps do cliente instalados (minimo 2).
    param($States)
    $known = @($States | Where-Object { $_ -and -not $_.Error })
    $installed = @($known | Where-Object { $_.Installed }).Count
    $total = @($States).Count
    $looksConfigured = ($installed -ge 2) -and ($total -gt 0) -and (($installed / $total) -ge 0.5)
    return [pscustomobject]@{ Installed = $installed; Total = $total; LooksConfigured = $looksConfigured }
}

function Get-TrivorRunPlan {
    # O que sera feito, para o resumo antes de executar (console e janela).
    param(
        [Parameter(Mandatory)] [ValidateSet('PostFormat', 'Compliance', 'Update', 'Hostname')] [string]$Mode,
        [Parameter(Mandatory)] [string]$ClientName,
        [Parameter(Mandatory)] $Config,
        [string]$CurrentHostname = $env:COMPUTERNAME,
        [string]$ExpectedHostname
    )
    $apps = @($Config.Applications)
    $winget = @($apps | Where-Object { $_.PSObject.Properties.Match('WingetId').Count -gt 0 -and $_.WingetId })
    $hasPrefix = $Config.PSObject.Properties.Match('HostnamePrefix').Count -gt 0 -and $Config.HostnamePrefix

    $hostAction = 'Nenhuma'
    if ($Mode -in @('PostFormat', 'Compliance', 'Hostname')) {
        if (-not $hasPrefix) { $hostAction = 'SemPrefixo' }
        elseif (-not $ExpectedHostname) { $hostAction = 'SerialInvalido' }
        elseif ($CurrentHostname -eq $ExpectedHostname) { $hostAction = 'JaCorreto' }
        else { $hostAction = 'Renomear' }
    }

    $count = switch ($Mode) { 'Update' { $winget.Count } 'Hostname' { 0 } default { $apps.Count } }
    return [pscustomobject]@{
        Mode             = $Mode
        ClientName       = $ClientName
        AppCount         = $count
        AppNames         = @($(if ($Mode -eq 'Update') { $winget } elseif ($Mode -eq 'Hostname') { @() } else { $apps }) | ForEach-Object { [string]$_.Name })
        HostAction       = $hostAction
        RemoveAppx       = ($Mode -in @('PostFormat', 'Compliance'))
        CurrentHostname  = $CurrentHostname
        ExpectedHostname = $ExpectedHostname
    }
}

#endregion

#region Inicializacao

function Initialize-TrivorClientDetection {
    # Identidade + indice + deteccao. Guarda em globais para o console e a janela.
    param([Parameter(Mandatory)] [string[]]$Names, [Parameter(Mandatory)] [string]$ClientsPath)

    $global:TrivorMachineIdentity = Get-TrivorMachineIdentity
    $global:TrivorClientIndex = @(Get-TrivorClientIndex -Names $Names -ClientsPath $ClientsPath)
    $global:TrivorClientMatch = Find-TrivorClientMatch -Identity $global:TrivorMachineIdentity -Index $global:TrivorClientIndex

    $id = $global:TrivorMachineIdentity
    $m = $global:TrivorClientMatch
    $what = switch ($m.Status) { 'Single' { "$($m.Client) ($($m.Reasons -join '; '))" } 'Conflict' { "conflito entre $($m.Clients -join ', ')" } default { 'nenhum cliente' } }
    Write-Log ("Deteccao de cliente: {0} | hostname={1} prefixo={2} dominio={3} tenantEntra={4} | indice={5}/{6} clientes" -f `
        $what, $id.Hostname, $(if ($id.Prefix) { $id.Prefix } else { '-' }), $(if ($id.Domain) { $id.Domain } else { '-' }),
        $(if ($id.EntraTenantId) { 'sim' } else { 'nao' }), $global:TrivorClientIndex.Count, @($Names).Count) "INFO"
    return $m
}

#endregion

#region Tempo-limite da primeira pergunta (console)

function Read-TrivorFirstInput {
    # Le uma linha com tempo-limite. Status: Ok (Text), Timeout, EOF (entrada fechada:
    # ninguem do outro lado, ex. script disparado sem terminal interativo).
    param([string]$Prompt, [int]$TimeoutSeconds = $global:TrivorFirstInputTimeoutSeconds)

    Write-Host -NoNewline "${Prompt}: "
    # A leitura roda numa thread de SEGUNDO PLANO: o ReadLineAsync do console do .NET
    # bloqueia ate chegar uma linha, e uma thread comum impediria o processo de encerrar
    # se a entrada nunca fechar.
    try {
        if (-not ('TrivorConsoleReader' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
public static class TrivorConsoleReader {
    public static string ReadLine(int timeoutMs, out bool timedOut) {
        string line = null;
        System.Threading.Thread t = new System.Threading.Thread(delegate () { line = System.Console.In.ReadLine(); });
        t.IsBackground = true;
        t.Start();
        timedOut = !t.Join(timeoutMs);
        return line;
    }
}
'@
        }
        $timedOut = $false
        $line = [TrivorConsoleReader]::ReadLine($TimeoutSeconds * 1000, [ref]$timedOut)
    } catch {
        # Sem compilador ou sem console de texto: comportamento anterior, sem tempo-limite
        Write-Log "Tempo-limite indisponivel: $($_.Exception.Message)" "WARN"
        return [pscustomobject]@{ Status = 'Ok'; Text = (Read-Host) }
    }
    if ($timedOut) { Write-Host ""; return [pscustomobject]@{ Status = 'Timeout'; Text = $null } }
    if ($null -eq $line) { Write-Host ""; return [pscustomobject]@{ Status = 'EOF'; Text = $null } }
    return [pscustomobject]@{ Status = 'Ok'; Text = $line }
}

#endregion
