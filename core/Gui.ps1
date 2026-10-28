# ==============================
# Trivor Installer - Gui.ps1
# ==============================
# Interface grafica (WPF). Usa somente as funcoes de acao do motor
# (Get-ApplicationState, Install-Application, Invoke-AppAction, Update-WingetApp,
# Invoke-HostnameCheck); os menus de console (Menu.ps1) continuam intactos e sao o
# fallback em contexto SYSTEM/RMM ou quando o WPF nao esta disponivel.
# As acoes rodam em um runspace separado para a janela nao congelar.

#region Recursos embutidos (logo e icone da Trivor, trivor.com.br)
$script:TrivorGuiLogoB64 = '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'
$script:TrivorGuiIconB64 = 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAFAUlEQVRYw+2Xa4hVVRiGn3fPcbwkdjGTiqIEiykI7ApdzD10xzIzia4m7n3K1Cy6/CjqV1BERNlN994zRfbDSioLuhC5LQjKoiIiIwqNgjAryxodZzzn7cfZp9keb0cJIuiDxeHsdfne9a1vvd+7xF5YGCUVoCPPqlvDKLkSWCqpw3Y/8BrwCLA6z6rb2l2z0pbjOYkQR4Bmgz8DVpT7JY0AZto+HcjCKH3G5rtVPbH3tHbQxq4PRMwCXpa4V9L4pl+kfqDfdhPI4ZLuAVZInhVGyYEnnbRE+xSBMEpGAJOBW0DdEsNbhnwITDd0ANNszxCMQwokTrBZDFwxZpIeCScl7+ZZtX9nfnZAN2XOkkDScUjzsa+QdEDLkBtWpnGyHdg46cScgbQA+3xJo5p9tn8DvQB+3PDlqqxa2ymAs65PVKkwDrgOmCtpwi6CswOAEpDRmIuBhUgnqxGdJpB1wBLg6Tyrrt8uB7rjlEqFY4BngPubzm1j+yfbA+0ka55W/wSWIU3Hvsf22lKiHgXcB/SGUdIVRskQgDEjg7FBoIeACyVV3HD+C/AEMBv4qd1rlWdV52n8I/AgcKntXsPGAkSH4CLgYWAsQEUSgzWfgzlPEkAd+/0C7SpJhwL1ko+J3XE6uRTa9cDXeVZ1C5Aa8HkYpzdhnje+S9JkJGF30wCyNLj69t5gW43Q0Fks+CkwC/N2nlV3FvqbgTdK7W6XznrHY4m31szbQGT7iyISnaCzwigNAkkjgYmlOZ8A6/Ke6q5IpBMY1WySKoF2e9V5rye2Xf8WeGvoq48GjwjUiPuwUrLUWsNZNtsDtvtKbaBJRLuzVT03Gvi25Ge4pKDC3tujLVS8wabWzkRJ9X2qBS2LfLMyjd/nH7KAf9n+B/DfA2CjfxLAPlxDTwmj5HXMD02yCqNUiMMwHRLfr0z3rITaBlDovU1FnUDSTNvHIhaFUfIKSMB0YB4wHHgqjNJl4F9bCc12h1pYM7BtMUQktitnz1lcHvUz8ITtDcX/DkmTgMXAK+CXgCcFJ0oc36h0XtSsdiWFFQBdJT9bbNcCm36JNaWxpwUKusIoUamq9YBm2l5u01ei0rMlTflbrpnNtl8vhMfvzQW740ygLqRzS5S2DtgqgKnzssu3DPo5m+FuEPvHwIOINwuRUewiHQ2eWlTEUyV1FLupAasb+kGv5ln8R2nno4ELQHeAT5Ek21uA6/Os+oIAZizs3X9Tfy2p1ZnZlGm2+wqtvwj0UZ7F24oFBYwHrgWuQQL7eaAXWN889+44G2bXTwEWAJeUdKJtvwjEeVbd9PdZXzy/58iBbX5gsObLimSiqHLrgadBGXhtnlXrpTM9uJGD/jlPm9/TADwBFEnMNj5Exc216Qe/CtyZZ9XvdlDFU+f17L95oH4lsMB2l4ZS1rbXNKLBcrn268qeudtl+JRoiYTGAjNAN8PQfNt10BrgMfCyPKv+vktZ3h2nspkAngtcVUiyAgYDxu+BFiHeydN4c7HrkeAQuE1wJlJni2R7FliMgrV5Gnm374KWd+CpwELgIkmjS2z4B3gF0ksCDNOxp0kaU3LcB7xZvBc/2NV7cY+0GkbJfo0s5lbgNEll8hosfoeVHA+CVoMfB72WZ3HfbvVFe6/iVOBxwNXAjcBEtVCajcFfAymwFLQhz/ZMyXtVWMI4CTBdxbHMAA4qujYCy4twf9W8Ke3YXz9ISSeL8A4xAAAAAElFTkSuQmCC'
#endregion

#region Funcoes puras (testaveis sem WPF)

function Test-TrivorGuiAvailable {
    # Decide se a interface grafica pode abrir. Retorna Available + Reason.
    $no = { param($r) [pscustomobject]@{ Available = $false; Reason = $r } }

    if ($env:TRIVOR_UI -eq 'console') { return (& $no 'TRIVOR_UI=console') }
    if ((Test-Path variable:IsWindows) -and -not $IsWindows) { return (& $no 'Sistema operacional nao e Windows') }
    if (Get-Command Test-TrivorSystemContext -ErrorAction SilentlyContinue) {
        if (Test-TrivorSystemContext) { return (& $no 'Contexto SYSTEM/RMM (sem desktop interativo)') }
    }
    if (-not [Environment]::UserInteractive) { return (& $no 'Sessao nao interativa') }
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        return (& $no 'Thread nao e STA (use Windows PowerShell 5.1 ou pwsh -sta)')
    }
    try {
        Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop
    }
    catch { return (& $no "WPF indisponivel: $($_.Exception.Message)") }

    return [pscustomobject]@{ Available = $true; Reason = '' }
}

function ConvertFrom-TrivorWingetTable {
    # Converte a tabela de 'winget upgrade' em objetos. As colunas sao localizadas
    # (Name/Nome, Id/ID...), entao a leitura usa a POSICAO dos titulos, a partir da
    # linha de tracos que o winget imprime abaixo do cabecalho.
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    $lines = @($Text -split "`n" | ForEach-Object {
        $l = $_.TrimEnd("`r")
        $cr = $l.LastIndexOf("`r")
        if ($cr -ge 0) { $l = $l.Substring($cr + 1) }   # descarta o spinner de progresso
        $l
    })

    $headerIdx = -1
    for ($i = 0; $i -lt $lines.Count - 1; $i++) {
        if ($lines[$i + 1] -match '^\s*-{10,}\s*$' -and $lines[$i].Trim().Length -gt 0) { $headerIdx = $i; break }
    }
    if ($headerIdx -lt 0) { return @() }

    $header = $lines[$headerIdx]
    $starts = @([regex]::Matches($header, '\S+') | ForEach-Object { $_.Index })
    if ($starts.Count -lt 4) { return @() }

    $cut = {
        param($line, $col)
        $s = $starts[$col]
        if ($s -ge $line.Length) { return '' }
        $e = if ($col + 1 -lt $starts.Count) { [Math]::Min($starts[$col + 1], $line.Length) } else { $line.Length }
        return $line.Substring($s, $e - $s).Trim()
    }

    $items = New-Object System.Collections.ArrayList
    for ($i = $headerIdx + 2; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { break }
        # Fim da tabela: linha de resumo ("6 upgrades available." / "2 atualizações disponíveis.")
        # nao tem separacao antes da coluna Id nem versoes preenchidas
        if ($line.Length -le $starts[1] -or $line[$starts[1] - 1] -ne ' ') { break }
        $id = & $cut $line 1
        if ([string]::IsNullOrWhiteSpace($id) -or $id -match '\s') { break }
        if ([string]::IsNullOrWhiteSpace((& $cut $line 2)) -or [string]::IsNullOrWhiteSpace((& $cut $line 3))) { break }
        [void]$items.Add([pscustomobject]@{
            Name       = $line.Substring(0, [Math]::Min($starts[1], $line.Length)).Trim()
            Id         = $id
            Version    = & $cut $line 2
            Available  = & $cut $line 3
            Selectable = -not ($id.EndsWith([string][char]0x2026) -or $id.EndsWith('...'))
        })
    }
    return $items.ToArray()
}

function Select-TrivorLogLines {
    # Filtra linhas de log por nivel ([INFO], [WARN], [ERROR]) e texto.
    param(
        [string[]]$Lines,
        [ValidateSet('Todos', 'INFO', 'WARN', 'ERROR')] [string]$Level = 'Todos',
        [string]$Search
    )
    $out = @($Lines)
    if ($Level -ne 'Todos') { $out = @($out | Where-Object { $_ -match ('\[' + $Level + '\]') }) }
    if (-not [string]::IsNullOrWhiteSpace($Search)) {
        $out = @($out | Where-Object { $_.IndexOf($Search, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
    }
    return $out
}

function Get-TrivorGuiAppSource {
    # Texto da coluna "Origem" a partir do JSON do cliente.
    param([Parameter(Mandatory)] $App)
    if ($App.PSObject.Properties.Match('WingetId').Count -gt 0 -and $App.WingetId) { return 'Winget' }
    $i = $App.Install
    if (-not $i) { return 'Somente detecção' }
    switch ($i.Method) {
        'RepoExePublic' { if ($i.Sha256) { return 'Repositório (SHA256)' } else { return 'Repositório (assinatura)' } }
        'UrlExe' {
            if ($i.Sha256) { return 'URL (SHA256)' }
            if ($i.Signer) { return "URL (assinatura $($i.Signer))" }
            return 'URL (assinatura)'
        }
        'RegFile' { return 'Registro (.reg)' }
    }
    return [string]$i.Method
}

function Get-TrivorGuiStatusStyle {
    # Cores dos selos de status (texto escuro sobre fundo claro, contraste >= 4.5:1).
    param([string]$Kind)
    switch ($Kind) {
        'ok'   { return @{ Bg = '#E6F4EA'; Fg = '#0B5E30' } }
        'miss' { return @{ Bg = '#FDECEA'; Fg = '#9C1F17' } }
        'warn' { return @{ Bg = '#FFF4DE'; Fg = '#7A4A00' } }
        default { return @{ Bg = '#EEEEEE'; Fg = '#4A4A4A' } }
    }
}

function New-TrivorGuiAppRow {
    # Linha da tabela de apps. $State = resultado da deteccao (ou $null = verificando).
    param([Parameter(Mandatory)] $App, $State)

    if ($null -eq $State) { $kind = 'neutral'; $status = 'Verificando…'; $version = '' }
    elseif ($State.Error) { $kind = 'warn'; $status = 'Erro na detecção'; $version = '' }
    elseif (-not $State.Installed) { $kind = 'miss'; $status = 'Faltando'; $version = '—' }
    elseif ($State.Old) { $kind = 'warn'; $status = 'Versão antiga'; $version = $State.Version }
    else { $kind = 'ok'; $status = 'Instalado'; $version = $State.Version }
    if ([string]::IsNullOrWhiteSpace($version)) { $version = '—' }

    $style = Get-TrivorGuiStatusStyle -Kind $kind
    return [pscustomobject]@{
        Selected = [bool]($State -and -not $State.Error -and (-not $State.Installed -or $State.Old))
        Name     = [string]$App.Name
        Source   = Get-TrivorGuiAppSource -App $App
        Status   = $status
        StatusBg = $style.Bg
        StatusFg = $style.Fg
        Version  = [string]$version
        App      = $App
    }
}

function New-TrivorGuiSteps {
    # Monta as etapas de uma execucao, na mesma ordem que o motor usa no console.
    param(
        [Parameter(Mandatory)] [ValidateSet('PostFormat', 'Compliance', 'Selected', 'Update', 'Hostname', 'Upgrade')] [string]$Mode,
        $Config,
        $SelectedApps,
        $WingetItems
    )

    $steps = New-Object System.Collections.ArrayList
    $hasPrefix = $Config -and $Config.PSObject.Properties.Match('HostnamePrefix').Count -gt 0 -and $Config.HostnamePrefix
    $byPriority = {
        param($apps)
        @($apps) | Sort-Object { $p = $_.PSObject.Properties['Priority']; if ($p -and $null -ne $p.Value) { [int]$p.Value } else { 100 } }
    }

    if ($Mode -in @('PostFormat', 'Compliance', 'Hostname') -and $hasPrefix) {
        [void]$steps.Add([pscustomobject]@{ Type = 'hostname'; Name = 'Verificar/renomear hostname'; App = $null; Id = $null })
    }
    switch ($Mode) {
        { $_ -in @('PostFormat', 'Compliance') } {
            foreach ($a in (& $byPriority $Config.Applications)) { [void]$steps.Add([pscustomobject]@{ Type = 'app'; Name = [string]$a.Name; App = $a; Id = $null }) }
        }
        'Selected' {
            foreach ($a in (& $byPriority $SelectedApps)) { [void]$steps.Add([pscustomobject]@{ Type = 'app'; Name = [string]$a.Name; App = $a; Id = $null }) }
        }
        'Update' {
            foreach ($a in @($Config.Applications | Where-Object { $_.PSObject.Properties.Match('WingetId').Count -gt 0 -and $_.WingetId })) {
                [void]$steps.Add([pscustomobject]@{ Type = 'app'; Name = [string]$a.Name; App = $a; Id = $null })
            }
        }
        'Upgrade' {
            foreach ($w in @($WingetItems)) { [void]$steps.Add([pscustomobject]@{ Type = 'winget'; Name = [string]$w.Name; App = $null; Id = [string]$w.Id }) }
        }
    }
    return $steps.ToArray()
}

function Get-TrivorGuiModeLabel {
    param([string]$Mode)
    switch ($Mode) {
        'PostFormat' { 'Pós-Formatação' }
        'Compliance' { 'Compliance' }
        'Selected'   { 'Instalação dos selecionados' }
        'Update'     { 'Atualização dos apps' }
        'Hostname'   { 'Renomear hostname' }
        'Upgrade'    { 'Upgrade geral' }
        default      { $Mode }
    }
}

function Get-TrivorGuiStepVisual {
    # Aparencia de cada etapa na tela de execucao.
    param([string]$State)
    switch ($State) {
        'run'  { @{ Dot = '#FFFFFF'; Ring = '#3568B1'; Text = 'Executando…';   Color = '#3568B1'; Weight = 'SemiBold' } }
        'done' { @{ Dot = '#0E7A3E'; Ring = '#0E7A3E'; Text = 'Concluído';     Color = '#0B5E30'; Weight = 'Normal' } }
        'fail' { @{ Dot = '#9C1F17'; Ring = '#9C1F17'; Text = 'Falhou';        Color = '#9C1F17'; Weight = 'Normal' } }
        'skip' { @{ Dot = '#EEEEEE'; Ring = '#B5B5B5'; Text = 'Não executado'; Color = '#5C5C5C'; Weight = 'Normal' } }
        default { @{ Dot = '#FFFFFF'; Ring = '#B5B5B5'; Text = 'Aguardando';   Color = '#5C5C5C'; Weight = 'Normal' } }
    }
}

function Get-TrivorGuiClientConfig {
    # Equivalente ao Get-ClientConfigByName do console, sem Read-Host (que travaria a janela).
    param([Parameter(Mandatory)] [string]$ClientName)

    if ($ClientName -notmatch '^[A-Za-z0-9_\-]{1,80}$') { throw "Nome de cliente invalido: $ClientName" }

    $clientsPath = Get-ClientsPath
    $file = Join-Path $clientsPath "$ClientName.json"
    if (-not (Test-Path -LiteralPath $file)) {
        $url = "https://raw.githubusercontent.com/$($global:TrivorOwner)/$($global:TrivorRepo)/$($global:TrivorBranch)/Clientes/$ClientName.json"
        New-Item -ItemType Directory -Force -Path $clientsPath | Out-Null
        Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing -ErrorAction Stop
        Write-Log "Downloaded client config: $ClientName" "INFO"
    }
    $cfg = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if (-not (Test-ClientConfig -Config $cfg -ClientName $ClientName)) { throw "JSON do cliente '$ClientName' com estrutura invalida (detalhes no log)." }
    return $cfg
}

#endregion

#region Worker (executa no runspace separado)

$script:TrivorGuiWorker = @'
param($Sync, $Ctx, $Kind, $Payload)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Set-TrivorWorkerGlobals {
    foreach ($k in $Ctx.Globals.Keys) { Set-Variable -Name $k -Value $Ctx.Globals[$k] -Scope Global }
}

try {
    # Globais antes (Engine calcula caminhos ao carregar) e depois (Logger zera o arquivo de log ao carregar)
    Set-TrivorWorkerGlobals
    foreach ($m in $Ctx.Modules) { . (Join-Path $Ctx.CorePath $m) }
    Set-TrivorWorkerGlobals

    switch ($Kind) {
        'detect' {
            $out = New-Object System.Collections.ArrayList
            foreach ($app in @($Payload.Apps)) {
                try {
                    $st = Get-ApplicationState -App $app
                    $old = $false
                    if ($st.Installed) { $old = [bool](Should-ForceReinstallByVersion -App $app -State $st) }
                    [void]$out.Add([pscustomobject]@{ Installed = [bool]$st.Installed; Source = [string]$st.Source; Version = [string]$st.Version; Old = $old; Error = $null })
                }
                catch {
                    Write-Log "Erro ao detectar $($app.Name): $($_.Exception.Message)" "WARN"
                    [void]$out.Add([pscustomobject]@{ Installed = $false; Source = ''; Version = ''; Old = $false; Error = $_.Exception.Message })
                }
            }
            $Sync.Detect = $out.ToArray()
        }

        'run' {
            [void](Initialize-Winget)
            Write-Log ("Interface grafica: iniciando {0} | Cliente={1} | Etapas={2}" -f $Payload.Mode, $Payload.ClientName, @($Payload.Steps).Count) "INFO"
            $steps = @($Payload.Steps)
            for ($i = 0; $i -lt $steps.Count; $i++) {
                if ($Sync.CancelRequested) {
                    Write-Log "Execucao cancelada pelo tecnico. Etapas restantes nao executadas." "WARN"
                    for ($j = $i; $j -lt $steps.Count; $j++) {
                        $Sync.StepStates[$j] = 'skip'
                        [void]$Sync.Results.Add([pscustomobject]@{ Name = $steps[$j].Name; State = 'skip'; Detail = 'Não executado (cancelado)' })
                    }
                    $Sync.Cancelled = $true
                    break
                }

                $step = $steps[$i]
                $Sync.StepStates[$i] = 'run'
                $Sync.Current = $step.Name
                $counts = ($step.Type -ne 'hostname')
                if ($counts) { $Sync.Total = $Sync.Total + 1 }
                $ok = $false
                $detail = ''

                try {
                    switch ($step.Type) {
                        'hostname' {
                            $cfg = $Payload.Config
                            $expected = Get-ExpectedHostname -Prefix ([string]$cfg.HostnamePrefix).ToUpper()
                            if (-not $expected) { $detail = 'Serial inválido ou prefixo longo demais (ver log)' }
                            elseif ($env:COMPUTERNAME -eq $expected) { $ok = $true; $detail = "Já estava correto ($expected)" }
                            else {
                                $null = Invoke-HostnameCheck -ClientConfig $cfg
                                $pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue).ComputerName
                                if ($pending -eq $expected) {
                                    $ok = $true; $Sync.RebootRequired = $true
                                    $detail = "$($env:COMPUTERNAME) → $expected (reinício pendente)"
                                }
                                else { $detail = 'Falha ao renomear (ver log)' }
                            }
                        }
                        'app' {
                            Write-Log ("Interface grafica [{0}/{1}]: {2}" -f ($i + 1), $steps.Count, $step.Name) "INFO"
                            $r = @(switch ($Payload.Mode) {
                                'PostFormat' { Install-Application -App $step.App }
                                'Update'     { Update-WingetApp -WingetId $step.App.WingetId }
                                default      { Invoke-AppAction -App $step.App }
                            })
                            $ok = ($r.Count -gt 0) -and [bool]$r[-1]
                        }
                        'winget' {
                            Write-Log ("Interface grafica [{0}/{1}]: upgrade {2}" -f ($i + 1), $steps.Count, $step.Id) "INFO"
                            $r = @(Update-WingetApp -WingetId $step.Id)
                            $ok = ($r.Count -gt 0) -and [bool]$r[-1]
                        }
                    }
                }
                catch {
                    $ok = $false
                    $detail = "Erro: $($_.Exception.Message)"
                    Write-Log "Erro na etapa '$($step.Name)': $($_.Exception.Message)" "ERROR"
                }

                if ($counts -and -not $ok) { $Sync.Failed = $Sync.Failed + 1 }
                if (-not $detail) { $detail = if ($ok) { 'Concluído' } else { 'Falhou (detalhes no log)' } }
                $Sync.StepStates[$i] = if ($ok) { 'done' } else { 'fail' }
                [void]$Sync.Results.Add([pscustomobject]@{ Name = $step.Name; State = $Sync.StepStates[$i]; Detail = $detail })
                $Sync.Done = $i + 1
            }
            Write-Log ("Interface grafica: {0} finalizado | {1} total / {2} falhas" -f $Payload.Mode, $Sync.Total, $Sync.Failed) "INFO"
        }

        'index' {
            $Sync.Match = Initialize-TrivorClientDetection -Names $Payload.Names -ClientsPath $Payload.ClientsPath
        }

        'upgradelist' {
            [void](Initialize-Winget)
            $wingetArgs = 'upgrade --accept-source-agreements --disable-interactivity'
            if ($Payload.IncludeUnknown) { $wingetArgs += ' --include-unknown' }
            $r = Invoke-WingetAsUser -Arguments $wingetArgs -OperationName 'upgrade_list_gui'
            $text = ''
            if ($r.StdOut -and (Test-Path $r.StdOut)) { $text = Get-Content $r.StdOut -Raw -Encoding UTF8 }
            $Sync.UpgradeText = [string]$text
        }
    }
}
catch {
    $Sync.Error = $_.Exception.Message
    try { Write-Log "Erro no processamento em segundo plano ($Kind): $($_.Exception.Message)" "ERROR" } catch { Write-Verbose "Log indisponivel" }
}
finally {
    $Sync.RebootRequired = [bool]($Sync.RebootRequired -or $global:TrivorRebootRequired)
    $Sync.Finished = $true
}
'@

#endregion

#region XAML

$script:TrivorGuiXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Trivor Installer" Width="1280" Height="800" MinWidth="1100" MinHeight="680"
        WindowStartupLocation="CenterScreen" Background="#F3F3F3"
        FontFamily="Segoe UI" FontSize="14" Foreground="#1B1B1B" UseLayoutRounding="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Accent" Color="#3568B1"/>
    <SolidColorBrush x:Key="AccentDark" Color="#28508A"/>

    <Style TargetType="Button">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="Foreground" Value="#1B1B1B"/>
      <Setter Property="BorderBrush" Value="#C4C4C4"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="16,0"/>
      <Setter Property="MinHeight" Value="36"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.88"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#3568B1"/><Setter TargetName="Bd" Property="BorderThickness" Value="2"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Bd" Property="Opacity" Value="0.45"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Setter Property="HorizontalContentAlignment" Value="Center"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>

    <Style x:Key="AccentButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#3568B1"/>
      <Setter Property="BorderBrush" Value="#3568B1"/>
      <Setter Property="Foreground" Value="#FFFFFF"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>

    <Style x:Key="ActionCard" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Padding" Value="16,14"/>
      <Setter Property="MinHeight" Value="92"/>
      <Setter Property="Margin" Value="0,0,12,0"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="VerticalContentAlignment" Value="Top"/>
      <Setter Property="BorderBrush" Value="#D1D1D1"/>
    </Style>

    <Style x:Key="AccentActionCard" TargetType="Button" BasedOn="{StaticResource ActionCard}">
      <Setter Property="Background" Value="#3568B1"/>
      <Setter Property="BorderBrush" Value="#3568B1"/>
      <Setter Property="Foreground" Value="#FFFFFF"/>
    </Style>

    <Style x:Key="NavItem" TargetType="RadioButton">
      <Setter Property="GroupName" Value="Nav"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,0,4"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="6" Height="44" Padding="12,0">
              <Grid>
                <Rectangle x:Name="Ind" Width="3" Height="18" RadiusX="1.5" RadiusY="1.5" Fill="#3568B1" HorizontalAlignment="Left" Visibility="Collapsed"/>
                <ContentPresenter Margin="14,0,0,0" VerticalAlignment="Center"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#EAEAEA"/></Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FFFFFF"/>
                <Setter TargetName="Ind" Property="Visibility" Value="Visible"/>
                <Setter Property="FontWeight" Value="SemiBold"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Foreground" Value="#8A8A8A"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Chip" TargetType="RadioButton">
      <Setter Property="GroupName" Value="Lvl"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,6,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" Background="#FFFFFF" BorderBrush="#C4C4C4" BorderThickness="1" CornerRadius="16" Padding="14,5">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#3568B1"/>
                <Setter TargetName="Bd" Property="BorderBrush" Value="#3568B1"/>
                <Setter Property="Foreground" Value="#FFFFFF"/>
                <Setter Property="FontWeight" Value="SemiBold"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="BorderBrush" Value="#E0E0E0"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="6"/>
    </Style>
    <Style x:Key="H1" TargetType="TextBlock">
      <Setter Property="FontSize" Value="28"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Foreground" Value="#333333"/>
    </Style>
    <Style x:Key="H2" TargetType="TextBlock">
      <Setter Property="FontSize" Value="16"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="Muted" TargetType="TextBlock">
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Foreground" Value="#5C5C5C"/>
    </Style>
    <Style x:Key="Mono" TargetType="TextBox">
      <Setter Property="FontFamily" Value="Consolas"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="12"/>
      <Setter Property="TextWrapping" Value="NoWrap"/>
      <Setter Property="VerticalScrollBarVisibility" Value="Auto"/>
      <Setter Property="HorizontalScrollBarVisibility" Value="Auto"/>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#EEEEEE"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="RowHeight" Value="44"/>
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserDeleteRows" Value="False"/>
      <Setter Property="CanUserResizeRows" Value="False"/>
      <Setter Property="SelectionMode" Value="Single"/>
      <Setter Property="IsReadOnly" Value="True"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#F7F7F7"/>
      <Setter Property="Foreground" Value="#4A4A4A"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="10,0"/>
      <Setter Property="Height" Value="36"/>
      <Setter Property="BorderThickness" Value="0"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="10,0"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="10,0">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#EEF3FA"/>
          <Setter Property="Foreground" Value="#1B1B1B"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <DataTemplate x:Key="BadgeStatus">
      <Border Background="{Binding StatusBg}" CornerRadius="12" Padding="10,3" HorizontalAlignment="Left">
        <TextBlock Text="{Binding Status}" Foreground="{Binding StatusFg}" FontSize="12" FontWeight="SemiBold"/>
      </Border>
    </DataTemplate>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="32"/></Grid.RowDefinitions>
    <Grid.ColumnDefinitions><ColumnDefinition Width="220"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>

    <!-- Menu lateral -->
    <DockPanel Grid.Row="0" Grid.Column="0" Margin="12,16,12,12" LastChildFill="True">
      <Image x:Name="LogoImage" DockPanel.Dock="Top" Height="60" HorizontalAlignment="Left" Margin="6,0,0,14" AutomationProperties.Name="Trivor Custom IT Solutions"/>
      <RadioButton x:Name="NavAbout" DockPanel.Dock="Bottom" Style="{StaticResource NavItem}" Content="Sobre"/>
      <StackPanel>
        <RadioButton x:Name="NavClients" Style="{StaticResource NavItem}" Content="Clientes" IsChecked="True"/>
        <RadioButton x:Name="NavUpgrade" Style="{StaticResource NavItem}" Content="Upgrade geral"/>
        <RadioButton x:Name="NavReports" Style="{StaticResource NavItem}" Content="Relatórios (em breve)" IsEnabled="False"/>
        <RadioButton x:Name="NavLogs" Style="{StaticResource NavItem}" Content="Logs"/>
      </StackPanel>
    </DockPanel>

    <!-- Conteudo -->
    <Border Grid.Row="0" Grid.Column="1" Margin="0,8,8,0" Background="#FAFAFA" BorderBrush="#E5E5E5" BorderThickness="1,1,1,0" CornerRadius="8,8,0,0">
      <Grid Margin="32,28,32,0">

        <!-- 1. Clientes -->
        <Grid x:Name="ViewClients">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <StackPanel>
            <DockPanel>
              <StackPanel DockPanel.Dock="Right" Width="320" VerticalAlignment="Bottom">
                <Label Content="Buscar cliente" Target="{Binding ElementName=SearchBox}" Padding="0,0,0,4" FontSize="12" Foreground="#5C5C5C"/>
                <TextBox x:Name="SearchBox" Height="36" Padding="10,0" VerticalContentAlignment="Center" BorderBrush="#C4C4C4"/>
              </StackPanel>
              <StackPanel>
                <TextBlock Style="{StaticResource H1}" Text="Selecione o cliente"/>
                <TextBlock x:Name="ClientsCount" Style="{StaticResource Muted}" Margin="0,4,0,0"/>
              </StackPanel>
            </DockPanel>
            <Border x:Name="DetectedBanner" Margin="0,16,0,0" Padding="16,10" CornerRadius="6" BorderThickness="1" Background="#EAF2F8" BorderBrush="#C3D9EA">
              <DockPanel>
                <Button x:Name="BtnOpenDetected" DockPanel.Dock="Right" Style="{StaticResource AccentButton}" Content="Abrir cliente detectado" Visibility="Collapsed" Margin="16,0,0,0"/>
                <TextBlock x:Name="DetectedText" Foreground="#123A57" FontSize="13" TextWrapping="Wrap" VerticalAlignment="Center" Text="Identificando o cliente desta máquina…"/>
              </DockPanel>
            </Border>
          </StackPanel>
          <ScrollViewer Grid.Row="1" Margin="0,20,0,0" VerticalScrollBarVisibility="Auto">
            <ItemsControl x:Name="ClientsList">
              <ItemsControl.ItemsPanel><ItemsPanelTemplate><UniformGrid Columns="4" VerticalAlignment="Top"/></ItemsPanelTemplate></ItemsControl.ItemsPanel>
              <ItemsControl.ItemTemplate>
                <DataTemplate>
                  <Button Tag="{Binding Name}" Margin="0,0,12,12" MinHeight="60" Padding="16,0" HorizontalContentAlignment="Left" BorderBrush="#E0E0E0" AutomationProperties.Name="{Binding Name}">
                    <TextBlock Text="{Binding Name}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
                  </Button>
                </DataTemplate>
              </ItemsControl.ItemTemplate>
            </ItemsControl>
          </ScrollViewer>
          <TextBlock Grid.Row="2" Style="{StaticResource Muted}" Margin="0,8,0,14" Text="Clique em um cliente para abrir o painel."/>
        </Grid>

        <!-- 2. Painel do cliente -->
        <Grid x:Name="ViewClient" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <DockPanel>
            <Border DockPanel.Dock="Right" Style="{StaticResource Card}" Padding="18,10">
              <StackPanel Orientation="Horizontal">
                <StackPanel>
                  <TextBlock Style="{StaticResource Muted}" FontSize="12" Text="Hostname atual"/>
                  <TextBlock x:Name="HostCurrent" FontFamily="Consolas" FontSize="15" FontWeight="SemiBold"/>
                </StackPanel>
                <TextBlock Text="→" Margin="16,0" VerticalAlignment="Center" Foreground="#5C5C5C"/>
                <StackPanel>
                  <TextBlock Style="{StaticResource Muted}" FontSize="12" Text="Esperado (prefixo + serial)"/>
                  <TextBlock x:Name="HostExpected" FontFamily="Consolas" FontSize="15" FontWeight="SemiBold"/>
                </StackPanel>
                <Border x:Name="HostBadge" CornerRadius="12" Padding="10,4" Margin="16,0,0,0" VerticalAlignment="Center">
                  <TextBlock x:Name="HostBadgeText" FontSize="12" FontWeight="SemiBold"/>
                </Border>
              </StackPanel>
            </Border>
            <StackPanel Orientation="Horizontal">
              <Button x:Name="BtnBack" Width="44" Height="44" Padding="0" FontFamily="Segoe MDL2 Assets" Content="&#xE72B;" ToolTip="Voltar para clientes" AutomationProperties.Name="Voltar para clientes"/>
              <StackPanel Margin="16,0,0,0" VerticalAlignment="Center">
                <TextBlock x:Name="ClientTitle" Style="{StaticResource H1}"/>
                <TextBlock x:Name="ClientSubtitle" Style="{StaticResource Muted}"/>
              </StackPanel>
            </StackPanel>
          </DockPanel>

          <UniformGrid Grid.Row="1" Columns="5" Margin="0,18,-12,18">
            <Button x:Name="BtnPostFormat" Style="{StaticResource AccentActionCard}">
              <StackPanel><TextBlock Text="Pós-Formatação" FontSize="15" FontWeight="SemiBold"/><TextBlock Text="Hostname + instalar tudo por prioridade" FontSize="12" TextWrapping="Wrap" Margin="0,6,0,0"/></StackPanel>
            </Button>
            <Button x:Name="BtnCompliance" Style="{StaticResource ActionCard}">
              <StackPanel><TextBlock Text="Compliance" FontSize="15" FontWeight="SemiBold"/><TextBlock Text="Verificar, instalar faltantes e atualizar" FontSize="12" Foreground="#5C5C5C" TextWrapping="Wrap" Margin="0,6,0,0"/></StackPanel>
            </Button>
            <Button x:Name="BtnSelected" Style="{StaticResource ActionCard}">
              <StackPanel><TextBlock Text="Instalar selecionados" FontSize="15" FontWeight="SemiBold"/><TextBlock x:Name="SelectedDesc" FontSize="12" Foreground="#5C5C5C" TextWrapping="Wrap" Margin="0,6,0,0"/></StackPanel>
            </Button>
            <Button x:Name="BtnUpdate" Style="{StaticResource ActionCard}">
              <StackPanel><TextBlock Text="Atualizar apps" FontSize="15" FontWeight="SemiBold"/><TextBlock Text="Winget update dos apps do cliente" FontSize="12" Foreground="#5C5C5C" TextWrapping="Wrap" Margin="0,6,0,0"/></StackPanel>
            </Button>
            <Button x:Name="BtnHostname" Style="{StaticResource ActionCard}">
              <StackPanel><TextBlock Text="Renomear hostname" FontSize="15" FontWeight="SemiBold"/><TextBlock x:Name="HostnameDesc" FontSize="12" Foreground="#5C5C5C" TextWrapping="Wrap" Margin="0,6,0,0"/></StackPanel>
            </Button>
          </UniformGrid>

          <Border Grid.Row="2" Style="{StaticResource Card}" Margin="0,0,0,16">
            <DockPanel>
              <DockPanel DockPanel.Dock="Top" Margin="16,12">
                <TextBlock x:Name="AppsSummary" DockPanel.Dock="Right" Style="{StaticResource Muted}" VerticalAlignment="Center"/>
                <TextBlock Style="{StaticResource H2}" Text="Aplicativos"/>
              </DockPanel>
              <DataGrid x:Name="AppsGrid">
                <DataGrid.Columns>
                  <DataGridTemplateColumn Width="48">
                    <DataGridTemplateColumn.CellTemplate>
                      <DataTemplate><CheckBox IsChecked="{Binding Selected, Mode=OneWay}" HorizontalAlignment="Center" AutomationProperties.Name="{Binding Name}"/></DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                  </DataGridTemplateColumn>
                  <DataGridTextColumn Header="Aplicativo" Binding="{Binding Name}" Width="2.2*" FontWeight="SemiBold"/>
                  <DataGridTextColumn Header="Origem" Binding="{Binding Source}" Width="1.6*"/>
                  <DataGridTemplateColumn Header="Status" Width="1.2*" CellTemplate="{StaticResource BadgeStatus}"/>
                  <DataGridTextColumn Header="Versão" Binding="{Binding Version}" Width="1*" FontFamily="Consolas"/>
                </DataGrid.Columns>
              </DataGrid>
            </DockPanel>
          </Border>
        </Grid>

        <!-- 3. Execucao -->
        <Grid x:Name="ViewRun" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <DockPanel>
            <Button x:Name="BtnCancel" DockPanel.Dock="Right" Content="Cancelar após o app atual" VerticalAlignment="Bottom"/>
            <StackPanel>
              <TextBlock x:Name="RunTitle" Style="{StaticResource H1}"/>
              <TextBlock x:Name="RunSubtitle" Style="{StaticResource Muted}" Margin="0,4,0,0"/>
            </StackPanel>
          </DockPanel>
          <Border Grid.Row="1" Style="{StaticResource Card}" Padding="20,16" Margin="0,18">
            <StackPanel>
              <DockPanel>
                <TextBlock x:Name="RunPercent" DockPanel.Dock="Right" Style="{StaticResource Muted}"/>
                <TextBlock x:Name="RunStatus"/>
              </DockPanel>
              <ProgressBar x:Name="RunProgress" Height="8" Margin="0,10,0,0" Maximum="100" Foreground="#3568B1" Background="#E5E5E5" BorderThickness="0"/>
            </StackPanel>
          </Border>
          <Grid Grid.Row="2" Margin="0,0,0,16">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="1.35*"/></Grid.ColumnDefinitions>
            <Border Style="{StaticResource Card}">
              <DockPanel>
                <TextBlock DockPanel.Dock="Top" Style="{StaticResource H2}" Text="Etapas" Margin="16,12"/>
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                  <ItemsControl x:Name="StepsList">
                    <ItemsControl.ItemTemplate>
                      <DataTemplate>
                        <Border BorderBrush="#EEEEEE" BorderThickness="0,1,0,0" Padding="16,0" Height="46">
                          <DockPanel>
                            <Ellipse DockPanel.Dock="Left" Width="12" Height="12" Fill="{Binding Dot}" Stroke="{Binding Ring}" StrokeThickness="2" VerticalAlignment="Center"/>
                            <TextBlock DockPanel.Dock="Right" Text="{Binding StateText}" Foreground="{Binding StateColor}" FontSize="12" VerticalAlignment="Center"/>
                            <TextBlock Text="{Binding Name}" FontWeight="{Binding Weight}" Margin="12,0" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
                          </DockPanel>
                        </Border>
                      </DataTemplate>
                    </ItemsControl.ItemTemplate>
                  </ItemsControl>
                </ScrollViewer>
              </DockPanel>
            </Border>
            <Border Grid.Column="1" Style="{StaticResource Card}" Margin="16,0,0,0">
              <DockPanel>
                <TextBlock DockPanel.Dock="Top" Style="{StaticResource H2}" Text="Log" Margin="16,12"/>
                <TextBox x:Name="RunLog" Style="{StaticResource Mono}"/>
              </DockPanel>
            </Border>
          </Grid>
        </Grid>

        <!-- 4. Resumo -->
        <Grid x:Name="ViewSummary" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <DockPanel>
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Bottom">
              <Button x:Name="BtnSumBack" Content="Voltar"/>
              <Button x:Name="BtnSumLog" Content="Abrir log" Margin="8,0,0,0" Style="{StaticResource AccentButton}"/>
            </StackPanel>
            <StackPanel>
              <TextBlock x:Name="SumTitle" Style="{StaticResource H1}"/>
              <TextBlock x:Name="SumSubtitle" Style="{StaticResource Muted}" Margin="0,4,0,0"/>
            </StackPanel>
          </DockPanel>
          <UniformGrid Grid.Row="1" Columns="4" Margin="0,16,-12,16">
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,12,0"><StackPanel><TextBlock Style="{StaticResource Muted}" Text="Com sucesso"/><TextBlock x:Name="SumOk" FontSize="32" FontWeight="SemiBold" Foreground="#0B5E30"/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,12,0"><StackPanel><TextBlock Style="{StaticResource Muted}" Text="Falhas"/><TextBlock x:Name="SumFail" FontSize="32" FontWeight="SemiBold" Foreground="#9C1F17"/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,12,0"><StackPanel><TextBlock Style="{StaticResource Muted}" Text="Código de saída da sessão (RMM)"/><TextBlock x:Name="SumExit" FontSize="32" FontWeight="SemiBold"/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Padding="18,14" Margin="0,0,12,0"><StackPanel><TextBlock Style="{StaticResource Muted}" Text="Duração"/><TextBlock x:Name="SumDuration" FontSize="32" FontWeight="SemiBold"/></StackPanel></Border>
          </UniformGrid>
          <Border x:Name="RebootBanner" Grid.Row="2" Background="#FFF4DE" BorderBrush="#F0D9A8" BorderThickness="1" CornerRadius="6" Padding="18,12" Margin="0,0,0,16" Visibility="Collapsed">
            <DockPanel>
              <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                <Button x:Name="BtnRebootLater" Content="Depois" Foreground="#5C3800" BorderBrush="#C9A86A"/>
                <Button x:Name="BtnRebootNow" Content="Reiniciar ao fechar" Margin="8,0,0,0" Background="#7A4A00" BorderBrush="#7A4A00" Foreground="#FFFFFF" FontWeight="SemiBold"/>
              </StackPanel>
              <StackPanel VerticalAlignment="Center">
                <TextBlock Text="Reinício pendente" FontWeight="SemiBold" Foreground="#5C3800"/>
                <TextBlock x:Name="RebootText" FontSize="13" Foreground="#5C3800" TextWrapping="Wrap"/>
              </StackPanel>
            </DockPanel>
          </Border>
          <Border Grid.Row="3" Style="{StaticResource Card}" Margin="0,0,0,16">
            <DataGrid x:Name="ResultsGrid">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Etapa" Binding="{Binding Name}" Width="1.6*" FontWeight="SemiBold"/>
                <DataGridTemplateColumn Header="Resultado" Width="1*" CellTemplate="{StaticResource BadgeStatus}"/>
                <DataGridTextColumn Header="Detalhe" Binding="{Binding Detail}" Width="2.4*"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
        </Grid>

        <!-- 5. Upgrade geral -->
        <Grid x:Name="ViewUpgrade" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <DockPanel>
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Bottom">
              <Button x:Name="BtnUpgradeRefresh" Content="Verificar novamente"/>
              <Button x:Name="BtnUpgradeRun" Content="Atualizar selecionados" Margin="8,0,0,0" Style="{StaticResource AccentButton}"/>
            </StackPanel>
            <StackPanel>
              <TextBlock Style="{StaticResource H1}" Text="Upgrade geral da máquina"/>
              <TextBlock Style="{StaticResource Muted}" Margin="0,4,0,0" Text="Todos os apps com atualização no winget, não só os do cliente"/>
            </StackPanel>
          </DockPanel>
          <Border Grid.Row="1" Background="#EAF2F8" BorderBrush="#C3D9EA" BorderThickness="1" CornerRadius="6" Padding="16,10" Margin="0,16">
            <TextBlock Foreground="#123A57" FontSize="13" TextWrapping="Wrap" Text="Nada é atualizado sem confirmação. Desmarque o que não deve mudar nesta máquina (ex.: software com versão homologada pelo cliente)."/>
          </Border>
          <Border Grid.Row="2" Style="{StaticResource Card}" Margin="0,0,0,16">
            <DockPanel>
              <DockPanel DockPanel.Dock="Top" Margin="16,12">
                <CheckBox x:Name="UpgradeUnknown" DockPanel.Dock="Right" Content="Incluir versões desconhecidas" VerticalAlignment="Center"/>
                <TextBlock x:Name="UpgradeStatus" Style="{StaticResource H2}"/>
              </DockPanel>
              <Grid>
                <DataGrid x:Name="UpgradeGrid">
                  <DataGrid.Columns>
                    <DataGridTemplateColumn Width="48">
                      <DataGridTemplateColumn.CellTemplate>
                        <DataTemplate><CheckBox IsChecked="{Binding Selected, Mode=OneWay}" IsEnabled="{Binding Selectable}" HorizontalAlignment="Center" AutomationProperties.Name="{Binding Name}"/></DataTemplate>
                      </DataGridTemplateColumn.CellTemplate>
                    </DataGridTemplateColumn>
                    <DataGridTextColumn Header="Aplicativo" Binding="{Binding Name}" Width="2*" FontWeight="SemiBold"/>
                    <DataGridTextColumn Header="Id winget" Binding="{Binding Id}" Width="2*" FontFamily="Consolas"/>
                    <DataGridTextColumn Header="Instalada" Binding="{Binding Version}" Width="1*" FontFamily="Consolas"/>
                    <DataGridTextColumn Header="Disponível" Binding="{Binding Available}" Width="1*" FontFamily="Consolas"/>
                  </DataGrid.Columns>
                </DataGrid>
                <TextBox x:Name="UpgradeRaw" Style="{StaticResource Mono}" Visibility="Collapsed"/>
              </Grid>
            </DockPanel>
          </Border>
        </Grid>

        <!-- 6. Logs -->
        <Grid x:Name="ViewLogs" Visibility="Collapsed">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <DockPanel>
            <Button x:Name="BtnOpenLogFolder" DockPanel.Dock="Right" Content="Abrir pasta" VerticalAlignment="Bottom"/>
            <StackPanel>
              <TextBlock Style="{StaticResource H1}" Text="Logs"/>
              <TextBlock x:Name="LogsPath" Style="{StaticResource Muted}" Margin="0,4,0,0"/>
            </StackPanel>
          </DockPanel>
          <Grid Grid.Row="1" Margin="0,16,0,16">
            <Grid.ColumnDefinitions><ColumnDefinition Width="320"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Border Style="{StaticResource Card}">
              <DockPanel>
                <TextBlock DockPanel.Dock="Top" Style="{StaticResource H2}" Text="Arquivos" Margin="16,12"/>
                <ListBox x:Name="LogFilesList" BorderThickness="0">
                  <ListBox.ItemTemplate>
                    <DataTemplate>
                      <StackPanel Margin="6,6">
                        <TextBlock Text="{Binding Name}" FontFamily="Consolas" FontSize="12" FontWeight="SemiBold"/>
                        <TextBlock Text="{Binding Meta}" FontSize="12" Foreground="#5C5C5C"/>
                      </StackPanel>
                    </DataTemplate>
                  </ListBox.ItemTemplate>
                </ListBox>
              </DockPanel>
            </Border>
            <Border Grid.Column="1" Style="{StaticResource Card}" Margin="16,0,0,0">
              <DockPanel>
                <DockPanel DockPanel.Dock="Top" Margin="16,10">
                  <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                    <Label Content="Buscar" Target="{Binding ElementName=LogSearch}" VerticalAlignment="Center" FontSize="12" Foreground="#5C5C5C"/>
                    <TextBox x:Name="LogSearch" Width="220" Height="32" Padding="8,0" VerticalContentAlignment="Center"/>
                  </StackPanel>
                  <StackPanel Orientation="Horizontal">
                    <RadioButton x:Name="LevelAll" Style="{StaticResource Chip}" Content="Todos" IsChecked="True"/>
                    <RadioButton x:Name="LevelInfo" Style="{StaticResource Chip}" Content="INFO"/>
                    <RadioButton x:Name="LevelWarn" Style="{StaticResource Chip}" Content="WARN"/>
                    <RadioButton x:Name="LevelError" Style="{StaticResource Chip}" Content="ERROR"/>
                  </StackPanel>
                </DockPanel>
                <TextBox x:Name="LogViewer" Style="{StaticResource Mono}"/>
              </DockPanel>
            </Border>
          </Grid>
        </Grid>

        <!-- 7. Sobre -->
        <ScrollViewer x:Name="ViewAbout" Visibility="Collapsed" VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="0,0,0,16">
            <Border Style="{StaticResource Card}" Padding="28,24">
              <DockPanel>
                <StackPanel DockPanel.Dock="Right" VerticalAlignment="Center">
                  <Button x:Name="BtnChangelog" Content="Ver o que mudou (CHANGELOG)" Style="{StaticResource AccentButton}"/>
                  <Button x:Name="BtnSite" Content="trivor.com.br" Margin="0,8,0,0"/>
                </StackPanel>
                <StackPanel Orientation="Horizontal">
                  <Image x:Name="AboutLogo" Height="100" Width="250"/>
                  <Border BorderBrush="#E5E5E5" BorderThickness="1,0,0,0" Padding="28,0,0,0" Margin="28,0,0,0">
                    <StackPanel VerticalAlignment="Center">
                      <TextBlock Style="{StaticResource H1}" Text="Trivor Installer"/>
                      <TextBlock x:Name="AboutVersion" FontSize="15" Foreground="#4A4A4A" Margin="0,4,0,0"/>
                      <TextBlock Style="{StaticResource Muted}" Margin="0,4,0,0" Text="Padronização de instalação de softwares e aplicativos gerenciados"/>
                    </StackPanel>
                  </Border>
                </StackPanel>
              </DockPanel>
            </Border>
            <UniformGrid Columns="2" Margin="0,16,-16,0">
              <Border Style="{StaticResource Card}" Margin="0,0,16,0">
                <StackPanel>
                  <TextBlock Style="{StaticResource H2}" Text="Ambiente" Margin="16,12"/>
                  <ItemsControl x:Name="AboutEnv">
                    <ItemsControl.ItemTemplate>
                      <DataTemplate>
                        <Border BorderBrush="#F0F0F0" BorderThickness="0,1,0,0" Padding="16,0" MinHeight="44">
                          <DockPanel><TextBlock DockPanel.Dock="Right" Text="{Binding V}" FontWeight="SemiBold" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/><TextBlock Text="{Binding K}" Foreground="#4A4A4A" VerticalAlignment="Center"/></DockPanel>
                        </Border>
                      </DataTemplate>
                    </ItemsControl.ItemTemplate>
                  </ItemsControl>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Margin="0,0,16,0">
                <StackPanel>
                  <TextBlock Style="{StaticResource H2}" Text="Pastas e retenção" Margin="16,12"/>
                  <ItemsControl x:Name="AboutPaths">
                    <ItemsControl.ItemTemplate>
                      <DataTemplate>
                        <Border BorderBrush="#F0F0F0" BorderThickness="0,1,0,0" Padding="16,0" MinHeight="44">
                          <DockPanel><TextBlock DockPanel.Dock="Right" Text="{Binding V}" FontWeight="SemiBold" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/><TextBlock Text="{Binding K}" Foreground="#4A4A4A" VerticalAlignment="Center"/></DockPanel>
                        </Border>
                      </DataTemplate>
                    </ItemsControl.ItemTemplate>
                  </ItemsControl>
                </StackPanel>
              </Border>
            </UniformGrid>
            <TextBlock Style="{StaticResource Muted}" Margin="0,16,0,0" Text="Desenvolvido por Fernando B. Oliveira · Trivor Custom IT Solutions"/>
          </StackPanel>
        </ScrollViewer>
      </Grid>
    </Border>

    <!-- Barra de status -->
    <Border Grid.Row="1" Grid.ColumnSpan="2" Background="#EBEBEB" BorderBrush="#D9D9D9" BorderThickness="0,1,0,0">
      <StackPanel Orientation="Horizontal" Margin="16,0" VerticalAlignment="Center">
        <Ellipse x:Name="StatusDot" Width="8" Height="8" Fill="#0E7A3E" VerticalAlignment="Center"/>
        <TextBlock x:Name="StatusContext" Margin="6,0,24,0" FontSize="12" Foreground="#4A4A4A"/>
        <TextBlock x:Name="StatusWinget" Margin="0,0,24,0" FontSize="12" Foreground="#4A4A4A"/>
        <TextBlock x:Name="StatusLog" FontSize="12" Foreground="#4A4A4A"/>
      </StackPanel>
    </Border>
  </Grid>
</Window>
'@

$script:TrivorGuiConfirmXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Confirmação necessária" Width="560" SizeToContent="Height" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" FontFamily="Segoe UI" FontSize="14" Background="#FFFFFF">
  <StackPanel Margin="24,20">
    <TextBlock x:Name="ConfirmTitle" FontSize="17" FontWeight="SemiBold" Foreground="#7A4A00" TextWrapping="Wrap"/>
    <TextBlock x:Name="ConfirmText" Margin="0,10,0,0" TextWrapping="Wrap" Foreground="#1B1B1B"/>
    <Label x:Name="ConfirmLabel" Margin="0,16,0,0" Padding="0,0,0,4" Target="{Binding ElementName=ConfirmInput}"/>
    <TextBox x:Name="ConfirmInput" Height="36" Padding="10,0" VerticalContentAlignment="Center"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,20,0,0">
      <Button x:Name="ConfirmCancel" Content="Cancelar" IsCancel="True" MinWidth="110" Height="36" Padding="16,0"/>
      <Button x:Name="ConfirmOk" Content="Continuar mesmo assim" IsEnabled="False" MinWidth="110" Height="36" Padding="16,0" Margin="8,0,0,0"/>
    </StackPanel>
  </StackPanel>
</Window>
'@

#endregion

#region Janela

function ConvertFrom-TrivorBase64Image {
    param([string]$Base64)
    $bytes = [Convert]::FromBase64String($Base64)
    $ms = New-Object System.IO.MemoryStream(, $bytes)
    $img = New-Object System.Windows.Media.Imaging.BitmapImage
    $img.BeginInit()
    $img.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
    $img.StreamSource = $ms
    $img.EndInit()
    $img.Freeze()
    return $img
}

function Show-TrivorGuiMessage {
    param([string]$Text, [string]$Kind = 'Info', [switch]$YesNo)
    $buttons = if ($YesNo) { [System.Windows.MessageBoxButton]::YesNo } else { [System.Windows.MessageBoxButton]::OK }
    $icon = switch ($Kind) { 'Error' { [System.Windows.MessageBoxImage]::Error } 'Warn' { [System.Windows.MessageBoxImage]::Warning } 'Question' { [System.Windows.MessageBoxImage]::Question } default { [System.Windows.MessageBoxImage]::Information } }
    $owner = $script:Gui.Window
    $r = if ($owner) { [System.Windows.MessageBox]::Show($owner, $Text, 'Trivor Installer', $buttons, $icon) } else { [System.Windows.MessageBox]::Show($Text, 'Trivor Installer', $buttons, $icon) }
    return ($r -eq [System.Windows.MessageBoxResult]::Yes -or $r -eq [System.Windows.MessageBoxResult]::OK)
}

function Show-TrivorGuiChoice {
    # Sim / Nao / Cancelar. Retorna 'Yes', 'No' ou 'Cancel'.
    param([string]$Text)
    $r = [System.Windows.MessageBox]::Show($script:Gui.Window, $Text, 'Trivor Installer', [System.Windows.MessageBoxButton]::YesNoCancel, [System.Windows.MessageBoxImage]::Warning)
    switch ($r) { 'Yes' { 'Yes' } 'No' { 'No' } default { 'Cancel' } }
}

function Show-TrivorGuiTypeConfirm {
    # Confirmacao forte: o botao so habilita quando o analista digita exatamente o nome esperado.
    param([string]$Title, [string]$Text, [Parameter(Mandatory)] [string]$Expected)

    $xml = [xml]$script:TrivorGuiConfirmXaml
    $dlg = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xml))
    $dlg.Owner = $script:Gui.Window
    $dlg.Icon = $script:Gui.Window.Icon
    $c = @{}
    foreach ($n in @('ConfirmTitle', 'ConfirmText', 'ConfirmLabel', 'ConfirmInput', 'ConfirmCancel', 'ConfirmOk')) { $c[$n] = $dlg.FindName($n) }
    $c.ConfirmTitle.Text = $Title
    $c.ConfirmText.Text = $Text
    $c.ConfirmLabel.Content = "Para continuar, digite o nome do cliente: $Expected"
    $script:TrivorGuiConfirmExpected = $Expected
    $script:TrivorGuiConfirmCtl = $c
    $c.ConfirmInput.Add_TextChanged({ $script:TrivorGuiConfirmCtl.ConfirmOk.IsEnabled = ($script:TrivorGuiConfirmCtl.ConfirmInput.Text.Trim() -eq $script:TrivorGuiConfirmExpected) })
    $c.ConfirmOk.Add_Click({ $script:TrivorGuiConfirmDialog.DialogResult = $true })
    $script:TrivorGuiConfirmDialog = $dlg
    [void]$c.ConfirmInput.Focus()
    return [bool]$dlg.ShowDialog()
}

function Format-TrivorGuiPlanText {
    # Texto do resumo antes de executar (mesmo conteudo do console, com acentos).
    param([Parameter(Mandatory)] $Plan)
    $label = Get-TrivorGuiModeLabel $Plan.Mode
    $hostText = switch ($Plan.HostAction) {
        'Renomear'       { "$($Plan.CurrentHostname) → $($Plan.ExpectedHostname) (exige reiniciar)" }
        'JaCorreto'      { "$($Plan.CurrentHostname) (já está correto)" }
        'SemPrefixo'     { 'mantido (cliente sem prefixo)' }
        'SerialInvalido' { 'mantido (serial inválido, ver log)' }
        default          { 'mantido' }
    }
    $lines = @("Cliente: $($Plan.ClientName)", "Modo: $label")
    if ($Plan.Mode -ne 'Hostname') { $lines += "Aplicativos ($($Plan.AppCount)): $($Plan.AppNames -join ', ')" }
    $lines += "Hostname: $hostText"
    return ($lines -join "`n")
}

function Confirm-TrivorGuiPlan {
    param([Parameter(Mandatory)] [string]$Mode)
    $plan = Get-TrivorRunPlan -Mode $Mode -ClientName $script:Gui.ClientName -Config $script:Gui.Config -ExpectedHostname $script:Gui.ExpectedHostname
    return (Show-TrivorGuiMessage -Kind Question -YesNo -Text ("Confirmar a execução?`n`n" + (Format-TrivorGuiPlanText -Plan $plan)))
}

function Confirm-TrivorGuiClientChoice {
    # Cliente escolhido x cliente detectado na maquina. Retorna $true para seguir.
    param([Parameter(Mandatory)] [string]$Name)
    $check = Test-TrivorClientChoice -Selected $Name -Match $script:Gui.Match
    if ($check -eq 'Ok' -or $script:Gui.Confirmed[$Name]) { return $true }
    $m = $script:Gui.Match
    $what = if ($check -eq 'Mismatch') { "Esta máquina parece ser do cliente $($m.Client) ($($m.Reasons -join '; '))." } else { "Mais de um cliente corresponde a esta máquina: $($m.Clients -join ', ')." }
    $text = "$what`n`nVocê escolheu $Name. Aplicar o cliente errado instala o agente RMM e renomeia o hostname para outro cliente."
    if (Show-TrivorGuiTypeConfirm -Title 'O cliente escolhido não confere com esta máquina' -Text $text -Expected $Name) {
        $script:Gui.Confirmed[$Name] = $true
        Write-Log ("Analista confirmou cliente {0} apesar da deteccao ({1})." -f $Name, $check) "WARN"
        return $true
    }
    Write-Log ("Cliente {0} nao confirmado pelo analista ({1}). Nada foi executado." -f $Name, $check) "INFO"
    return $false
}

function Update-TrivorGuiDetectedBanner {
    $ui = $script:Gui.Ui
    $m = $script:Gui.Match
    $ui.BtnOpenDetected.Visibility = 'Collapsed'
    if (-not $m -or $m.Status -eq 'None') { $ui.DetectedBanner.Visibility = 'Collapsed'; return }
    $ui.DetectedBanner.Visibility = 'Visible'
    if ($m.Status -eq 'Single') {
        $ui.DetectedBanner.Background = '#EAF2F8'; $ui.DetectedBanner.BorderBrush = '#C3D9EA'; $ui.DetectedText.Foreground = '#123A57'
        $ui.DetectedText.Text = "Cliente detectado nesta máquina: $($m.Client) — $($m.Reasons -join '; ')."
        $ui.BtnOpenDetected.Tag = $m.Client
        $ui.BtnOpenDetected.Visibility = 'Visible'
    }
    else {
        $ui.DetectedBanner.Background = '#FFF4DE'; $ui.DetectedBanner.BorderBrush = '#F0D9A8'; $ui.DetectedText.Foreground = '#5C3800'
        $ui.DetectedText.Text = "Atenção: mais de um cliente corresponde a esta máquina ($($m.Clients -join ', ')). Confira antes de escolher."
    }
}

function Invoke-TrivorGuiSafe {
    # Executa um handler de evento sem derrubar a janela em caso de erro.
    param([scriptblock]$Action)
    try { . $Action }
    catch {
        try { Write-Log "Erro na interface grafica: $($_.Exception.Message)" "ERROR" } catch { Write-Verbose "Log indisponivel" }
        Show-TrivorGuiMessage -Text "Ocorreu um erro: $($_.Exception.Message)`n`nDetalhes no log da sessão." -Kind Error | Out-Null
    }
}

function Show-TrivorGuiView {
    param([Parameter(Mandatory)] [string]$Name)
    foreach ($v in @('ViewClients', 'ViewClient', 'ViewRun', 'ViewSummary', 'ViewUpgrade', 'ViewLogs', 'ViewAbout')) {
        $script:Gui.Ui[$v].Visibility = if ($v -eq $Name) { 'Visible' } else { 'Collapsed' }
    }
    $script:Gui.View = $Name
}

function Set-TrivorGuiBusy {
    param([bool]$Busy)
    $script:Gui.Busy = $Busy
    $ui = $script:Gui.Ui
    foreach ($n in @('NavClients', 'NavUpgrade', 'NavLogs', 'NavAbout', 'BtnBack', 'BtnPostFormat', 'BtnCompliance', 'BtnUpdate', 'BtnUpgradeRefresh', 'BtnUpgradeRun', 'ClientsList', 'UpgradeUnknown', 'BtnOpenDetected')) {
        $ui[$n].IsEnabled = -not $Busy
    }
    if (-not $Busy) { Update-TrivorGuiClientButtons }
    else { $ui.BtnSelected.IsEnabled = $false; $ui.BtnHostname.IsEnabled = $false }
    $ui.Window.Cursor = if ($Busy) { [System.Windows.Input.Cursors]::AppStarting } else { $null }
}

function Get-TrivorGuiWorkerContext {
    $names = @('TrivorBasePath', 'CachePath', 'TrivorLogFile', 'TrivorLogDir', 'TrivorOwner', 'TrivorRepo', 'TrivorBranch',
               'TrivorRoot', 'TrivorRootReady', 'TrivorVersion', 'TrivorWingetDir', 'TrivorLogRetentionDays')
    $globals = @{}
    foreach ($n in $names) {
        $v = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $v) { $globals[$n] = $v }
    }
    return @{
        CorePath = Join-Path $global:TrivorBasePath 'core'
        Modules  = @('Logger.ps1', 'Detection.ps1', 'Engine.ps1', 'Hostname.ps1', 'Guard.ps1')
        Globals  = $globals
    }
}

function Start-TrivorGuiJob {
    # Executa o worker em um runspace separado. OnDone roda na thread da janela.
    param([Parameter(Mandatory)] [string]$Kind, $Payload, [scriptblock]$OnDone, [string[]]$StepStates)

    $sync = [hashtable]::Synchronized(@{
        Finished = $false; Error = $null; Done = 0; Total = 0; Failed = 0; Current = ''
        CancelRequested = $false; Cancelled = $false; RebootRequired = $false
        Results = (New-Object System.Collections.ArrayList); StepStates = $StepStates
        Detect = $null; UpgradeText = $null
    })

    # Funcoes de seguranca do bootstrap (Install.ps1) para o motor usar no runspace
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fn in @('Test-TrivorReparsePoint', 'Remove-TrivorReparsePoints', 'Remove-TrivorDirectorySafe', 'Protect-TrivorDirectory')) {
        $cmd = Get-Command $fn -CommandType Function -ErrorAction SilentlyContinue
        if ($cmd) { $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $cmd.ScriptBlock.ToString()))) }
    }
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($script:TrivorGuiWorker).AddArgument($sync).AddArgument((Get-TrivorGuiWorkerContext)).AddArgument($Kind).AddArgument($Payload)

    $script:Gui.Job = @{ Kind = $Kind; Sync = $sync; PS = $ps; Runspace = $rs; Handle = $ps.BeginInvoke(); OnDone = $OnDone }
    Set-TrivorGuiBusy -Busy $true
    $script:Gui.Timer.Start()
}

function Complete-TrivorGuiJob {
    $job = $script:Gui.Job
    try { $job.PS.EndInvoke($job.Handle) | Out-Null } catch { $job.Sync.Error = $_.Exception.Message }
    foreach ($e in @($job.PS.Streams.Error)) { try { Write-Log "Worker ($($job.Kind)): $($e.ToString())" "WARN" } catch { Write-Verbose "Log indisponivel" } }
    $job.PS.Dispose()
    $job.Runspace.Dispose()
    $script:Gui.Timer.Stop()
    $script:Gui.Job = $null
    # Uma falha ao reabilitar a tela nao pode impedir o OnDone (resultado da tarefa)
    try { Set-TrivorGuiBusy -Busy $false }
    catch {
        Write-Log "Falha ao reabilitar a interface: $($_.Exception.Message)" "WARN"
        $script:Gui.Busy = $false
        $script:Gui.Ui.Window.Cursor = $null
    }
    if ($job.OnDone) { & $job.OnDone $job.Sync }
}

function Update-TrivorGuiTick {
    $job = $script:Gui.Job
    if (-not $job) { $script:Gui.Timer.Stop(); return }
    if ($job.Kind -eq 'run') { Update-TrivorGuiRunView -Sync $job.Sync }
    if ($job.Sync.Finished -or $job.Handle.IsCompleted) { Complete-TrivorGuiJob }
}

#region Clientes

function Update-TrivorGuiClientList {
    $ui = $script:Gui.Ui
    $filter = [string]$ui.SearchBox.Text
    $all = @($script:Gui.Clients)
    $shown = if ([string]::IsNullOrWhiteSpace($filter)) { $all } else { @($all | Where-Object { $_.IndexOf($filter.Trim(), [StringComparison]::OrdinalIgnoreCase) -ge 0 }) }
    $ui.ClientsList.ItemsSource = @($shown | ForEach-Object { [pscustomobject]@{ Name = $_ } })
    $ui.ClientsCount.Text = if ($shown.Count -eq $all.Count) { "$($all.Count) clientes · carregados do repositório" } else { "$($shown.Count) de $($all.Count) clientes" }
}

function Open-TrivorGuiClient {
    param([Parameter(Mandatory)] [string]$Name)
    if (-not (Confirm-TrivorGuiClientChoice -Name $Name)) { return }
    $ui = $script:Gui.Ui
    $ui.Window.Cursor = [System.Windows.Input.Cursors]::Wait
    try { $cfg = Get-TrivorGuiClientConfig -ClientName $Name }
    finally { $ui.Window.Cursor = $null }

    $script:Gui.ClientName = $Name
    $script:Gui.Config = $cfg
    $apps = @($cfg.Applications)
    $hasPrefix = $cfg.PSObject.Properties.Match('HostnamePrefix').Count -gt 0 -and $cfg.HostnamePrefix

    $ui.ClientTitle.Text = $Name
    $ui.ClientSubtitle.Text = if ($hasPrefix) { "$($apps.Count) aplicativos · prefixo de hostname $(([string]$cfg.HostnamePrefix).ToUpper())" } else { "$($apps.Count) aplicativos · sem prefixo de hostname" }
    $ui.HostCurrent.Text = $env:COMPUTERNAME

    $expected = $null
    if ($hasPrefix) { $expected = Get-ExpectedHostname -Prefix ([string]$cfg.HostnamePrefix).ToUpper() }
    $script:Gui.ExpectedHostname = $expected
    if (-not $hasPrefix) { $b = Get-TrivorGuiStatusStyle 'neutral'; $ui.HostExpected.Text = '—'; $ui.HostBadgeText.Text = 'Sem prefixo'; $ui.HostnameDesc.Text = 'Cliente sem HostnamePrefix no JSON' }
    elseif (-not $expected) { $b = Get-TrivorGuiStatusStyle 'warn'; $ui.HostExpected.Text = '—'; $ui.HostBadgeText.Text = 'Serial inválido'; $ui.HostnameDesc.Text = 'Não foi possível montar o nome (ver log)' }
    elseif ($env:COMPUTERNAME -eq $expected) { $b = Get-TrivorGuiStatusStyle 'ok'; $ui.HostExpected.Text = $expected; $ui.HostBadgeText.Text = 'Correto'; $ui.HostnameDesc.Text = 'Hostname já está no padrão' }
    else { $b = Get-TrivorGuiStatusStyle 'warn'; $ui.HostExpected.Text = $expected; $ui.HostBadgeText.Text = 'Diferente'; $ui.HostnameDesc.Text = "Aplica $expected (exige reinício)" }
    $ui.HostBadge.Background = $b.Bg
    $ui.HostBadgeText.Foreground = $b.Fg

    $script:Gui.Detect = $null
    $script:Gui.Rows = @($apps | ForEach-Object { New-TrivorGuiAppRow -App $_ -State $null })
    $ui.AppsGrid.ItemsSource = $script:Gui.Rows
    $ui.AppsSummary.Text = 'Verificando o que está instalado…'
    Update-TrivorGuiClientButtons
    Show-TrivorGuiView 'ViewClient'

    Start-TrivorGuiJob -Kind 'detect' -Payload @{ Apps = $apps } -OnDone {
        param($sync)
        $ui = $script:Gui.Ui
        if ($sync.Error) { $ui.AppsSummary.Text = "Falha na verificação: $($sync.Error)"; return }
        $det = @($sync.Detect)
        $script:Gui.Detect = $det
        $apps = @($script:Gui.Config.Applications)
        $rows = for ($i = 0; $i -lt $apps.Count; $i++) { New-TrivorGuiAppRow -App $apps[$i] -State $(if ($i -lt $det.Count) { $det[$i] } else { $null }) }
        $script:Gui.Rows = @($rows)
        $ui.AppsGrid.ItemsSource = $script:Gui.Rows
        $inst = @($rows | Where-Object { $_.Status -eq 'Instalado' }).Count
        $miss = @($rows | Where-Object { $_.Status -eq 'Faltando' }).Count
        $old = @($rows | Where-Object { $_.Status -eq 'Versão antiga' }).Count
        $ui.AppsSummary.Text = "$inst instalados · $miss faltando · $old versão antiga"
        Update-TrivorGuiClientButtons
    }
}

function Update-TrivorGuiClientButtons {
    $ui = $script:Gui.Ui
    $cfg = $script:Gui.Config
    $sel = @($script:Gui.Rows | Where-Object { $_.Selected }).Count
    if (-not $cfg) {
        # Nenhum cliente aberto ainda (ex.: fim da deteccao inicial). Passar $null adiante no
        # pipeline gera um item nulo e quebrava esta funcao.
        $ui.SelectedDesc.Text = "Instala ou atualiza os marcados (0)"
        return
    }
    $ui.SelectedDesc.Text = "Instala ou atualiza os marcados ($sel)"
    if ($script:Gui.Busy) { return }
    $ui.BtnSelected.IsEnabled = ($sel -gt 0)
    $hasPrefix = $cfg -and $cfg.PSObject.Properties.Match('HostnamePrefix').Count -gt 0 -and $cfg.HostnamePrefix
    $ui.BtnHostname.IsEnabled = [bool]($hasPrefix -and $script:Gui.ExpectedHostname)
    $ui.BtnUpdate.IsEnabled = [bool](@($cfg.Applications | Where-Object { $_.PSObject.Properties.Match('WingetId').Count -gt 0 -and $_.WingetId }).Count)
}

#endregion

#region Execucao e resumo

function Start-TrivorGuiRun {
    param([Parameter(Mandatory)] [string]$Mode, $Steps, [string]$BackView = 'ViewClient')
    $steps = @($Steps)
    if ($steps.Count -eq 0) { Show-TrivorGuiMessage -Text 'Nada a executar.' | Out-Null; return }

    $ui = $script:Gui.Ui
    $label = Get-TrivorGuiModeLabel $Mode
    $script:Gui.Run = @{ Mode = $Mode; Label = $label; Steps = $steps; Started = Get-Date; BackView = $BackView }
    $ui.RunTitle.Text = "$label em andamento"
    $who = if ($Mode -eq 'Upgrade') { 'Máquina inteira' } else { $script:Gui.ClientName }
    $ui.RunSubtitle.Text = "$who · iniciado às $((Get-Date).ToString('HH:mm')) · $(Split-Path $global:TrivorBasePath -Leaf)"
    $ui.RunLog.Clear()
    $ui.BtnCancel.IsEnabled = $true
    $ui.BtnCancel.Content = 'Cancelar após o app atual'

    $script:Gui.LogOffset = 0
    if ($global:TrivorLogFile -and (Test-Path -LiteralPath $global:TrivorLogFile)) { $script:Gui.LogOffset = (Get-Item -LiteralPath $global:TrivorLogFile).Length }

    $states = New-Object 'string[]' $steps.Count
    for ($i = 0; $i -lt $steps.Count; $i++) { $states[$i] = 'wait' }

    Show-TrivorGuiView 'ViewRun'
    $payload = @{ Mode = $Mode; Steps = $steps; Config = $script:Gui.Config; ClientName = $who }
    Start-TrivorGuiJob -Kind 'run' -Payload $payload -StepStates $states -OnDone {
        param($sync)
        Update-TrivorGuiRunView -Sync $sync
        # Contadores da sessao (exit code 0/1/2 e resumo final do Install.ps1)
        $global:TrivorSessionTotal = [int]$global:TrivorSessionTotal + [int]$sync.Total
        $global:TrivorSessionFailed = [int]$global:TrivorSessionFailed + [int]$sync.Failed
        if ($sync.RebootRequired) { $global:TrivorRebootRequired = $true }
        Show-TrivorGuiSummary -Sync $sync
    }
    Update-TrivorGuiRunView -Sync $script:Gui.Job.Sync
}

function Read-TrivorGuiLogTail {
    # Linhas novas do log da sessao desde a ultima leitura (sem DEBUG).
    $path = $global:TrivorLogFile
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        if ($fs.Length -le $script:Gui.LogOffset) { return @() }
        [void]$fs.Seek($script:Gui.LogOffset, 'Begin')
        $buf = New-Object byte[] ($fs.Length - $script:Gui.LogOffset)
        $n = $fs.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return @() }
        $lastNl = [Array]::LastIndexOf($buf, [byte]10, $n - 1)
        if ($lastNl -lt 0) { return @() }
        $script:Gui.LogOffset += ($lastNl + 1)
        $text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $lastNl + 1)
        return @($text -split "`r?`n" | Where-Object { $_ -and $_ -notmatch '\[DEBUG\]' })
    }
    catch { return @() }
    finally { if ($fs) { $fs.Dispose() } }
}

function Update-TrivorGuiRunView {
    param($Sync)
    $ui = $script:Gui.Ui
    $steps = @($script:Gui.Run.Steps)
    $states = @($Sync.StepStates)
    $ui.StepsList.ItemsSource = @(for ($i = 0; $i -lt $steps.Count; $i++) {
        $v = Get-TrivorGuiStepVisual $states[$i]
        [pscustomobject]@{ Name = $steps[$i].Name; Dot = $v.Dot; Ring = $v.Ring; StateText = $v.Text; StateColor = $v.Color; Weight = $v.Weight }
    })
    $done = [int]$Sync.Done
    $pct = if ($steps.Count) { [int][Math]::Floor($done * 100 / $steps.Count) } else { 100 }
    $ui.RunProgress.Value = $pct
    $ui.RunPercent.Text = "$pct%"
    $current = if ($Sync.Finished) { 'Finalizando…' } elseif ($Sync.CancelRequested) { "Cancelamento solicitado · terminando: $($Sync.Current)" } else { [string]$Sync.Current }
    $ui.RunStatus.Text = "$done de $($steps.Count) etapas · $current"

    $lines = @(Read-TrivorGuiLogTail)
    if ($lines.Count) { $ui.RunLog.AppendText(($lines -join "`r`n") + "`r`n"); $ui.RunLog.ScrollToEnd() }
}

function Show-TrivorGuiSummary {
    param($Sync)
    $ui = $script:Gui.Ui
    $run = $script:Gui.Run
    $results = @($Sync.Results)
    $ok = @($results | Where-Object { $_.State -eq 'done' }).Count
    $fail = @($results | Where-Object { $_.State -eq 'fail' }).Count
    $elapsed = (Get-Date) - $run.Started

    $title = if ($fail -eq 0) { "$($run.Label) concluída" } else { "$($run.Label) concluída com $fail falha(s)" }
    if ($Sync.Cancelled) { $title = "$($run.Label) cancelada" }
    if ($Sync.Error) { $title = "$($run.Label) interrompida por erro" }
    $ui.SumTitle.Text = $title
    $who = if ($run.Mode -eq 'Upgrade') { 'Máquina inteira' } else { $script:Gui.ClientName }
    $ui.SumSubtitle.Text = "$who · $($env:COMPUTERNAME) · $($run.Started.ToString('HH:mm')) até $((Get-Date).ToString('HH:mm'))" + $(if ($Sync.Error) { " · erro: $($Sync.Error)" } else { '' })
    $ui.SumOk.Text = "$ok"
    $ui.SumFail.Text = "$fail"
    $ui.SumExit.Text = if ([int]$global:TrivorSessionFailed -gt 0) { '2' } else { '0' }
    $ui.SumDuration.Text = if ($elapsed.TotalMinutes -ge 1) { "$([int][Math]::Round($elapsed.TotalMinutes)) min" } else { "$([int]$elapsed.TotalSeconds) s" }

    $ui.ResultsGrid.ItemsSource = @($results | ForEach-Object {
        $kind = switch ($_.State) { 'done' { 'ok' } 'fail' { 'miss' } default { 'neutral' } }
        $label = switch ($_.State) { 'done' { 'Sucesso' } 'fail' { 'Falha' } default { 'Não executado' } }
        $s = Get-TrivorGuiStatusStyle $kind
        [pscustomobject]@{ Name = $_.Name; Status = $label; StatusBg = $s.Bg; StatusFg = $s.Fg; Detail = $_.Detail }
    })

    if ($global:TrivorRebootRequired) {
        $ui.RebootText.Text = 'Um ou mais itens (hostname ou instaladores) só valem após reiniciar a máquina.'
        $ui.RebootBanner.Visibility = 'Visible'
    } else { $ui.RebootBanner.Visibility = 'Collapsed' }

    $ui.BtnSumBack.Content = if ($run.BackView -eq 'ViewUpgrade') { 'Voltar ao Upgrade geral' } else { 'Voltar ao cliente' }
    Show-TrivorGuiView 'ViewSummary'
}

#endregion

#region Upgrade geral

function Start-TrivorGuiUpgradeList {
    $ui = $script:Gui.Ui
    $ui.UpgradeStatus.Text = 'Consultando o winget…'
    $ui.UpgradeGrid.ItemsSource = $null
    $ui.UpgradeRaw.Visibility = 'Collapsed'
    $ui.UpgradeGrid.Visibility = 'Visible'
    Start-TrivorGuiJob -Kind 'upgradelist' -Payload @{ IncludeUnknown = [bool]$ui.UpgradeUnknown.IsChecked } -OnDone {
        param($sync)
        $ui = $script:Gui.Ui
        if ($sync.Error) { $ui.UpgradeStatus.Text = "Falha ao consultar o winget: $($sync.Error)"; return }
        $items = @(ConvertFrom-TrivorWingetTable -Text $sync.UpgradeText)
        $script:Gui.UpgradeRows = @($items | ForEach-Object {
            [pscustomobject]@{ Selected = [bool]$_.Selectable; Selectable = [bool]$_.Selectable; Name = $_.Name; Id = $_.Id; Version = $_.Version; Available = $_.Available }
        })
        if ($items.Count -gt 0) {
            $ui.UpgradeGrid.ItemsSource = $script:Gui.UpgradeRows
            $ui.UpgradeStatus.Text = "$($items.Count) atualizações disponíveis"
        }
        elseif ([string]::IsNullOrWhiteSpace($sync.UpgradeText) -or $sync.UpgradeText -notmatch '-{10,}') {
            $ui.UpgradeStatus.Text = 'Nenhuma atualização disponível'
            if (-not [string]::IsNullOrWhiteSpace($sync.UpgradeText)) { $ui.UpgradeRaw.Text = $sync.UpgradeText; $ui.UpgradeRaw.Visibility = 'Visible'; $ui.UpgradeGrid.Visibility = 'Collapsed' }
        }
        else {
            # Formato inesperado: mostra a saida original em vez de arriscar uma leitura errada
            $ui.UpgradeStatus.Text = 'Saída do winget em formato não reconhecido (exibida abaixo)'
            $ui.UpgradeRaw.Text = $sync.UpgradeText
            $ui.UpgradeRaw.Visibility = 'Visible'
            $ui.UpgradeGrid.Visibility = 'Collapsed'
        }
        Update-TrivorGuiUpgradeButton
    }
}

function Update-TrivorGuiUpgradeButton {
    $n = @($script:Gui.UpgradeRows | Where-Object { $_.Selected -and $_.Selectable }).Count
    $script:Gui.Ui.BtnUpgradeRun.Content = "Atualizar selecionados ($n)"
    if (-not $script:Gui.Busy) { $script:Gui.Ui.BtnUpgradeRun.IsEnabled = ($n -gt 0) }
}

#endregion

#region Logs e Sobre

function Update-TrivorGuiLogFiles {
    $ui = $script:Gui.Ui
    $dir = $global:TrivorLogDir
    $ui.LogsPath.Text = "$dir · retenção de $($global:TrivorLogRetentionDays) dias"
    $files = @(Get-ChildItem -LiteralPath $dir -File -Filter '*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    $ui.LogFilesList.ItemsSource = @($files | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Meta = "$($_.LastWriteTime.ToString('dd/MM HH:mm')) · $([Math]::Max(1, [int]($_.Length / 1KB))) KB"; Path = $_.FullName }
    })
    if ($files.Count) { $ui.LogFilesList.SelectedIndex = 0 }
}

function Update-TrivorGuiLogViewer {
    $ui = $script:Gui.Ui
    $item = $ui.LogFilesList.SelectedItem
    if (-not $item) { $ui.LogViewer.Text = ''; return }
    if ($script:Gui.LogViewerPath -ne $item.Path) {
        $fs = $null; $sr = $null
        try {
            $fs = [System.IO.File]::Open($item.Path, 'Open', 'Read', 'ReadWrite')
            $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
            $script:Gui.LogViewerLines = @($sr.ReadToEnd() -split "`r?`n")
            $script:Gui.LogViewerPath = $item.Path
        }
        finally { if ($sr) { $sr.Dispose() } elseif ($fs) { $fs.Dispose() } }
    }
    $level = if ($ui.LevelInfo.IsChecked) { 'INFO' } elseif ($ui.LevelWarn.IsChecked) { 'WARN' } elseif ($ui.LevelError.IsChecked) { 'ERROR' } else { 'Todos' }
    $ui.LogViewer.Text = (Select-TrivorLogLines -Lines $script:Gui.LogViewerLines -Level $level -Search $ui.LogSearch.Text) -join "`r`n"
}

function Update-TrivorGuiAbout {
    $ui = $script:Gui.Ui
    $ui.AboutVersion.Text = "Versão $($global:TrivorVersion) · canal $($global:TrivorBranch)"
    $kv = { param($k, $v) [pscustomobject]@{ K = $k; V = [string]$v } }
    $winget = Get-WingetExecutable
    $ui.AboutEnv.ItemsSource = @(
        (& $kv 'Contexto de execução' 'Administrador (interativo)'),
        (& $kv 'Usuário' ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)),
        (& $kv 'PowerShell' $PSVersionTable.PSVersion.ToString()),
        (& $kv 'Winget' $(if ($winget) { 'Disponível' } else { 'Não encontrado' })),
        (& $kv 'Máquina' $env:COMPUTERNAME)
    )
    $ui.AboutPaths.ItemsSource = @(
        (& $kv 'Raiz' $global:TrivorRoot),
        (& $kv 'Logs' "$($global:TrivorLogDir) ($($global:TrivorLogRetentionDays) dias)"),
        (& $kv 'Sessão atual' (Split-Path $global:TrivorBasePath -Leaf)),
        (& $kv 'Permissões' 'SYSTEM + Administradores')
    )
}

#endregion

function Start-TrivorGui {
    # Abre a janela principal. Retorna quando a janela fecha.
    $xml = [xml]$script:TrivorGuiXaml
    $window = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xml))

    $ui = @{ Window = $window }
    foreach ($node in $xml.SelectNodes("//*[@*[local-name()='Name' and namespace-uri()='http://schemas.microsoft.com/winfx/2006/xaml']]")) {
        $name = $node.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
        $ui[$name] = $window.FindName($name)
    }

    $script:Gui = @{
        Window = $window; Ui = $ui; Busy = $false; Job = $null; View = 'ViewClients'
        Clients = @(Get-ClientList); ClientName = $null; Config = $null; Rows = @(); ExpectedHostname = $null
        Run = $null; LogOffset = 0; UpgradeRows = @(); LogViewerPath = $null; LogViewerLines = @()
        Match = $null; Confirmed = @{}; Detect = $null
        Timer = New-Object System.Windows.Threading.DispatcherTimer
    }
    $script:Gui.Timer.Interval = [TimeSpan]::FromMilliseconds(400)
    $script:Gui.Timer.Add_Tick({
        # Sem caixa de mensagem aqui: o timer roda a cada 400 ms
        try { Update-TrivorGuiTick } catch { try { Write-Log "Erro na atualizacao da interface: $($_.Exception.Message)" "ERROR" } catch { Write-Verbose "Log indisponivel" } }
    })

    try {
        $window.Icon = ConvertFrom-TrivorBase64Image $script:TrivorGuiIconB64
        $logo = ConvertFrom-TrivorBase64Image $script:TrivorGuiLogoB64
        $ui.LogoImage.Source = $logo
        $ui.AboutLogo.Source = $logo
    } catch { Write-Log "Logo nao carregado na interface: $($_.Exception.Message)" "WARN" }

    $window.Title = "Trivor Installer $($global:TrivorVersion)"
    $ui.StatusContext.Text = 'Administrador (interativo)'
    $ui.StatusWinget.Text = if (Get-WingetExecutable) { 'Winget disponível' } else { 'Winget não encontrado' }
    $ui.StatusLog.Text = "Log: $($global:TrivorLogFile)"

    # Navegacao
    $ui.NavClients.Add_Click({ Invoke-TrivorGuiSafe { Show-TrivorGuiView 'ViewClients' } })
    $ui.NavUpgrade.Add_Click({ Invoke-TrivorGuiSafe { Show-TrivorGuiView 'ViewUpgrade'; if (-not $script:Gui.UpgradeRows.Count) { Start-TrivorGuiUpgradeList } } })
    $ui.NavLogs.Add_Click({ Invoke-TrivorGuiSafe { Show-TrivorGuiView 'ViewLogs'; Update-TrivorGuiLogFiles } })
    $ui.NavAbout.Add_Click({ Invoke-TrivorGuiSafe { Show-TrivorGuiView 'ViewAbout'; Update-TrivorGuiAbout } })

    # Clientes
    $ui.SearchBox.Add_TextChanged({ Invoke-TrivorGuiSafe { Update-TrivorGuiClientList } })
    $ui.ClientsList.AddHandler([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent, [System.Windows.RoutedEventHandler]{
        $e = $args[1]
        $name = [string]$e.OriginalSource.Tag
        if ($name) { Invoke-TrivorGuiSafe { Open-TrivorGuiClient -Name $name } }
    })
    $ui.BtnBack.Add_Click({ Invoke-TrivorGuiSafe { Show-TrivorGuiView 'ViewClients' } })
    $ui.BtnOpenDetected.Add_Click({ Invoke-TrivorGuiSafe { Open-TrivorGuiClient -Name ([string]$script:Gui.Ui.BtnOpenDetected.Tag) } })

    # Deteccao do cliente da maquina, em segundo plano, assim que a janela aparece
    $window.Add_ContentRendered({ Invoke-TrivorGuiSafe {
        Start-TrivorGuiJob -Kind 'index' -Payload @{ Names = @($script:Gui.Clients); ClientsPath = (Get-ClientsPath) } -OnDone {
            param($sync)
            $script:Gui.Match = $sync.Match
            $global:TrivorClientMatch = $sync.Match
            Update-TrivorGuiDetectedBanner
        }
    } })

    # Selecao de apps (o CheckBox atualiza o objeto da linha)
    $ui.AppsGrid.AddHandler([System.Windows.Controls.Primitives.ToggleButton]::ClickEvent, [System.Windows.RoutedEventHandler]{
        $e = $args[1]
        $row = $e.OriginalSource.DataContext
        if ($row -and $row.PSObject.Properties['Selected']) { $row.Selected = [bool]$e.OriginalSource.IsChecked; Update-TrivorGuiClientButtons }
    })
    $ui.UpgradeGrid.AddHandler([System.Windows.Controls.Primitives.ToggleButton]::ClickEvent, [System.Windows.RoutedEventHandler]{
        $e = $args[1]
        $row = $e.OriginalSource.DataContext
        if ($row -and $row.PSObject.Properties['Selected']) { $row.Selected = [bool]$e.OriginalSource.IsChecked; Update-TrivorGuiUpgradeButton }
    })

    # Acoes do cliente
    $ui.BtnPostFormat.Add_Click({ Invoke-TrivorGuiSafe {
        $cfg = $script:Gui.Config
        $mode = 'PostFormat'
        if ($script:Gui.Detect) {
            $a = Get-TrivorPostFormatAssessment -States $script:Gui.Detect
            if ($a.LooksConfigured) {
                $choice = Show-TrivorGuiChoice -Text ("Esta máquina não parece recém-formatada: $($a.Installed) de $($a.Total) aplicativos já estão instalados.`n`n" +
                    "A Pós-Formatação reinstala tudo sem verificar. O Compliance instala só o que falta e atualiza o resto.`n`n" +
                    "Sim = executar Compliance (recomendado)`nNão = executar Pós-Formatação mesmo assim`nCancelar = não executar nada")
                if ($choice -eq 'Cancel') { return }
                if ($choice -eq 'Yes') { $mode = 'Compliance'; Write-Log "Pos-Formatacao trocada por Compliance (maquina ja configurada)." "INFO" }
                else { Write-Log ("Pos-Formatacao mantida pelo analista em maquina com {0}/{1} apps instalados." -f $a.Installed, $a.Total) "WARN" }
            }
        }
        if (Confirm-TrivorGuiPlan -Mode $mode) { Start-TrivorGuiRun -Mode $mode -Steps (New-TrivorGuiSteps -Mode $mode -Config $cfg) }
    } })
    $ui.BtnCompliance.Add_Click({ Invoke-TrivorGuiSafe {
        if (Confirm-TrivorGuiPlan -Mode 'Compliance') { Start-TrivorGuiRun -Mode 'Compliance' -Steps (New-TrivorGuiSteps -Mode 'Compliance' -Config $script:Gui.Config) }
    } })
    $ui.BtnSelected.Add_Click({ Invoke-TrivorGuiSafe {
        $apps = @($script:Gui.Rows | Where-Object { $_.Selected } | ForEach-Object { $_.App })
        $text = "Confirmar a execução?`n`nCliente: $($script:Gui.ClientName)`nModo: Instalação dos selecionados (instala o que falta e atualiza o resto)`nAplicativos ($($apps.Count)): $(($apps | ForEach-Object { $_.Name }) -join ', ')`nHostname: mantido"
        if (Show-TrivorGuiMessage -Kind Question -YesNo -Text $text) {
            Start-TrivorGuiRun -Mode 'Selected' -Steps (New-TrivorGuiSteps -Mode 'Selected' -Config $script:Gui.Config -SelectedApps $apps)
        }
    } })
    $ui.BtnUpdate.Add_Click({ Invoke-TrivorGuiSafe { if (Confirm-TrivorGuiPlan -Mode 'Update') { Start-TrivorGuiRun -Mode 'Update' -Steps (New-TrivorGuiSteps -Mode 'Update' -Config $script:Gui.Config) } } })
    $ui.BtnHostname.Add_Click({ Invoke-TrivorGuiSafe {
        if (Confirm-TrivorGuiPlan -Mode 'Hostname') {
            Start-TrivorGuiRun -Mode 'Hostname' -Steps (New-TrivorGuiSteps -Mode 'Hostname' -Config $script:Gui.Config)
        }
    } })

    # Execucao e resumo
    $ui.BtnCancel.Add_Click({ Invoke-TrivorGuiSafe {
        if ($script:Gui.Job -and $script:Gui.Job.Sync) {
            $script:Gui.Job.Sync.CancelRequested = $true
            $ui = $script:Gui.Ui; $ui.BtnCancel.IsEnabled = $false; $ui.BtnCancel.Content = 'Cancelamento solicitado'
        }
    } })
    $ui.BtnSumBack.Add_Click({ Invoke-TrivorGuiSafe {
        $back = $script:Gui.Run.BackView
        if ($back -eq 'ViewUpgrade') { Show-TrivorGuiView 'ViewUpgrade'; Start-TrivorGuiUpgradeList }
        else { Open-TrivorGuiClient -Name $script:Gui.ClientName }
    } })
    $ui.BtnSumLog.Add_Click({ Invoke-TrivorGuiSafe { if ($global:TrivorLogFile) { Start-Process notepad.exe -ArgumentList "`"$($global:TrivorLogFile)`"" } } })
    $ui.BtnRebootLater.Add_Click({ Invoke-TrivorGuiSafe { $script:Gui.Ui.RebootBanner.Visibility = 'Collapsed' } })
    $ui.BtnRebootNow.Add_Click({ Invoke-TrivorGuiSafe {
        if (Show-TrivorGuiMessage -Kind Warn -YesNo -Text "A máquina será reiniciada ao fechar o Trivor Installer (depois da limpeza da sessão).`n`nFechar agora e reiniciar?") {
            $global:TrivorRebootOnExit = $true
            $script:Gui.Window.Close()
        }
    } })

    # Upgrade geral
    $ui.BtnUpgradeRefresh.Add_Click({ Invoke-TrivorGuiSafe { Start-TrivorGuiUpgradeList } })
    $ui.UpgradeUnknown.Add_Click({ Invoke-TrivorGuiSafe { Start-TrivorGuiUpgradeList } })
    $ui.BtnUpgradeRun.Add_Click({ Invoke-TrivorGuiSafe {
        $items = @($script:Gui.UpgradeRows | Where-Object { $_.Selected -and $_.Selectable })
        if ($items.Count -and (Show-TrivorGuiMessage -Kind Question -YesNo -Text "Atualizar $($items.Count) aplicativo(s) desta máquina via winget?")) {
            Start-TrivorGuiRun -Mode 'Upgrade' -Steps (New-TrivorGuiSteps -Mode 'Upgrade' -WingetItems $items) -BackView 'ViewUpgrade'
        }
    } })

    # Logs e Sobre
    $ui.LogFilesList.Add_SelectionChanged({ Invoke-TrivorGuiSafe { Update-TrivorGuiLogViewer } })
    foreach ($n in @('LevelAll', 'LevelInfo', 'LevelWarn', 'LevelError')) { $ui[$n].Add_Checked({ Invoke-TrivorGuiSafe { Update-TrivorGuiLogViewer } }) }
    $ui.LogSearch.Add_TextChanged({ Invoke-TrivorGuiSafe { Update-TrivorGuiLogViewer } })
    $ui.BtnOpenLogFolder.Add_Click({ Invoke-TrivorGuiSafe { Start-Process explorer.exe -ArgumentList "`"$($global:TrivorLogDir)`"" } })
    $ui.BtnChangelog.Add_Click({ Invoke-TrivorGuiSafe { Start-Process "https://github.com/$($global:TrivorOwner)/$($global:TrivorRepo)/blob/$($global:TrivorBranch)/CHANGELOG.md" } })
    $ui.BtnSite.Add_Click({ Invoke-TrivorGuiSafe { Start-Process 'https://trivor.com.br' } })

    # Nao fecha no meio de uma instalacao
    $window.Add_Closing({
        $e = $args[1]
        if ($script:Gui.Busy) {
            Show-TrivorGuiMessage -Kind Warn -Text 'Há uma execução em andamento. Aguarde terminar (ou use "Cancelar após o app atual") antes de fechar.' | Out-Null
            $e.Cancel = $true
        }
    })

    Update-TrivorGuiClientList
    Write-Log "Interface grafica aberta." "INFO"
    [void]$window.ShowDialog()
    Write-Log "Interface grafica fechada." "INFO"
}

#endregion
