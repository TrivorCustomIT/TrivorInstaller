# Trivor Installer - Debloat.ps1
# Remocao de apps do Windows (Appx/MSIX) desnecessarios em ambiente corporativo.
# Lista em Padrao/RemoverAppsWindows.json. NuncaRemover sempre tem prioridade sobre Remover.
# Pos-Formatacao remove todos os itens; Compliance so os marcados com "Compliance" em Modos.

$script:TrivorAppxList = $null

function Get-TrivorAppxRemovalList {
    # Baixa a lista para a pasta da sessao (uma vez) e devolve o objeto, ou $null em falha.
    if ($script:TrivorAppxList) { return $script:TrivorAppxList }

    $dir  = Join-Path $global:TrivorBasePath "padrao"
    $file = Join-Path $dir "RemoverAppsWindows.json"
    try {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        if (-not (Test-Path $file)) {
            $url = "https://raw.githubusercontent.com/$($global:TrivorOwner)/$($global:TrivorRepo)/$($global:TrivorBranch)/Padrao/RemoverAppsWindows.json"
            Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing -ErrorAction Stop
        }
        $list = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $list.Remover -or -not $list.NuncaRemover) { throw "lista sem Remover ou NuncaRemover" }
        $script:TrivorAppxList = $list
        return $list
    }
    catch {
        Write-Log "Falha ao carregar a lista de apps do Windows: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-TrivorAppxProtected {
    param([Parameter(Mandatory)] [string]$Name, $NeverRemove)
    foreach ($n in @($NeverRemove)) {
        if ($Name -like [string]$n.Id) { return $true }
    }
    return $false
}

function Invoke-TrivorAppxRemoval {
    # Remove o pacote provisionado (novos perfis) e o instalado para todos os usuarios.
    # Retorna Ok (sem falhas), Removed (itens removidos), Failed (itens com falha) e Names.
    param([Parameter(Mandatory)] [ValidateSet("PostFormat", "Compliance")] [string]$Mode)

    $result = [pscustomobject]@{ Ok = $false; Removed = 0; Failed = 0; Names = @() }

    if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
        Write-Log "Remocao de apps do Windows ignorada: cmdlets Appx indisponiveis neste sistema." "WARN"
        $result.Ok = $true
        return $result
    }

    $list = Get-TrivorAppxRemovalList
    if (-not $list) { $result.Failed = 1; return $result }

    $items = @($list.Remover | Where-Object { @($_.Modos) -contains $Mode })

    try { $installed = @(Get-AppxPackage -AllUsers -ErrorAction Stop) }
    catch {
        Write-Log "Falha ao listar apps do Windows: $($_.Exception.Message)" "ERROR"
        $result.Failed = 1
        return $result
    }
    $provisioned = @()
    try { $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop) }
    catch { Write-Log "Nao foi possivel listar apps provisionados: $($_.Exception.Message)" "WARN" }

    Write-Log ("Remocao de apps do Windows ({0}): {1} itens na lista" -f $Mode, $items.Count) "INFO"

    $names = New-Object System.Collections.ArrayList
    foreach ($item in $items) {
        $pattern = [string]$item.Id
        $provs = @($provisioned | Where-Object { $_.DisplayName -like $pattern })
        $pkgs  = @($installed | Where-Object { $_.Name -like $pattern } | Sort-Object PackageFullName -Unique)
        if ($provs.Count -eq 0 -and $pkgs.Count -eq 0) { continue }

        $acted = $false
        $itemOk = $true

        # Provisionado primeiro, para o app nao voltar em perfis novos durante a remocao
        foreach ($p in $provs) {
            if (Test-TrivorAppxProtected -Name $p.DisplayName -NeverRemove $list.NuncaRemover) {
                Write-Log "Protegido (NuncaRemover), mantido: $($p.DisplayName)" "WARN"
                continue
            }
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null
                Write-Log "App do Windows desprovisionado: $($item.Nome) [$($p.PackageName)]" "INFO"
                $acted = $true
            }
            catch {
                $itemOk = $false
                Write-Log "Falha ao desprovisionar app do Windows: $($item.Nome) [$($p.PackageName)] | $($_.Exception.Message)" "ERROR"
            }
        }

        foreach ($p in $pkgs) {
            if (Test-TrivorAppxProtected -Name $p.Name -NeverRemove $list.NuncaRemover) {
                Write-Log "Protegido (NuncaRemover), mantido: $($p.Name)" "WARN"
                continue
            }
            try {
                Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop
                Write-Log "App do Windows removido: $($item.Nome) [$($p.PackageFullName)]" "INFO"
                $acted = $true
            }
            catch {
                # Outra versao do mesmo app pode ter levado este pacote junto: confere antes de contar falha
                $still = @(Get-AppxPackage -AllUsers -Name $p.Name -ErrorAction SilentlyContinue | Where-Object { $_.PackageFullName -eq $p.PackageFullName })
                if ($still.Count -eq 0) {
                    Write-Log "App do Windows ja removido: $($item.Nome) [$($p.PackageFullName)]" "INFO"
                    $acted = $true
                }
                else {
                    $itemOk = $false
                    Write-Log "Falha ao remover app do Windows: $($item.Nome) [$($p.PackageFullName)] | $($_.Exception.Message)" "ERROR"
                }
            }
        }

        if (-not $itemOk) { $result.Failed++ }
        elseif ($acted) {
            $result.Removed++
            [void]$names.Add([string]$item.Nome)
        }
    }

    $result.Names = $names.ToArray()
    $result.Ok = ($result.Failed -eq 0)
    $level = if ($result.Ok) { "INFO" } else { "ERROR" }
    Write-Log ("Remocao de apps do Windows ({0}) finalizada: {1} removidos, {2} com falha" -f $Mode, $result.Removed, $result.Failed) $level
    return $result
}

function Invoke-TrivorAppxRemovalStep {
    # Etapa do console (Pos-Formatacao e Compliance); conta como uma etapa da sessao.
    param([Parameter(Mandatory)] [ValidateSet("PostFormat", "Compliance")] [string]$Mode)

    Write-Host ""
    Write-Host "Removendo apps do Windows desnecessarios..." -ForegroundColor Yellow
    $global:TrivorSessionTotal++
    $r = Invoke-TrivorAppxRemoval -Mode $Mode
    if (-not $r.Ok) { $global:TrivorSessionFailed++ }
    $color = if ($r.Ok) { "Green" } else { "Red" }
    Write-Host ("Apps do Windows: {0} removidos, {1} com falha." -f $r.Removed, $r.Failed) -ForegroundColor $color
}
