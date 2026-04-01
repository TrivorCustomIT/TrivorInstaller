# ==============================
# Trivor Installer - Hostname.ps1
# ==============================

function Get-ExpectedHostname {
    param([Parameter(Mandatory)] [string]$Prefix)

    try {
        $serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
        $serial = $serial.Trim()

        if (-not $serial -or $serial -eq "To be filled by O.E.M." -or $serial -eq "Default string") {
            Write-Log "Serial number invalido ou nao encontrado." "WARN"
            return $null
        }

        return "$Prefix-$serial".ToUpper()
    } catch {
        Write-Log "Erro ao obter serial number: $_" "ERROR"
        return $null
    }
}

function Invoke-HostnameCheck {
    param([Parameter(Mandatory)] [psobject]$ClientConfig)

    if ($ClientConfig.PSObject.Properties.Match("HostnamePrefix").Count -eq 0 -or -not $ClientConfig.HostnamePrefix) {
        Write-Log "HostnamePrefix nao definido para este cliente. Pulando rename." "INFO"
        return
    }

    $prefix   = $ClientConfig.HostnamePrefix.ToUpper()
    $expected = Get-ExpectedHostname -Prefix $prefix

    if (-not $expected) {
        Write-Host "[WARN] Nao foi possivel gerar o hostname esperado." -ForegroundColor Yellow
        return
    }

    $current = $env:COMPUTERNAME.ToUpper()

    Write-Host ""
    Write-Host "-----------------------------------"
    Write-Host "Hostname atual:   $current"
    Write-Host "Hostname esperado: $expected"
    Write-Host "-----------------------------------"

    if ($current -eq $expected) {
        Write-Host "[OK] Hostname ja esta correto." -ForegroundColor Green
        Write-Host ""
        return
    }

    Write-Host "[INFO] Hostname diferente do padrao. Renomeando..." -ForegroundColor Yellow

    try {
        Rename-Computer -NewName $expected -Force -ErrorAction Stop
        Write-Host ""
        Write-Host "===========================================" -ForegroundColor Cyan
        Write-Host " Hostname alterado para: $expected" -ForegroundColor Cyan
        Write-Host " E necessario reiniciar a maquina para" -ForegroundColor Yellow
        Write-Host " que a alteracao tenha efeito." -ForegroundColor Yellow
        Write-Host "===========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Log "Hostname renomeado: $current -> $expected" "INFO"
    } catch {
        Write-Host "[ERROR] Falha ao renomear: $_" -ForegroundColor Red
        Write-Log "Falha ao renomear hostname: $_" "ERROR"
    }
}
