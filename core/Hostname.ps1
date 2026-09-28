# ==============================
# Trivor Installer - Hostname.ps1
# ==============================

$global:TrivorHostnameMaxLength = 15   # limite NetBIOS

function ConvertTo-TrivorHostname {
    # Monta PREFIXO-SERIAL respeitando as regras de nome NetBIOS:
    # maximo 15 caracteres, apenas letras, numeros e hifen.
    # Se o serial for longo demais, mantem os ultimos caracteres (parte mais unica).
    param(
        [Parameter(Mandatory)] [string]$Prefix,
        [AllowEmptyString()] [string]$Serial
    )

    $invalidSerials = @("To be filled by O.E.M.", "Default string", "System Serial Number", "Not Specified", "None", "0")

    $raw = if ($Serial) { $Serial.Trim() } else { "" }
    if (-not $raw -or $invalidSerials -contains $raw) {
        Write-Log "Serial number invalido ou nao encontrado: '$raw'" "WARN"
        return $null
    }

    $cleanPrefix = ($Prefix -replace '[^A-Za-z0-9-]', '').Trim('-').ToUpper()
    $cleanSerial = ($raw -replace '[^A-Za-z0-9-]', '').Trim('-').ToUpper()

    if (-not $cleanPrefix -or -not $cleanSerial) {
        Write-Log "Prefixo ou serial vazio apos sanitizacao. Prefix='$Prefix' Serial='$raw'" "WARN"
        return $null
    }

    $maxSerial = $global:TrivorHostnameMaxLength - $cleanPrefix.Length - 1
    if ($maxSerial -lt 1) {
        Write-Log "HostnamePrefix '$cleanPrefix' muito longo para o limite de $($global:TrivorHostnameMaxLength) caracteres." "WARN"
        return $null
    }

    if ($cleanSerial.Length -gt $maxSerial) {
        $truncated = $cleanSerial.Substring($cleanSerial.Length - $maxSerial).TrimStart('-')
        Write-Log "Serial '$cleanSerial' excede o limite. Usando os ultimos $maxSerial caracteres: $truncated" "WARN"
        $cleanSerial = $truncated
    }

    return "$cleanPrefix-$cleanSerial"
}

function Get-ExpectedHostname {
    param([Parameter(Mandatory)] [string]$Prefix)

    try {
        $serial = [string](Get-CimInstance -ClassName Win32_BIOS).SerialNumber
        return (ConvertTo-TrivorHostname -Prefix $Prefix -Serial $serial)
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
