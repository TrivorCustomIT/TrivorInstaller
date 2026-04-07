function Initialize-Logger {
    param(
        [string]$BasePath = (Join-Path $env:SystemDrive "TrivorInstaller"),
        [string]$LogPrefix = "TrivorInstaller"
    )

    $global:TrivorPersistRoot = $BasePath
    $global:TrivorLogPath     = Join-Path $BasePath "Logs"
    $global:TrivorRunId       = Get-Date -Format "yyyyMMdd_HHmmss"
    $global:TrivorLogFile     = Join-Path $global:TrivorLogPath ("{0}_{1}.log" -f $LogPrefix, $global:TrivorRunId)

    New-Item -ItemType Directory -Path $global:TrivorLogPath -Force | Out-Null

    try {
        Start-Transcript -Path $global:TrivorLogFile -Append -Force | Out-Null
    } catch {
        Write-Host "[WARN] Nao foi possivel iniciar transcript: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Log "Logger inicializado. Arquivo: $global:TrivorLogFile" "INFO"
}

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")] [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message

    switch ($Level) {
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "DEBUG" { Write-Host $line -ForegroundColor DarkGray }
        default { Write-Host $line }
    }

    if ($global:TrivorLogFile) {
        try {
            Add-Content -Path $global:TrivorLogFile -Value $line -Encoding UTF8
        } catch {
            Write-Host "[WARN] Falha ao gravar log em arquivo: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Stop-Logger {
    try {
        Stop-Transcript | Out-Null
    } catch {}
}
