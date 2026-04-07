$global:TrivorLogDir = Join-Path $env:SystemDrive "TrivorInstaller\Logs"
$global:TrivorLogFile = $null
$global:TrivorTranscriptFile = $null

function Initialize-Logger {
    param(
        [string]$LogDir = $global:TrivorLogDir
    )

    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    $global:TrivorLogFile = Join-Path $LogDir "TrivorInstaller_$timestamp.log"
    $global:TrivorTranscriptFile = Join-Path $LogDir "Transcript_$timestamp.log"

    if (-not (Test-Path $global:TrivorLogFile)) {
        New-Item -ItemType File -Path $global:TrivorLogFile -Force | Out-Null
    }

    Write-Host "[{0}] [INFO] Logger inicializado. Arquivo: {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $global:TrivorLogFile
    Write-Log "Logger inicializado. Arquivo: $global:TrivorLogFile" "INFO"
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")][string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"

    Write-Host $line

    if ([string]::IsNullOrWhiteSpace($global:TrivorLogFile)) {
        return
    }

    $maxRetries = 8
    $retryDelayMs = 200

    for ($i = 1; $i -le $maxRetries; $i++) {
        $fs = $null
        $sw = $null

        try {
            $fs = [System.IO.File]::Open(
                $global:TrivorLogFile,
                [System.IO.FileMode]::Append,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite
            )

            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            $sw = New-Object System.IO.StreamWriter($fs, $utf8NoBom)
            $sw.WriteLine($line)
            $sw.Flush()

            return
        }
        catch {
            if ($i -eq $maxRetries) {
                Write-Host "[LOGGER-FAIL] $line"
                Write-Host "[LOGGER-FAIL] $($_.Exception.Message)"
                return
            }

            Start-Sleep -Milliseconds $retryDelayMs
        }
        finally {
            if ($sw) { $sw.Dispose() }
            if ($fs) { $fs.Dispose() }
        }
    }
}

function Start-TrivorTranscript {
    try {
        if (-not [string]::IsNullOrWhiteSpace($global:TrivorTranscriptFile)) {
            Start-Transcript -Path $global:TrivorTranscriptFile -Append -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Transcript iniciado: $global:TrivorTranscriptFile" "INFO"
        }
    }
    catch {
        Write-Log "Falha ao iniciar transcript: $($_.Exception.Message)" "WARN"
    }
}

function Stop-TrivorTranscript {
    try {
        Stop-Transcript | Out-Null
    }
    catch {
    }
}