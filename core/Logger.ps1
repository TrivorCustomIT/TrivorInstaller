$global:TrivorLogFile = $null
$global:TrivorLogDir  = Join-Path $env:SystemDrive "TrivorInstaller\Logs"

function Initialize-Logger {
    param(
        [string]$LogDir = $global:TrivorLogDir
    )

    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $global:TrivorLogFile = Join-Path $LogDir "TrivorInstaller_$timestamp.log"

    if (-not (Test-Path $global:TrivorLogFile)) {
        New-Item -ItemType File -Path $global:TrivorLogFile -Force | Out-Null
    }

    Write-Host "Log file: $global:TrivorLogFile"
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

    $maxRetries = 6
    $retryDelayMs = 250

    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            $fs = [System.IO.File]::Open(
                $global:TrivorLogFile,
                [System.IO.FileMode]::Append,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite
            )

            try {
                $sw = New-Object System.IO.StreamWriter($fs, [System.Text.UTF8Encoding]::new($false))
                $sw.WriteLine($line)
                $sw.Flush()
            }
            finally {
                if ($sw) { $sw.Dispose() }
                if ($fs) { $fs.Dispose() }
            }

            break
        }
        catch {
            if ($i -eq $maxRetries) {
                Write-Host "[LOGGER-FAIL] $line"
                Write-Host "[LOGGER-FAIL] $($_.Exception.Message)"
            }
            else {
                Start-Sleep -Milliseconds $retryDelayMs
            }
        }
    }
}