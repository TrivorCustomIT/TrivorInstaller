function Initialize-Logger {
    Write-Host "Logger inicializado"
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    Write-Host "[$Level] $Message"
}
