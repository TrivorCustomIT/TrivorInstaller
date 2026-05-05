Write-Host "Trivor Installer iniciado"

# --- Auto-elevacao compativel com irm | iex ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # Detecta contexto SYSTEM/RMM: nao tenta elevar via UAC pois nao ha desktop interativo
    # e o processo ja possui privilegios suficientes (ou deve ser tratado como tal)
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $isSystemContext = $false

    if ($currentIdentity -eq "NT AUTHORITY\SYSTEM") { $isSystemContext = $true }
    if ($currentIdentity -match '^NT (AUTHORITY\\(LOCAL SERVICE|NETWORK SERVICE)|SERVICE\\)') { $isSystemContext = $true }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { $isSystemContext = $true }
    if ($env:LOCALAPPDATA -match '\\(systemprofile|LocalService|NetworkService)\\') { $isSystemContext = $true }
    foreach ($sig in @($env:NABLE_AGENT_HOME, $env:SOLARWINDS_AGENT, $env:NAAGENT_HOME, $env:DATTO_AGENT, $env:NINJAONE_AGENT, $env:ATERA_AGENT)) {
        if (-not [string]::IsNullOrWhiteSpace($sig)) { $isSystemContext = $true }
    }

    if ($isSystemContext) {
        Write-Host "Contexto SYSTEM/RMM detectado. Continuando sem elevacao via UAC..."
        # Segue execucao normalmente - Engine.ps1 tratara Winget via usuario logado
    } else {
        Write-Host "Elevando privilegios..."
        $tempScript = Join-Path $env:TEMP "TrivorLauncher.ps1"
        $url = "https://raw.githubusercontent.com/TrivorCustomIT/TrivorInstaller/main/Install.ps1"
        Invoke-WebRequest -Uri $url -OutFile $tempScript -UseBasicParsing
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`"" -Verb RunAs
        exit
    }
}

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$global:TrivorVersion  = "3.35-manual-status"
$global:TrivorBasePath = Join-Path $env:TEMP "TrivorInstaller"

function Invoke-Cleanup {
    try {
        if (Test-Path $global:TrivorBasePath) {
            Remove-Item $global:TrivorBasePath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {}
}

Invoke-Cleanup

try {
    $BasePath    = $global:TrivorBasePath
    $CorePath    = Join-Path $BasePath "core"
    $ClientsPath = Join-Path $BasePath "Clientes"

    New-Item -ItemType Directory -Force -Path $CorePath | Out-Null
    New-Item -ItemType Directory -Force -Path $ClientsPath | Out-Null

    $Owner  = "TrivorCustomIT"
    $Repo   = "TrivorInstaller"
    $Branch = "main"

    $CoreBaseRaw = "https://raw.githubusercontent.com/$Owner/$Repo/$Branch/core"

    $Modules = @(
        "Logger.ps1",
        "Cache.ps1",
        "Banner.ps1",
        "Detection.ps1",
        "Engine.ps1",
        "Hostname.ps1",
        "Menu.ps1"
    )

    foreach ($Module in $Modules) {
        $Url  = "$CoreBaseRaw/$Module"
        $Dest = Join-Path $CorePath $Module
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -ErrorAction Stop
        }
        catch {
            Write-Host "ERROR: Failed to download module '$Module'."
            exit 1
        }
    }

    $Headers = @{
        "User-Agent" = "TrivorInstaller"
        "Accept"     = "application/vnd.github+json"
    }

    $ClientsApi = "https://api.github.com/repos/$Owner/$Repo/contents/Clientes?ref=$Branch"
    $downloadedAny = $false

    try {
        $items = Invoke-RestMethod -Uri $ClientsApi -Headers $Headers -ErrorAction Stop
        foreach ($it in $items) {
            if ($it.type -eq "file" -and $it.name -like "*.json" -and $it.name -ne "_manifest.json") {
                $dest = Join-Path $ClientsPath $it.name
                Invoke-WebRequest -Uri $it.download_url -OutFile $dest -UseBasicParsing
                $downloadedAny = $true
            }
        }
    }
    catch {
        Write-Host "ERROR: Failed to download client list from GitHub API."
        exit 1
    }

    if (-not $downloadedAny) {
        Write-Host "ERROR: No client JSON files found in 'Clientes' folder."
        exit 1
    }

    . "$CorePath\Logger.ps1"
    . "$CorePath\Cache.ps1"
    . "$CorePath\Banner.ps1"
    . "$CorePath\Detection.ps1"
    . "$CorePath\Engine.ps1"
    . "$CorePath\Hostname.ps1"
    . "$CorePath\Menu.ps1"

    Initialize-Logger
    Start-TrivorTranscript
    Write-Log "==== TrivorInstaller v$global:TrivorVersion ====" "INFO"

    Initialize-Cache
    Show-Banner
    Start-MainMenu
}
catch {
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log "Falha fatal no bootstrap: $($_.Exception.Message)" "ERROR"
    }
    else {
        Write-Host "Falha fatal no bootstrap: $($_.Exception.Message)"
    }
    throw
}
finally {
    if (Get-Command Stop-TrivorTranscript -ErrorAction SilentlyContinue) {
        Stop-TrivorTranscript
    }

    Invoke-Cleanup
}