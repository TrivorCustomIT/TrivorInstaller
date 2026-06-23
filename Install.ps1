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
    $global:TrivorExitCode      = 0
    $global:TrivorSessionTotal  = 0
    $global:TrivorSessionFailed = 0

    $BasePath    = $global:TrivorBasePath
    $CorePath    = Join-Path $BasePath "core"
    $ClientsPath = Join-Path $BasePath "Clientes"

    New-Item -ItemType Directory -Force -Path $CorePath    | Out-Null
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
            $global:TrivorExitCode = 1
            exit 1
        }
    }

    $global:TrivorOwner  = $Owner
    $global:TrivorRepo   = $Repo
    $global:TrivorBranch = $Branch

    $Headers = @{
        "User-Agent" = "TrivorInstaller"
        "Accept"     = "application/vnd.github+json"
    }

    $ClientsApi = "https://api.github.com/repos/$Owner/$Repo/contents/Clientes?ref=$Branch"

    try {
        $items = Invoke-RestMethod -Uri $ClientsApi -Headers $Headers -ErrorAction Stop
        $global:TrivorClientNames = @(
            $items |
            Where-Object { $_.type -eq "file" -and $_.name -like "*.json" -and $_.name -ne "_manifest.json" } |
            ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.name) } |
            Sort-Object
        )
    }
    catch {
        Write-Host "ERROR: Failed to fetch client list from GitHub API."
        $global:TrivorExitCode = 1
        exit 1
    }

    if ($global:TrivorClientNames.Count -eq 0) {
        Write-Host "ERROR: No client JSON files found in 'Clientes' folder."
        $global:TrivorExitCode = 1
        exit 1
    }

    . "$CorePath\Logger.ps1"
    . "$CorePath\Cache.ps1"
    . "$CorePath\Banner.ps1"
    . "$CorePath\Detection.ps1"
    . "$CorePath\Engine.ps1"
    . "$CorePath\Hostname.ps1"
    . "$CorePath\Menu.ps1"

    $global:TrivorVersion = Get-InstallerVersion

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
    if ($global:TrivorExitCode -eq 0) { $global:TrivorExitCode = 1 }
    throw
}
finally {
    if ($global:TrivorExitCode -eq 0 -and $global:TrivorSessionFailed -gt 0) {
        $global:TrivorExitCode = 2
    }

    if ($global:TrivorSessionTotal -gt 0) {
        $successCount = $global:TrivorSessionTotal - $global:TrivorSessionFailed
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log ("Sessao encerrada: {0} ok / {1} falhas / {2} total" -f $successCount, $global:TrivorSessionFailed, $global:TrivorSessionTotal) "INFO"
        }
        Write-Host ""
        Write-Host ("Sessao: {0} instalados com sucesso, {1} falhas." -f $successCount, $global:TrivorSessionFailed) -ForegroundColor $(if ($global:TrivorSessionFailed -gt 0) { "Yellow" } else { "Green" })
    }

    if (-not [string]::IsNullOrWhiteSpace($global:TrivorLogFile)) {
        Write-Host ""
        Write-Host "Log da sessao salvo em:" -ForegroundColor DarkGray
        Write-Host "  $global:TrivorLogFile" -ForegroundColor Gray
        if (-not [string]::IsNullOrWhiteSpace($global:TrivorTranscriptFile)) {
            Write-Host "  $global:TrivorTranscriptFile" -ForegroundColor Gray
        }
    }

    if (Get-Command Stop-TrivorTranscript -ErrorAction SilentlyContinue) {
        Stop-TrivorTranscript
    }

    Invoke-Cleanup
    exit $global:TrivorExitCode
}
