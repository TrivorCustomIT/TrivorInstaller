Write-Host "Trivor Installer iniciado"

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$BasePath    = Join-Path $env:TEMP "TrivorInstaller"
$CorePath    = Join-Path $BasePath "core"
$ClientsPath = Join-Path $BasePath "Clientes"

New-Item -ItemType Directory -Force -Path $CorePath    | Out-Null
New-Item -ItemType Directory -Force -Path $ClientsPath | Out-Null

$Owner  = "TrivorCustomIT"
$Repo   = "TrivorInstaller"
$Branch = "main"

$CoreBaseRaw = "https://raw.githubusercontent.com/$Owner/$Repo/$Branch/core"

# --- Download core modules ---
$Modules = @(
    "Logger.ps1",
    "Cache.ps1",
    "Banner.ps1",
    "Detection.ps1",
    "Engine.ps1",
    "Menu.ps1"
)

foreach ($Module in $Modules) {
    $Url  = "$CoreBaseRaw/$Module"
    $Dest = Join-Path $CorePath $Module
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Host "ERROR: Failed to download module '$Module'. Check your connection or repo."
        exit 1
    }
}

# --- Download client JSONs via GitHub API ---
$Headers = @{
    "User-Agent" = "TrivorInstaller"
    "Accept"     = "application/vnd.github+json"
}

$ClientsApi = "https://api.github.com/repos/$Owner/$Repo/contents/Clientes?ref=$Branch"
$downloadedAny = $false

try {
    $items = Invoke-RestMethod -Uri $ClientsApi -Headers $Headers -ErrorAction Stop
    foreach ($it in $items) {
        if ($it.type -eq "file" -and $it.name -like "*.json") {
            $dest = Join-Path $ClientsPath $it.name
            Invoke-WebRequest -Uri $it.download_url -OutFile $dest -UseBasicParsing
            $downloadedAny = $true
        }
    }
} catch {
    Write-Host "ERROR: Failed to download client list from GitHub API."
    Write-Host "Check if the 'Clientes' folder exists in the repo and the API is accessible."
    exit 1
}

if (-not $downloadedAny) {
    Write-Host "ERROR: No client JSON files found in 'Clientes' folder."
    exit 1
}

# --- Load modules ---
. "$CorePath\Logger.ps1"
. "$CorePath\Cache.ps1"
. "$CorePath\Banner.ps1"
. "$CorePath\Detection.ps1"
. "$CorePath\Engine.ps1"
. "$CorePath\Menu.ps1"

Initialize-Logger
Initialize-Cache
Show-Banner
Start-MainMenu
