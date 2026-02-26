# ==============================
# Trivor Installer - Engine.ps1
# Supports: AUTO, MANUAL
# Install methods: Winget, RepoExePublic (raw) with SHA256 validation and retry
# Reinstall rule: if Registry version < MinVersion -> reinstall
# ==============================

#region Download - Public Repo (raw)
function Get-PublicRepoFile {
    param(
        [Parameter(Mandatory)] [string]$Owner,
        [Parameter(Mandatory)] [string]$Repo,
        [Parameter(Mandatory)] [string]$Branch,
        [Parameter(Mandatory)] [string]$RelativePath,
        [Parameter(Mandatory)] [string]$DestinationFile
    )

    $url = "https://raw.githubusercontent.com/$Owner/$Repo/$Branch/$RelativePath"
    Write-Log "Downloading: $url" "INFO"

    try {
        Invoke-WebRequest -Uri $url -OutFile $DestinationFile -UseBasicParsing
        return $true
    } catch {
        Write-Log "Download failed: $RelativePath" "ERROR"
        return $false
    }
}
#endregion

#region SHA256 helpers
function Get-FileSha256 {
    param([Parameter(Mandatory)] [string]$Path)

    try {
        return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToUpper()
    } catch {
        return $null
    }
}

function Ensure-DownloadedWithSha256 {
    param(
        [Parameter(Mandatory)] [string]$Owner,
        [Parameter(Mandatory)] [string]$Repo,
        [Parameter(Mandatory)] [string]$Branch,
        [Parameter(Mandatory)] [string]$RelativePath,
        [Parameter(Mandatory)] [string]$DestinationFile,
        [Parameter(Mandatory)] [string]$ExpectedSha256,
        [int]$MaxAttempts = 2
    )

    $expected = $ExpectedSha256.ToUpper()

    for ($i = 1; $i -le $MaxAttempts; $i++) {

        if (Test-Path $DestinationFile) {
            $current = Get-FileSha256 -Path $DestinationFile
            if ($current -and $current -eq $expected) {
                Write-Log "SHA256 OK (cached): $DestinationFile" "INFO"
                return $true
            }
            Write-Log "SHA256 mismatch (attempt ${i}). Deleting cached file." "WARN"
            try { Remove-Item $DestinationFile -Force -ErrorAction SilentlyContinue } catch {}
        }

        Write-Log "Downloading attempt ${i}: $RelativePath" "INFO"

        $ok = Get-PublicRepoFile `
            -Owner $Owner -Repo $Repo -Branch $Branch `
            -RelativePath $RelativePath -DestinationFile $DestinationFile

        if (-not $ok) { continue }

        $hash = Get-FileSha256 -Path $DestinationFile
        if ($hash -and $hash -eq $expected) {
            Write-Log "SHA256 OK: $DestinationFile" "INFO"
            return $true
        }

        Write-Log "SHA256 mismatch after download (attempt ${i})." "ERROR"
        try { Remove-Item $DestinationFile -Force -ErrorAction SilentlyContinue } catch {}
    }

    Write-Log "Failed SHA256 validation after $MaxAttempts attempts." "ERROR"
    return $false
}
#endregion

#region Winget
function Initialize-Winget {
    Write-Log "Initializing winget..." "INFO"
    try { winget source update --accept-source-agreements 2>$null | Out-Null } catch {}
    try { winget list --accept-source-agreements 2>$null | Out-Null } catch {}
    Write-Log "Winget ready." "INFO"
}

function Install-WingetApp {
    param([Parameter(Mandatory)] [string]$WingetId)

    Write-Log "Installing via Winget: $WingetId" "INFO"
    try {
        winget install --id $WingetId --exact --silent --accept-package-agreements --accept-source-agreements
        return $true
    } catch {
        Write-Log "Winget install failed: $WingetId" "ERROR"
        return $false
    }
}

function Update-WingetApp {
    param([Parameter(Mandatory)] [string]$WingetId)

    Write-Log "Updating via Winget: $WingetId" "INFO"
    try {
        winget upgrade --id $WingetId --exact --silent --accept-package-agreements --accept-source-agreements
        return $true
    } catch {
        Write-Log "Winget upgrade failed: $WingetId" "WARN"
        return $false
    }
}

function Upgrade-WingetAll {
    Write-Log "Running: winget upgrade --all" "INFO"
    try {
        winget upgrade --all --silent --accept-package-agreements --accept-source-agreements
        return $true
    } catch {
        Write-Log "winget upgrade --all failed" "WARN"
        return $false
    }
}
#endregion

#region Install router
function Install-Application {
    param([Parameter(Mandatory)] $App)

    # 1) Winget
    if ($App.PSObject.Properties.Match("WingetId").Count -gt 0 -and $App.WingetId) {
        Install-WingetApp -WingetId $App.WingetId | Out-Null
        return
    }

    # 2) Public repo EXE
    if ($App.PSObject.Properties.Match("Install").Count -gt 0 -and $App.Install -and $App.Install.Method -eq "RepoExePublic") {

        $cacheRoot = Join-Path $env:TEMP "TrivorInstaller\cache"
        New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null

        $cacheFileName = if ($App.Install.CacheFileName) { $App.Install.CacheFileName } else { [System.IO.Path]::GetFileName($App.Install.RelativePath) }
        $localFile = Join-Path $cacheRoot $cacheFileName

        $needsHash = ($App.Install.PSObject.Properties.Match("Sha256").Count -gt 0 -and $App.Install.Sha256)

        if ($needsHash) {
            $ok = Ensure-DownloadedWithSha256 `
                -Owner $App.Install.Owner -Repo $App.Install.Repo -Branch $App.Install.Branch `
                -RelativePath $App.Install.RelativePath -DestinationFile $localFile `
                -ExpectedSha256 $App.Install.Sha256 -MaxAttempts 2
        } else {
            $ok = Get-PublicRepoFile `
                -Owner $App.Install.Owner -Repo $App.Install.Repo -Branch $App.Install.Branch `
                -RelativePath $App.Install.RelativePath -DestinationFile $localFile
        }

        if (-not $ok) { return }

        Write-Log "Executing installer: $localFile" "INFO"

        $installArgs = if ($App.Install.SilentArgs) { $App.Install.SilentArgs } else { "" }
        Start-Process -FilePath $localFile -ArgumentList $installArgs -Wait -NoNewWindow

        if ($App.Install.CleanAfterInstall -eq $true) {
            try { Remove-Item $localFile -Force -ErrorAction SilentlyContinue } catch {}
            Write-Log "Cache cleaned: $localFile" "INFO"
        }

        return
    }

    Write-Log "No valid installation method for $($App.Name)" "ERROR"
}
#endregion

#region Actions
function Should-ForceReinstallByVersion {
    param(
        [Parameter(Mandatory)] $App,
        [Parameter(Mandatory)] $State
    )

    if (-not $App.Detection) { return $false }
    if (-not $App.Detection.MinVersion) { return $false }
    if (-not $State.Version) { return $false }

    try {
        if ([version]$State.Version -lt [version]$App.Detection.MinVersion) {
            Write-Log ("Version below required. Installed={0} Required={1}. Will reinstall." -f $State.Version, $App.Detection.MinVersion) "WARN"
            return $true
        }
    } catch {
        Write-Log "Version compare failed. Skipping forced reinstall." "WARN"
    }

    return $false
}

function Invoke-AppAction {
    param(
        [Parameter(Mandatory)] $App,
        [Parameter(Mandatory)] [ValidateSet("Auto","Manual")] [string]$Mode
    )

    $state     = Get-ApplicationState -App $App
    $installed = [bool]$state.Installed
    $hasWinget = ($App.PSObject.Properties.Match("WingetId").Count -gt 0 -and $App.WingetId)

    # Force reinstall if version is below minimum required
    if ($installed -and (Should-ForceReinstallByVersion -App $App -State $state)) {
        $installed = $false
    }

    if ($installed) {
        Write-Log "$($App.Name) already installed. Checking for updates..." "INFO"

        if ($hasWinget) {
            if ($Mode -eq "Manual") {
                $choice = Read-Host "Update $($App.Name) via Winget? (Y/N)"
                if ($choice -match "^(Y|y)$") {
                    Update-WingetApp -WingetId $App.WingetId | Out-Null
                } else {
                    Write-Log "Skipped update: $($App.Name)" "INFO"
                }
            } else {
                Update-WingetApp -WingetId $App.WingetId | Out-Null
            }
        } else {
            Write-Log "No WingetId for update: $($App.Name)" "INFO"
        }

        return
    }

    # Not installed -> install
    Write-Log "$($App.Name) not installed." "INFO"

    if ($Mode -eq "Manual") {
        $choice = Read-Host "Install $($App.Name)? (Y/N)"
        if ($choice -match "^(Y|y)$") {
            Install-Application -App $App
        } else {
            Write-Log "Skipped install: $($App.Name)" "INFO"
        }
    } else {
        Install-Application -App $App
    }
}

function Invoke-AppActionManual {
    param([Parameter(Mandatory)] $App)

    $state     = Get-ApplicationState -App $App
    $installed = [bool]$state.Installed
    $hasWinget = ($App.PSObject.Properties.Match("WingetId").Count -gt 0 -and $App.WingetId)

    Write-Host ""
    Write-Host "-----------------------------------"
    Write-Host "App: $($App.Name)"
    Write-Host ("Installed: {0}" -f $installed)
    if ($state.Source)  { Write-Host ("Source: {0}"  -f $state.Source) }
    if ($state.Version) { Write-Host ("Version: {0}" -f $state.Version) }
    Write-Host "-----------------------------------"

    if ($installed) {
        if ($hasWinget) { Write-Host "[U] Update via Winget" }
        Write-Host "[S] Skip"
        Write-Host "[Q] Quit manual mode"
        $choice = Read-Host "Choose"

        if ($choice -match "^(U|u)$" -and $hasWinget) {
            Update-WingetApp -WingetId $App.WingetId | Out-Null
            return "CONTINUE"
        }
        if ($choice -match "^(Q|q)$") { return "QUIT" }

        Write-Log "Skipped: $($App.Name)" "INFO"
        return "CONTINUE"
    }

    Write-Host "[I] Install"
    Write-Host "[S] Skip"
    Write-Host "[Q] Quit manual mode"
    $choice = Read-Host "Choose"

    if ($choice -match "^(I|i)$") {
        Install-Application -App $App
        return "CONTINUE"
    }
    if ($choice -match "^(Q|q)$") { return "QUIT" }

    Write-Log "Skipped: $($App.Name)" "INFO"
    return "CONTINUE"
}
#endregion

#region Entry points
function Invoke-ClientInstallation {
    param([Parameter(Mandatory)] [psobject]$ClientConfig)

    Initialize-Winget
    Write-Log "Starting AUTO mode for client: $($ClientConfig.Client)" "INFO"

    foreach ($app in $ClientConfig.Applications) {
        Write-Log "Processing: $($app.Name)" "INFO"
        Invoke-AppAction -App $app -Mode "Auto"
    }

    Write-Log "Finished AUTO mode for client: $($ClientConfig.Client)" "INFO"
}

function Invoke-ClientUpdateOnly {
    param([Parameter(Mandatory)] [psobject]$ClientConfig)

    Initialize-Winget
    Write-Log "Starting UPDATE ONLY mode for client: $($ClientConfig.Client)" "INFO"

    foreach ($app in $ClientConfig.Applications) {
        if ($app.PSObject.Properties.Match("WingetId").Count -gt 0 -and $app.WingetId) {
            Update-WingetApp -WingetId $app.WingetId | Out-Null
        } else {
            Write-Log "No WingetId for update: $($app.Name)" "INFO"
        }
    }

    Write-Log "Finished UPDATE ONLY mode for client: $($ClientConfig.Client)" "INFO"
}

function Invoke-ClientComplianceInstall {
    param([Parameter(Mandatory)] [psobject]$ClientConfig)

    Initialize-Winget
    Write-Log "Starting COMPLIANCE mode for client: $($ClientConfig.Client)" "INFO"

    foreach ($app in $ClientConfig.Applications) {
        Write-Log "Processing: $($app.Name)" "INFO"
        Invoke-AppAction -App $app -Mode "Auto"
    }

    Upgrade-WingetAll | Out-Null

    Write-Log "Finished COMPLIANCE mode for client: $($ClientConfig.Client)" "INFO"
}

function Invoke-ClientManualInstall {
    param([Parameter(Mandatory)] [psobject]$ClientConfig)

    Initialize-Winget
    Write-Log "Starting MANUAL mode for client: $($ClientConfig.Client)" "INFO"

    foreach ($app in $ClientConfig.Applications) {
        $r = Invoke-AppActionManual -App $app
        if ($r -eq "QUIT") {
            Write-Log "Manual mode aborted by user." "INFO"
            return
        }
    }

    Write-Log "Finished MANUAL mode for client: $($ClientConfig.Client)" "INFO"
}
#endregion
