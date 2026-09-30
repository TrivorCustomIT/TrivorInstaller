$global:TrivorVersionCache    = $null
$global:TrivorVersionFallback = "v3.4.5"

function Select-LatestSemVerTag {
    # Retorna a maior tag no padrao maior.menor.bug (vX.Y.Z).
    # Tags legadas fora do padrao (ex: v3.41, v.3.4.2) sao ignoradas, pois a
    # API do GitHub nao ordena por versao e elas apareciam antes da mais recente.
    param([string[]]$TagNames)

    $valid = @(
        $TagNames |
        Where-Object { $_ -match '^v(\d+)\.(\d+)\.(\d+)$' } |
        Sort-Object -Property @{ Expression = { [version]($_.Substring(1)) } } -Descending
    )
    if ($valid.Count -gt 0) { return $valid[0] }
    return $null
}

function Get-InstallerVersion {
    if ($global:TrivorVersionCache) { return $global:TrivorVersionCache }
    try {
        $headers = @{ "User-Agent" = "TrivorInstaller" }
        $tags = Invoke-RestMethod -Uri "https://api.github.com/repos/TrivorCustomIT/TrivorInstaller/tags?per_page=100" -Headers $headers -ErrorAction Stop
        $latest = Select-LatestSemVerTag -TagNames @($tags | ForEach-Object { $_.name })
        if ($latest) {
            $global:TrivorVersionCache = $latest
            return $global:TrivorVersionCache
        }
    } catch {}
    $global:TrivorVersionCache = $global:TrivorVersionFallback
    return $global:TrivorVersionCache
}

function Show-Banner {

    Clear-Host
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

    $version = Get-InstallerVersion

    $ascii = @"
     _______ _____  _______      ______  _____  
    |__   __|  __ \|_   _\ \    / / __ \|  __ \ 
       | |  | |__) | | |  \ \  / / |  | | |__) |
       | |  |  _  /  | |   \ \/ /| |  | |  _  / 
       | |  | | \ \ _| |_   \  / | |__| | | \ \ 
       |_|  |_|  \_\_____|   \/   \____/|_|  \_\
"@

    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor DarkCyan
    Write-Host ("            TRIVOR INSTALLER {0,-27}                  " -f $version) -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host $ascii -ForegroundColor Cyan
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor DarkCyan
    Write-Host "        Developed by Fernando B. Oliveira              " -ForegroundColor Gray
    Write-Host "        GitHub: github.com/nandinhooliveira            " -ForegroundColor Gray
    Write-Host "=======================================================" -ForegroundColor DarkCyan
    Write-Host ""
}
