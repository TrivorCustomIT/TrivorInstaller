$global:TrivorVersionCache = $null

function Get-InstallerVersion {
    if ($global:TrivorVersionCache) { return $global:TrivorVersionCache }
    try {
        $headers = @{ "User-Agent" = "TrivorInstaller" }
        $tags = Invoke-RestMethod -Uri "https://api.github.com/repos/TrivorCustomIT/TrivorInstaller/tags" -Headers $headers -ErrorAction Stop
        if ($tags -and $tags.Count -gt 0) {
            $global:TrivorVersionCache = $tags[0].name
            return $global:TrivorVersionCache
        }
    } catch {}
    $global:TrivorVersionCache = "v3.40"
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
