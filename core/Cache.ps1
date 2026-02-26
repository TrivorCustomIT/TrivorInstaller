function Initialize-Cache {
    $global:CachePath = Join-Path $env:TEMP "TrivorInstaller\cache"

    if (-not (Test-Path $CachePath)) {
        New-Item -ItemType Directory -Path $CachePath -Force | Out-Null
    }

    Write-Log "Cache criado em $CachePath"
}
