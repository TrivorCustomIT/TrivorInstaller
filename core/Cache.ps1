function Initialize-Cache {
    # Fonte canonica do caminho de cache para toda a sessao.
    # Engine.ps1 e outros modulos devem referenciar $global:CachePath.
    $global:CachePath = Join-Path $env:TEMP "TrivorInstaller\cache"
    if (-not (Test-Path $global:CachePath)) {
        New-Item -ItemType Directory -Path $global:CachePath -Force | Out-Null
    }
    Write-Log "Cache path: $global:CachePath" "INFO"
}
