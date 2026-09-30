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

# Somente TLS 1.2 (e 1.3 quando o .NET suportar)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 } catch { Write-Verbose "TLS 1.3 indisponivel neste .NET; usando TLS 1.2." }

#region Seguranca de diretorios

function Test-TrivorReparsePoint {
    param([Parameter(Mandatory)] [string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
    }
    catch { return $false }
}

function Remove-TrivorReparsePoints {
    # Percorre a arvore sem nunca descer em reparse points e remove apenas os links
    # (junction/symlink), preservando o destino. Retorna a quantidade removida.
    param([Parameter(Mandatory)] [string]$Path)

    $removed = 0
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
        if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            Write-Host "[WARN] Link removido: $($child.FullName)" -ForegroundColor Yellow
            try {
                if ($child.PSIsContainer) { [System.IO.Directory]::Delete($child.FullName) } else { [System.IO.File]::Delete($child.FullName) }
                $removed++
            } catch {
                Write-Host "[WARN] Nao foi possivel remover o link $($child.FullName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        elseif ($child.PSIsContainer) {
            $removed += Remove-TrivorReparsePoints -Path $child.FullName
        }
    }
    return $removed
}

function Remove-TrivorDirectorySafe {
    # Remove um diretorio sem nunca seguir junctions/symlinks. Se o caminho for um
    # reparse point, remove apenas o link, preservando o destino.
    param([Parameter(Mandatory)] [string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    if (Test-TrivorReparsePoint -Path $Path) {
        Write-Host "[WARN] '$Path' e um link (junction/symlink). Removendo apenas o link." -ForegroundColor Yellow
        [System.IO.Directory]::Delete($Path)
        return
    }

    # Links internos sao removidos antes, para o Remove-Item recursivo nao entrar neles
    $null = Remove-TrivorReparsePoints -Path $Path

    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Protect-TrivorDirectory {
    # Cria (se necessario) e restringe um diretorio: dono Administradores, sem heranca,
    # Controle Total somente para SYSTEM e Administradores. SIDs evitam problema com
    # nomes localizados (ex: "Administradores" em pt-BR).
    # -ModifySids concede Modificar a SIDs adicionais (ex: usuario logado da Scheduled Task).
    # -ResetChildren aplica a nova ACL a arquivos/pastas ja existentes.
    param(
        [Parameter(Mandatory)] [string]$Path,
        [string[]]$ModifySids = @(),
        [switch]$ResetChildren
    )

    try {
        if ((Test-Path -LiteralPath $Path) -and (Test-TrivorReparsePoint -Path $Path)) {
            Write-Host "[WARN] '$Path' e um link (junction/symlink). Removendo o link e recriando o diretorio." -ForegroundColor Yellow
            [System.IO.Directory]::Delete($Path)
        }
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Force -Path $Path | Out-Null
        }

        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $noProp  = [System.Security.AccessControl.PropagationFlags]::None
        $allow   = [System.Security.AccessControl.AccessControlType]::Allow
        $admins  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $system  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")

        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetOwner($admins)
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($system, $admins)) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, $noProp, $allow)))
        }
        foreach ($s in $ModifySids) {
            if ([string]::IsNullOrWhiteSpace($s)) { continue }
            $sid = New-Object System.Security.Principal.SecurityIdentifier($s)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'Modify', $inherit, $noProp, $allow)))
        }

        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop

        if ($ResetChildren -and (Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
            # Links internos sao removidos antes, para o icacls /T nunca alterar o destino deles
            $null = Remove-TrivorReparsePoints -Path $Path

            # Dono Administradores e ACL apenas herdada em tudo que ja existia
            & icacls.exe "$Path\*" /setowner "*S-1-5-32-544" /T /C /Q 2>&1 | Out-Null
            & icacls.exe "$Path\*" /reset /T /C /Q 2>&1 | Out-Null
        }
        return $true
    }
    catch {
        Write-Host "[WARN] Nao foi possivel restringir permissoes de '$Path': $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

#endregion

# Diretorio de trabalho com nome aleatorio e ACL restrita. Em contexto SYSTEM o TEMP e
# C:\Windows\Temp, onde usuarios comuns podem criar arquivos: um nome fixo permitia
# plantar instaladores/modulos ou uma junction antes da execucao.
$global:TrivorBasePath = Join-Path $env:TEMP ("TrivorInstaller_" + [guid]::NewGuid().ToString('N'))

function Invoke-Cleanup {
    try { Remove-TrivorDirectorySafe -Path $global:TrivorBasePath }
    catch { Write-Host "[WARN] Falha na limpeza de $($global:TrivorBasePath): $($_.Exception.Message)" -ForegroundColor Yellow }
}

try {
    $global:TrivorExitCode      = 0
    $global:TrivorSessionTotal  = 0
    $global:TrivorSessionFailed = 0

    $BasePath    = $global:TrivorBasePath
    $CorePath    = Join-Path $BasePath "core"
    $ClientsPath = Join-Path $BasePath "Clientes"

    if (-not (Protect-TrivorDirectory -Path $BasePath)) {
        Write-Host "[WARN] Continuando com diretorio de trabalho sem ACL restrita: $BasePath" -ForegroundColor Yellow
    }
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

    if ($global:TrivorRebootRequired) {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log "Reinicio pendente: um ou mais instaladores solicitaram reinicio." "WARN"
        }
        Write-Host "[ATENCAO] Um ou mais instaladores solicitaram reinicio da maquina." -ForegroundColor Yellow
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
