# ==============================
# Trivor Installer - Engine.ps1
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

#region SHA256
function Get-FileSha256 {
    param([Parameter(Mandatory)] [string]$Path)
    try { return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToUpper() } catch { return $null }
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

        Write-Log ("Downloading attempt {0}: {1}" -f $i, $RelativePath) "INFO"
        $ok = Get-PublicRepoFile -Owner $Owner -Repo $Repo -Branch $Branch -RelativePath $RelativePath -DestinationFile $DestinationFile
        if (-not $ok) { continue }

        $hash = Get-FileSha256 -Path $DestinationFile
        if ($hash -and $hash -eq $expected) {
            Write-Log "SHA256 OK: $DestinationFile" "INFO"
            return $true
        }

        Write-Log "SHA256 mismatch after download (attempt ${i})." "ERROR"
        try { Remove-Item $DestinationFile -Force -ErrorAction SilentlyContinue } catch {}
    }

    Write-Log ("Failed SHA256 validation after {0} attempts." -f $MaxAttempts) "ERROR"
    return $false
}
#endregion

function Get-TrivorFileHeaderHex {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [int]$Bytes = 2
    )

    try {
        if (-not (Test-Path $Path)) { return $null }
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $buffer = New-Object byte[] $Bytes
            $read = $fs.Read($buffer, 0, $Bytes)
            if ($read -le 0) { return $null }
            return (($buffer[0..($read - 1)] | ForEach-Object { $_.ToString('X2') }) -join '')
        }
        finally {
            $fs.Close()
        }
    }
    catch {
        Write-Log "Nao foi possivel ler assinatura do arquivo: $Path | $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Invoke-TrivorDownloadWithProgress {
    param(
        [Parameter(Mandatory)] [string]$Url,
        [Parameter(Mandatory)] [string]$OutFile,
        [int]$MaxAttempts = 3,
        [switch]$ValidateExe
    )

    Write-Log "Iniciando download: $Url" "INFO"

    $folder = Split-Path $OutFile
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }

    $partialFile = "$OutFile.download"

    try {
        # Garante TLS moderno em Windows PowerShell 5.1
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
        }
        catch {}

        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
            try {
                if (Test-Path $OutFile) { Remove-Item $OutFile -Force -ErrorAction SilentlyContinue }
                if (Test-Path $partialFile) { Remove-Item $partialFile -Force -ErrorAction SilentlyContinue }

                Write-Log "Download tentativa $attempt/$MaxAttempts" "INFO"

                $request = [System.Net.HttpWebRequest]::Create($Url)
                $request.Method = "GET"
                $request.AllowAutoRedirect = $true
                $request.MaximumAutomaticRedirections = 10
                $request.Timeout = 300000
                $request.ReadWriteTimeout = 300000
                $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TrivorInstaller/3.34"
                $request.Accept = "*/*"

                $response = $request.GetResponse()
                $statusCode = [int]$response.StatusCode
                $contentType = $response.ContentType
                $totalBytes = [int64]$response.ContentLength

                Write-Log "HTTP Status=$statusCode | ContentType=$contentType | ContentLength=$totalBytes" "INFO"

                $inputStream = $response.GetResponseStream()
                $outputStream = [System.IO.File]::Open($partialFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

                try {
                    $buffer = New-Object byte[] (1024 * 1024)
                    [int64]$downloaded = 0
                    $lastLoggedPercent = -10
                    $lastLoggedMb = -25

                    while ($true) {
                        $read = $inputStream.Read($buffer, 0, $buffer.Length)
                        if ($read -le 0) { break }

                        $outputStream.Write($buffer, 0, $read)
                        $downloaded += $read

                        if ($totalBytes -gt 0) {
                            $percent = [math]::Floor(($downloaded / $totalBytes) * 100)
                            $mbRead = [math]::Round($downloaded / 1MB, 2)
                            $mbTotal = [math]::Round($totalBytes / 1MB, 2)

                            Write-Progress `
                                -Activity "Baixando instalador" `
                                -Status "$mbRead MB de $mbTotal MB ($percent%)" `
                                -PercentComplete ([Math]::Min($percent, 100))

                            if (($percent -ge ($lastLoggedPercent + 10)) -or ($percent -eq 100)) {
                                Write-Log "Download progresso: $percent% ($mbRead MB / $mbTotal MB)" "INFO"
                                $lastLoggedPercent = $percent
                            }
                        }
                        else {
                            $mbRead = [math]::Round($downloaded / 1MB, 2)
                            Write-Progress `
                                -Activity "Baixando instalador" `
                                -Status "$mbRead MB baixados" `
                                -PercentComplete 0

                            if ($mbRead -ge ($lastLoggedMb + 25)) {
                                Write-Log "Download progresso: $mbRead MB baixados" "INFO"
                                $lastLoggedMb = $mbRead
                            }
                        }
                    }

                    $outputStream.Flush()
                }
                finally {
                    if ($outputStream) { $outputStream.Close() }
                    if ($inputStream) { $inputStream.Close() }
                    if ($response) { $response.Close() }
                    Write-Progress -Activity "Baixando instalador" -Completed
                }

                if (-not (Test-Path $partialFile)) {
                    throw "Arquivo parcial nao foi criado."
                }

                $fileInfo = Get-Item $partialFile -ErrorAction Stop

                if ($fileInfo.Length -le 0) {
                    throw "Arquivo baixado esta vazio."
                }

                if ($totalBytes -gt 0 -and $fileInfo.Length -ne $totalBytes) {
                    throw "Download incompleto. Esperado=$totalBytes bytes | Baixado=$($fileInfo.Length) bytes"
                }

                $signature = Get-TrivorFileHeaderHex -Path $partialFile -Bytes 4

                if ($contentType -match 'text/html|application/json|text/plain|xml') {
                    $preview = ""
                    try { $preview = (Get-Content -Path $partialFile -TotalCount 5 -ErrorAction SilentlyContinue) -join " " } catch {}
                    throw "Servidor retornou conteudo nao-binario. ContentType=$contentType | Inicio=$preview"
                }

                if ($ValidateExe) {
                    if (-not $signature -or -not $signature.StartsWith("4D5A")) {
                        $preview = ""
                        try { $preview = (Get-Content -Path $partialFile -TotalCount 3 -ErrorAction SilentlyContinue) -join " " } catch {}
                        throw "Arquivo baixado nao parece EXE valido. Assinatura=$signature | Inicio=$preview"
                    }
                }

                Move-Item -Path $partialFile -Destination $OutFile -Force

                $finalInfo = Get-Item $OutFile -ErrorAction Stop
                Write-Log "Download concluido e validado: $OutFile | Size=$([math]::Round($finalInfo.Length / 1MB, 2)) MB | Signature=$signature" "INFO"
                return $true
            }
            catch {
                Write-Log ("Falha no download tentativa {0}/{1}: {2}" -f $attempt, $MaxAttempts, $_.Exception.Message) "ERROR"
                try { if (Test-Path $partialFile) { Remove-Item $partialFile -Force -ErrorAction SilentlyContinue } } catch {}
                try { if (Test-Path $OutFile) { Remove-Item $OutFile -Force -ErrorAction SilentlyContinue } } catch {}

                if ($attempt -lt $MaxAttempts) {
                    Start-Sleep -Seconds (3 * $attempt)
                }
            }
        }

        Write-Log ("Download falhou apos {0} tentativas: {1}" -f $MaxAttempts, $Url) "ERROR"
        return $false
    }
    catch {
        Write-Log "Erro inesperado no download: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

#region Winget - contexto normal ou RMM/SYSTEM via usuario logado

$global:TrivorWingetDir         = Join-Path $env:SystemDrive "TrivorInstaller\Winget"
$global:TrivorWingetExe         = $null
$global:TrivorWingetInitialized = $false

function Test-TrivorSystemContext {
    # Detecta contexto nao-interativo: SYSTEM literal, contas de servico NT, ou
    # ausencia de perfil de usuario (tipico de RMMs como N-able, Datto, Ninja, etc.)
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $name     = $identity.Name

        # 1) NT AUTHORITY\SYSTEM classico
        if ($name -eq "NT AUTHORITY\SYSTEM") { return $true }

        # 2) Contas de servico NT (ex: NT SERVICE\NableAgent)
        if ($name -match '^NT (AUTHORITY\\(LOCAL SERVICE|NETWORK SERVICE)|SERVICE\\)') { return $true }

        # 3) Sem perfil de usuario carregado (nenhum USERPROFILE apontando para C:\Users\<alguem>)
        $profile = [System.Environment]::GetFolderPath("UserProfile")
        if ([string]::IsNullOrWhiteSpace($profile)) { return $true }
        if ($profile -match '\\(system32|windows|systemprofile)$') { return $true }

        # 4) Variaveis de ambiente tipicas de agentes RMM
        $rmmSignals = @(
            $env:NABLE_AGENT_HOME,       # N-able
            $env:SOLARWINDS_AGENT,       # SolarWinds/N-able legado
            $env:NAAGENT_HOME,           # N-able alternativo
            $env:DATTO_AGENT,            # Datto RMM
            $env:NINJAONE_AGENT,         # NinjaOne
            $env:ATERA_AGENT             # Atera
        )
        foreach ($sig in $rmmSignals) {
            if (-not [string]::IsNullOrWhiteSpace($sig)) { return $true }
        }

        # 5) LOCALAPPDATA ausente ou apontando para perfil de sistema
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { return $true }
        if ($env:LOCALAPPDATA -match '\\(systemprofile|LocalService|NetworkService)\\') { return $true }

        return $false
    }
    catch {
        return $false
    }
}

function Get-TrivorLoggedOnUser {
    try {
        $user = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if ([string]::IsNullOrWhiteSpace($user)) { return $null }
        return $user
    }
    catch {
        Write-Log "Falha ao detectar usuario logado: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Get-WingetExecutable {
    # Esta funcao so deve localizar Winget no contexto atual.
    # Em RMM/SYSTEM, o Winget sera localizado dentro do script executado como usuario logado.
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }

    $candidates = @()

    if ($env:LOCALAPPDATA) {
        $candidates += (Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\winget.exe")
    }

    $candidates += "$env:SystemRoot\System32\winget.exe"

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    return $null
}

function Initialize-Winget {
    # Evita re-inicializacao redundante (ex: chamada por app em loop de deteccao)
    if ($global:TrivorWingetInitialized) {
        return ($global:TrivorWingetExe -ne $null -or (Test-TrivorSystemContext))
    }

    Write-Log "Initializing winget..." "INFO"

    # Log da identidade atual para facilitar debug em RMM
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-Log "Contexto de execucao: $currentUser" "INFO"
    } catch {}

    if (-not (Test-Path $global:TrivorWingetDir)) {
        New-Item -ItemType Directory -Force -Path $global:TrivorWingetDir | Out-Null
    }

    if (Test-TrivorSystemContext) {
        $loggedUser = Get-TrivorLoggedOnUser
        if ($loggedUser) {
            Write-Log "Contexto SYSTEM/RMM detectado. Winget sera executado no usuario logado: $loggedUser" "INFO"
            $global:TrivorWingetExe = $null
            $global:TrivorWingetInitialized = $true
            return $true
        }

        Write-Log "Contexto SYSTEM/RMM detectado, mas nenhum usuario interativo esta logado. Winget indisponivel." "ERROR"
        $global:TrivorWingetExe = $null
        $global:TrivorWingetInitialized = $true
        return $false
    }

    $global:TrivorWingetExe = Get-WingetExecutable

    if (-not $global:TrivorWingetExe) {
        Write-Log "Winget nao encontrado no contexto atual." "ERROR"
        $global:TrivorWingetInitialized = $true
        return $false
    }

    Write-Log "Winget ready. Executavel: $global:TrivorWingetExe" "INFO"
    $global:TrivorWingetInitialized = $true
    return $true
}

function Invoke-WingetDirect {
    param(
        [Parameter(Mandatory)] [string]$Arguments,
        [Parameter(Mandatory)] [string]$OperationName
    )

    if (-not $global:TrivorWingetExe) {
        $null = Initialize-Winget
    }

    if (-not $global:TrivorWingetExe) {
        return @{ Success = $false; ExitCode = -1; StdOut = $null; StdErr = $null }
    }

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeName = ($OperationName -replace '[^a-zA-Z0-9\-_\.]', '_')
    $stdout = Join-Path $global:TrivorWingetDir "${stamp}_${safeName}_stdout.log"
    $stderr = Join-Path $global:TrivorWingetDir "${stamp}_${safeName}_stderr.log"

    try {
        $p = Start-Process `
            -FilePath $global:TrivorWingetExe `
            -ArgumentList $Arguments `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr

        return @{ Success = ($p.ExitCode -eq 0); ExitCode = $p.ExitCode; StdOut = $stdout; StdErr = $stderr }
    }
    catch {
        Write-Log "Falha ao executar winget diretamente: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; ExitCode = -1; StdOut = $stdout; StdErr = $stderr }
    }
}

function Invoke-WingetAsLoggedUserTask {
    param(
        [Parameter(Mandatory)] [string]$Arguments,
        [Parameter(Mandatory)] [string]$OperationName
    )

    $loggedUser = Get-TrivorLoggedOnUser

    if (-not $loggedUser) {
        Write-Log "Nenhum usuario logado. Nao e possivel executar Winget em contexto de usuario." "ERROR"
        return @{ Success = $false; ExitCode = -1; StdOut = $null; StdErr = $null }
    }

    if (-not (Test-Path $global:TrivorWingetDir)) {
        New-Item -ItemType Directory -Force -Path $global:TrivorWingetDir | Out-Null
    }

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeName = ($OperationName -replace '[^a-zA-Z0-9\-_\.]', '_')
    $stdout = Join-Path $global:TrivorWingetDir "${stamp}_${safeName}_stdout.log"
    $stderr = Join-Path $global:TrivorWingetDir "${stamp}_${safeName}_stderr.log"
    $runner = Join-Path $global:TrivorWingetDir "${stamp}_${safeName}_runner.ps1"

    $runnerContent = @"
`$ErrorActionPreference = 'Continue'
`$ProgressPreference = 'SilentlyContinue'

function Resolve-UserWinget {
    `$cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (`$cmd -and `$cmd.Source) { return `$cmd.Source }

    `$candidates = @()
    if (`$env:LOCALAPPDATA) {
        `$candidates += (Join-Path `$env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe')
    }
    `$candidates += (Join-Path `$env:USERPROFILE 'AppData\Local\Microsoft\WindowsApps\winget.exe')
    `$candidates += "`$env:SystemRoot\System32\winget.exe"

    foreach (`$candidate in `$candidates) {
        if (`$candidate -and (Test-Path `$candidate)) { return `$candidate }
    }

    return `$null
}

"==== Trivor Winget Runner ====" | Out-File -FilePath "$stdout" -Append -Encoding UTF8
"User=`$env:USERDOMAIN\`$env:USERNAME" | Out-File -FilePath "$stdout" -Append -Encoding UTF8
"Operation=$OperationName" | Out-File -FilePath "$stdout" -Append -Encoding UTF8
"Arguments=$Arguments" | Out-File -FilePath "$stdout" -Append -Encoding UTF8

`$wingetExe = Resolve-UserWinget
if (-not `$wingetExe) {
    "Winget nao encontrado no contexto do usuario logado." | Out-File -FilePath "$stderr" -Append -Encoding UTF8
    exit 1
}

"WingetExe=`$wingetExe" | Out-File -FilePath "$stdout" -Append -Encoding UTF8

try {
    `$process = Start-Process -FilePath `$wingetExe -ArgumentList "$Arguments" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$stdout" -RedirectStandardError "$stderr"
    exit `$process.ExitCode
}
catch {
    "Falha ao executar Winget: `$(`$_.Exception.Message)" | Out-File -FilePath "$stderr" -Append -Encoding UTF8
    exit 1
}
"@

    Set-Content -Path $runner -Value $runnerContent -Encoding UTF8 -Force

    $taskName = "TrivorWinget_$([guid]::NewGuid().ToString('N'))"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$runner`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3)
    $principal = New-ScheduledTaskPrincipal -UserId $loggedUser -LogonType Interactive -RunLevel Highest

    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        Write-Log "Scheduled Task criada para executar Winget como usuario logado: $loggedUser | Task=$taskName" "INFO"
        Start-ScheduledTask -TaskName $taskName

        $timeout = 900
        $elapsed = 0

        Start-Sleep -Seconds 5

        do {
            Start-Sleep -Seconds 2
            $elapsed += 2
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            $state = if ($task) { $task.State } else { "Unknown" }
        } while ($state -eq "Running" -and $elapsed -lt $timeout)

        $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $exitCode = if ($info) { [int]$info.LastTaskResult } else { -1 }

        return @{ Success = ($exitCode -eq 0); ExitCode = $exitCode; StdOut = $stdout; StdErr = $stderr }
    }
    catch {
        Write-Log "Falha ao executar winget via usuario logado/Scheduled Task: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; ExitCode = -1; StdOut = $stdout; StdErr = $stderr }
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Remove-Item $runner -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-WingetAsUser {
    param(
        [Parameter(Mandatory)] [string]$Arguments,
        [Parameter(Mandatory)] [string]$OperationName
    )

    if (Test-TrivorSystemContext) {
        Write-Log "Contexto SYSTEM/RMM detectado. Redirecionando Winget para usuario logado." "DEBUG"
        return (Invoke-WingetAsLoggedUserTask -Arguments $Arguments -OperationName $OperationName)
    }

    Write-Log "Contexto normal detectado. Executando Winget no contexto atual." "DEBUG"
    return (Invoke-WingetDirect -Arguments $Arguments -OperationName $OperationName)
}

function Write-WingetResult {
    param(
        [Parameter(Mandatory)] [string]$Action,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] $Result
    )

    $stdOutText = ""
    $stdErrText = ""

    if ($Result.StdOut -and (Test-Path $Result.StdOut)) {
        try { $stdOutText = (Get-Content $Result.StdOut -Raw -ErrorAction SilentlyContinue) } catch {}
    }

    if ($Result.StdErr -and (Test-Path $Result.StdErr)) {
        try { $stdErrText = (Get-Content $Result.StdErr -Raw -ErrorAction SilentlyContinue) } catch {}
    }

    $msg = "$Action | Target=$Target | ExitCode=$($Result.ExitCode) | StdOutFile=$($Result.StdOut) | StdErrFile=$($Result.StdErr)"

    if ($Result.Success) {
        Write-Log $msg "INFO"
    } else {
        Write-Log $msg "ERROR"
    }

    if (-not [string]::IsNullOrWhiteSpace($stdOutText)) {
        Write-Log "$Action stdout [$Target]: $stdOutText" "INFO"
    }

    if (-not [string]::IsNullOrWhiteSpace($stdErrText)) {
        Write-Log "$Action stderr [$Target]: $stdErrText" "ERROR"
    }
}

function Install-WingetApp {
    param([Parameter(Mandatory)] [string]$WingetId)

    Write-Log "Installing via Winget: $WingetId" "INFO"
    $result = Invoke-WingetAsUser -Arguments "install --id `"$WingetId`" --exact --source winget --silent --accept-package-agreements --accept-source-agreements --disable-interactivity" -OperationName "install_$WingetId"
    Write-WingetResult -Action "WingetInstall" -Target $WingetId -Result $result
    return $result.Success
}

function Update-WingetApp {
    param([Parameter(Mandatory)] [string]$WingetId)

    Write-Log "Updating via Winget: $WingetId" "INFO"
    $result = Invoke-WingetAsUser -Arguments "upgrade --id `"$WingetId`" --exact --source winget --silent --include-unknown --accept-package-agreements --accept-source-agreements --disable-interactivity" -OperationName "upgrade_$WingetId"
    Write-WingetResult -Action "WingetUpgrade" -Target $WingetId -Result $result
    return $result.Success
}

function Upgrade-WingetAll {
    Write-Log "Running: winget upgrade --all" "INFO"
    $result = Invoke-WingetAsUser -Arguments "upgrade --all --silent --include-unknown --accept-package-agreements --accept-source-agreements --disable-interactivity" -OperationName "upgrade_all"
    Write-WingetResult -Action "WingetUpgradeAll" -Target "ALL" -Result $result
    return $result.Success
}

function Invoke-WingetUpgradeAllWithDisplay {
    [void](Initialize-Winget)

    $isSystem = Test-TrivorSystemContext

    Write-Host ""
    Write-Host "Verificando apps com atualizacao disponivel..." -ForegroundColor Cyan
    Write-Host ""

    if ($isSystem) {
        $listResult = Invoke-WingetAsUser -Arguments "upgrade" -OperationName "upgrade_list"
        if ($listResult.StdOut -and (Test-Path $listResult.StdOut)) {
            Get-Content $listResult.StdOut -Encoding UTF8 | ForEach-Object { Write-Host $_ }
        } else {
            Write-Host "Nao foi possivel obter a lista de atualizacoes." -ForegroundColor Yellow
        }
    } else {
        if (-not $global:TrivorWingetExe) { $null = Initialize-Winget }
        if (-not $global:TrivorWingetExe) {
            Write-Host "Winget nao disponivel." -ForegroundColor Red
            return
        }
        & $global:TrivorWingetExe upgrade 2>&1 | ForEach-Object { Write-Host $_ }
    }

    Write-Host ""
    $confirm = Read-Host "Deseja atualizar todos os apps acima? (S para confirmar)"
    if ($confirm -notmatch "^(S|s|Y|y)$") {
        Write-Host "Operacao cancelada." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Executando: winget upgrade --all" -ForegroundColor Yellow
    Write-Host ""
    Write-Log "Iniciando winget upgrade --all via menu" "INFO"

    if ($isSystem) {
        $result = Invoke-WingetAsUser -Arguments "upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --disable-interactivity" -OperationName "upgrade_all_display"
        Write-WingetResult -Action "WingetUpgradeAll" -Target "ALL" -Result $result
        if ($result.StdOut -and (Test-Path $result.StdOut)) {
            Get-Content $result.StdOut -Encoding UTF8 | ForEach-Object { Write-Host $_ }
        }
        if ($result.Success) {
            Write-Host ""
            Write-Host "Upgrade concluido com sucesso." -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "Upgrade finalizado com erros. Verifique o log." -ForegroundColor Yellow
        }
    } else {
        & $global:TrivorWingetExe upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements 2>&1 | ForEach-Object { Write-Host $_ }
        Write-Host ""
        Write-Host "Upgrade concluido." -ForegroundColor Green
        Write-Log "winget upgrade --all finalizado" "INFO"
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

    $cacheRoot = Join-Path $env:TEMP "TrivorInstaller\cache"
    New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null

    # 2) RepoExePublic
    if ($App.PSObject.Properties.Match("Install").Count -gt 0 -and $App.Install -and $App.Install.Method -eq "RepoExePublic") {

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

    # 3) UrlExe
    if ($App.PSObject.Properties.Match("Install").Count -gt 0 -and $App.Install -and $App.Install.Method -eq "UrlExe") {

        $cacheFileName = if ($App.Install.CacheFileName) { $App.Install.CacheFileName } else { [System.IO.Path]::GetFileName($App.Install.Url) }
        if ([string]::IsNullOrWhiteSpace($cacheFileName)) {
            $cacheFileName = "$($App.Id).exe"
        }

        $localFile = Join-Path $cacheRoot $cacheFileName
        $hasHash = ($App.Install.PSObject.Properties.Match("Sha256").Count -gt 0 -and $App.Install.Sha256 -and $App.Install.Sha256 -ne "")

        if ($hasHash -and (Test-Path $localFile)) {
            $expected = $App.Install.Sha256.ToUpper()
            $current = Get-FileSha256 -Path $localFile

            if ($current -and $current -eq $expected) {
                Write-Log "SHA256 OK (cached): $localFile" "INFO"
            }
            else {
                Write-Log "Cache existente invalido para $($App.Name). Removendo e baixando novamente." "WARN"
                try { Remove-Item $localFile -Force -ErrorAction SilentlyContinue } catch {}
            }
        }

        if (-not (Test-Path $localFile)) {
            if ($hasHash) {
                Write-Log "Downloading (UrlExe, with hash): $($App.Install.Url)" "INFO"
            }
            else {
                Write-Log "Downloading (UrlExe, no hash): $($App.Install.Url)" "INFO"
            }

            $ok = Invoke-TrivorDownloadWithProgress `
                -Url $App.Install.Url `
                -OutFile $localFile `
                -MaxAttempts 3 `
                -ValidateExe

            if (-not $ok) {
                Write-Log "Download failed: $($App.Install.Url)" "ERROR"
                return
            }
        }

        if ($hasHash) {
            $expected = $App.Install.Sha256.ToUpper()
            $hash = Get-FileSha256 -Path $localFile

            if (-not ($hash -and $hash -eq $expected)) {
                Write-Log "SHA256 mismatch after download. Expected=$expected | Current=$hash. Aborting." "ERROR"
                try { Remove-Item $localFile -Force -ErrorAction SilentlyContinue } catch {}
                return
            }

            Write-Log "SHA256 OK: $localFile" "INFO"
        }

        if (-not (Test-Path $localFile)) {
            Write-Log "Installer nao encontrado apos download: $localFile" "ERROR"
            return
        }

        $fileInfo = Get-Item $localFile -ErrorAction SilentlyContinue
        if (-not $fileInfo -or $fileInfo.Length -le 0) {
            Write-Log "Installer invalido ou vazio: $localFile" "ERROR"
            return
        }

        Write-Log "Executing installer: $localFile" "INFO"
        $installArgs = if ($App.Install.SilentArgs) { $App.Install.SilentArgs } else { "" }

        try {
            $p = Start-Process -FilePath $localFile -ArgumentList $installArgs -Wait -NoNewWindow -PassThru
            Write-Log "Installer finished: $($App.Name) | ExitCode=$($p.ExitCode)" "INFO"
        }
        catch {
            Write-Log "Falha ao executar installer: $localFile | $($_.Exception.Message)" "ERROR"
            return
        }

        if ($App.Install.CleanAfterInstall -eq $true) {
            try { Remove-Item $localFile -Force -ErrorAction SilentlyContinue } catch {}
            Write-Log "Cache cleaned: $localFile" "INFO"
        }
        return
    }


    # 4) RegFile
    if ($App.PSObject.Properties.Match("Install").Count -gt 0 -and $App.Install -and $App.Install.Method -eq "RegFile") {

        $cacheFileName = if ($App.Install.CacheFileName) { $App.Install.CacheFileName } else { [System.IO.Path]::GetFileName($App.Install.RelativePath) }
        $localFile = Join-Path $cacheRoot $cacheFileName

        $ok = Get-PublicRepoFile `
            -Owner $App.Install.Owner `
            -Repo $App.Install.Repo `
            -Branch $App.Install.Branch `
            -RelativePath $App.Install.RelativePath `
            -DestinationFile $localFile

        if (-not $ok) {
            Write-Log "Falha ao baixar .reg: $($App.Install.RelativePath)" "ERROR"
            return
        }

        # Garante encoding UTF-16 LE com BOM (exigido pelo reg import)
        try {
            $rawBytes = [System.IO.File]::ReadAllBytes($localFile)
            $hasUtf16Bom = ($rawBytes.Length -ge 2 -and $rawBytes[0] -eq 0xFF -and $rawBytes[1] -eq 0xFE)

            if (-not $hasUtf16Bom) {
                Write-Log "Convertendo .reg para UTF-16 LE..." "INFO"
                $text = [System.IO.File]::ReadAllText($localFile, [System.Text.Encoding]::UTF8)
                [System.IO.File]::WriteAllText($localFile, $text, [System.Text.Encoding]::Unicode)
            }
        } catch {
            Write-Log "Aviso: nao foi possivel verificar encoding do .reg: $_" "WARN"
        }

        Write-Log "Aplicando registry: $localFile" "INFO"
        try {
            $result = Start-Process -FilePath "reg.exe" -ArgumentList "import `"$localFile`"" -Wait -NoNewWindow -PassThru
            if ($result.ExitCode -eq 0) {
                Write-Log "Registry aplicado com sucesso: $cacheFileName" "INFO"
            } else {
                Write-Log "reg import retornou codigo $($result.ExitCode)" "WARN"
            }
        } catch {
            Write-Log "Erro ao aplicar registry: $_" "ERROR"
        }

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
    param([Parameter(Mandatory)] $App, [Parameter(Mandatory)] $State)

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

    if ($installed -and (Should-ForceReinstallByVersion -App $App -State $state)) {
        $installed = $false
    }

    if ($installed) {
        Write-Log "$($App.Name) already installed. Checking for updates..." "INFO"
        if ($hasWinget) {
            if ($Mode -eq "Manual") {
                $choice = Read-Host "Update $($App.Name) via Winget? (Y/N)"
                if ($choice -match "^(Y|y)$") { Update-WingetApp -WingetId $App.WingetId | Out-Null }
                else { Write-Log "Skipped update: $($App.Name)" "INFO" }
            } else {
                Update-WingetApp -WingetId $App.WingetId | Out-Null
            }
        } else {
            Write-Log "No WingetId for update: $($App.Name)" "INFO"
        }
        return
    }

    Write-Log "$($App.Name) not installed." "INFO"

    if ($Mode -eq "Manual") {
        $choice = Read-Host "Install $($App.Name)? (Y/N)"
        if ($choice -match "^(Y|y)$") { Install-Application -App $App }
        else { Write-Log "Skipped install: $($App.Name)" "INFO" }
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

    [void](Initialize-Winget)
    Write-Log "Starting AUTO mode for client: $($ClientConfig.Client)" "INFO"

    foreach ($app in $ClientConfig.Applications) {
        Write-Log "Processing: $($app.Name)" "INFO"
        Invoke-AppAction -App $app -Mode "Auto"
    }

    Write-Log "Finished AUTO mode for client: $($ClientConfig.Client)" "INFO"
}

function Invoke-ClientUpdateOnly {
    param([Parameter(Mandatory)] [psobject]$ClientConfig)

    [void](Initialize-Winget)
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

function Invoke-ClientManualInstall {
    param([Parameter(Mandatory)] [psobject]$ClientConfig)

    [void](Initialize-Winget)
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