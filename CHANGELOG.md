# Changelog

Todas as alterações relevantes do Trivor Installer são registradas neste arquivo, da versão mais recente para a mais antiga.

Padrão de versão (a partir da v3.4.2): `vMAIOR.MENOR.BUG`, por exemplo `v3.4.4`. Cada nova tag incrementa a maior versão existente. As tags anteriores (`v3.41`, `v3.40`, `v3.38`...) seguem um padrão legado e não são consideradas pelo instalador para exibir a versão.

---

## v3.4.5 — Sprint 2: segurança

### Corrigido (vulnerabilidades)

- **Execução de código como SYSTEM via cache plantado.** Em contexto RMM/SYSTEM, a pasta de trabalho era `C:\Windows\Temp\TrivorInstaller`, com nome fixo, num local onde usuários comuns podem criar arquivos. Um usuário podia deixar ali, antes da execução, um instalador (ex.: `TakeControlAgent.exe`), um módulo `.ps1` ou um JSON de cliente, e o instalador executava ou carregava esse arquivo como SYSTEM.
  - A pasta de trabalho agora tem nome aleatório (`TrivorInstaller_<GUID>`) e ACL restrita a SYSTEM e Administradores, aplicada antes de qualquer download.
  - Cache, módulos e JSONs de clientes ficam dentro dessa pasta.
- **Exclusão arbitrária como SYSTEM via junction.** A limpeza fazia `Remove-Item -Recurse` no caminho fixo. Uma junction criada ali por um usuário comum levava o PowerShell 5.1 a apagar o conteúdo do destino. A remoção agora nunca segue links: junctions e symlinks são removidos sem tocar no destino.
- **`C:\TrivorInstaller` gravável por usuários comuns.** A pasta herdava de `C:\` permissão de modificação para Usuários Autenticados, o que permitia alterar ou ler logs (que contêm URLs de instalação dos clientes) e plantar junctions nos caminhos em que o SYSTEM grava.
  - A pasta e todo o conteúdo existente passam a ter dono Administradores, sem herança, com acesso apenas para SYSTEM e Administradores.
  - Links encontrados dentro dela são removidos antes da aplicação da ACL.
- **Winget via Scheduled Task:** cada execução usa uma subpasta própria em `C:\TrivorInstaller\Winget`. Somente o usuário logado (pelo SID) recebe permissão de Modificar, e apenas nessa subpasta.

### Adicionado

- **Validação de assinatura digital (Authenticode) para instaladores sem SHA256** (`UrlExe` e `RepoExePublic`). O instalador só executa se a assinatura for válida.
  - Novo campo opcional `Install.Signer`: exige que o certificado seja da organização informada (campo O= do certificado).
  - Instalador sem hash nunca é reaproveitado do cache: é sempre baixado de novo e validado.
  - Os 12 clientes com Take Control passam a exigir o assinante `N-ABLE TECHNOLOGIES LTD`, verificado no instalador real (certificado EV DigiCert, válido até 06/2027).
- `.gitignore` com `.claude/settings.local.json`, que deixa de ser versionado (continha caminhos locais da máquina de desenvolvimento).

### Removido

- TLS 1.0 e 1.1 nos downloads. Agora apenas TLS 1.2 e, quando o .NET suportar, TLS 1.3.

### Alterado

- User-Agent e versão de fallback atualizados para 3.4.5.

---

## v3.4.4 — Sprint 1: correção de bugs

### Corrigido

- **Exit code dos instaladores agora é validado.** Antes, os métodos `RepoExePublic`, `UrlExe` e `RegFile` retornavam sucesso mesmo quando o instalador falhava, o que gerava contagem errada no resumo da sessão e exit code 0 para o RMM.
  - Códigos aceitos como sucesso: `0`, `3010` (reinício pendente) e `1641` (reinício iniciado).
  - Novo campo opcional por app no JSON: `Install.SuccessExitCodes` (ex.: `[0, 1]`), para instaladores que usam códigos fora do padrão.
  - `RegFile`: falha no `reg import` agora é contabilizada como falha.
- **Winget: "nenhuma atualização disponível" não conta mais como falha.** O código `0x8A15002B` (`UPDATE_NOT_APPLICABLE`) no upgrade é tratado como sucesso, assim como `0x8A150061` (`PACKAGE_ALREADY_INSTALLED`) no install e os códigos de reinício `0x8A150109`/`0x8A15010B`. Isso evita o exit code 2 em máquinas que já estão atualizadas.
- **Winget via Scheduled Task (contexto RMM/SYSTEM): o exit code estourava.** O `LastTaskResult` vem como UInt32, e a conversão com `[int]` gerava exceção em HRESULTs do winget (ex.: `0x8A15002B`), transformando qualquer retorno desse tipo em falha genérica. A conversão agora é feita com sinal (`ConvertTo-TrivorInt32`).
- **Timeout da Scheduled Task:** após 900 s, a task agora é encerrada (`Stop-ScheduledTask`) e o timeout é registrado no log, em vez de deixar o winget rodando em segundo plano.
- **Winget upgrade --all (modo interativo):** passa a verificar o exit code em vez de exibir sempre "Upgrade concluído".
- **Detecção via winget com match exato do Id:** `Mozilla.Firefox` não é mais detectado como instalado quando só existe `Mozilla.Firefox.ESR` (o mesmo vale para `Google.Chrome` x `Google.Chrome.Beta`).
- **Detecção via registro com prioridade de match:** exato > prefixo > contém. Nomes curtos não pegam mais outro produto quando existe um match mais preciso. Nenhuma detecção que funcionava antes deixa de funcionar.
- **Versão exibida no banner.** A API do GitHub não ordena as tags por versão, e o banner mostrava `v3.41` (tag legada) em vez da mais recente (`v3.4.3`). Agora são consideradas apenas as tags no padrão `vMAIOR.MENOR.BUG`, e a maior versão é escolhida numericamente. As tags legadas (`v3.41`, `v3.40`, `v.3.4.2`...) são ignoradas.
- **Hostname respeita o limite NetBIOS de 15 caracteres.** Espaços e caracteres inválidos do serial são removidos e, se o nome passar do limite, são mantidos os últimos caracteres do serial. Seriais comuns (Dell, Lenovo, HP) geram o mesmo nome de antes, então máquinas já padronizadas não são renomeadas de novo.

### Adicionado

- Aviso no fim da sessão quando algum instalador solicita reinício da máquina.
- Este arquivo `CHANGELOG.md`.

### Alterado

- User-Agent e versão de fallback atualizados para 3.4.4.

---

## v3.4.3

- Validação da estrutura do JSON do cliente (campos `Client` e `Applications`).
- Exibição do caminho do log no fim da sessão.
- `Cache.ps1` passa a ser a fonte canônica do caminho de cache.
- Exit codes do script: `0` (sucesso), `1` (erro fatal), `2` (concluído com falhas).

## v3.4.2

- Adobe Reader e Zoom adicionados a todos os clientes.
- Carregamento dos JSONs de clientes sob demanda, em vez de baixar todos no início.

## v3.41

- Dois momentos de instalação: Pós-Formatação e Compliance.
- Prioridade de instalação por app (campo `Priority`).
- Contador de progresso `[x/total]`.
- Modo manual passa a voltar ao grid de apps após cada ação.

## v3.40

Refatoração e correções de qualidade:

- Versão buscada da API do GitHub em todos os contextos (sem valor fixo no código).
- Corrigido: o runner da Scheduled Task sobrescrevia o stdout antes de o winget executar.
- Código morto removido: `Invoke-AppAction` modo Manual, `Invoke-ClientManualInstall` e cache de status do menu.
- `Detection.ps1`: o método Registry aceita tanto `DisplayName` quanto `RegistryDisplayName`.
- `Engine.ps1`: User-Agent atualizado para 3.40.

## v3.38, v3.36, v3.35

Sem registro de alterações.

## v3.37

Nova opção no menu do cliente: **Winget upgrade --all**.

- Exibe na tela todos os apps instalados com atualização disponível (`winget upgrade`).
- Solicita confirmação antes de prosseguir.
- Executa `winget upgrade --all` e mostra o progresso em tempo real.
- Compatível com contexto RMM/SYSTEM (executa via Scheduled Task como usuário logado).

Ajustes no menu do cliente:

- Opção 3 renomeada para "Update todos os programas do cliente (Winget)".
- Nova opção 5: "Winget upgrade --all (atualizar todos os apps da máquina)".
- Opção 6: voltar ao menu principal.

## v3.32

Atualização do modo manual:

- Exibe um grid com todos os apps do cliente.
- O técnico digita o número do app.
- Aparece o prompt `[I] Install / [U] Update / [S] Skip / [Q] Quit`.
- Volta ao grid para selecionar o próximo app.
