# Changelog

Todas as alterações relevantes do Trivor Installer são registradas neste arquivo, da versão mais recente para a mais antiga.

Padrão de versão (a partir da v3.4.2): `vMAIOR.MENOR.BUG`, por exemplo `v3.4.4`. Cada nova tag incrementa a maior versão existente. As tags anteriores (`v3.41`, `v3.40`, `v3.38`...) seguem um padrão legado e não são consideradas pelo instalador para exibir a versão.

---

## v3.6.0 — Remoção de apps do Windows desnecessários

### Adicionado

- **Remoção de apps do Windows (Appx/MSIX):** nova etapa "Remover apps do Windows desnecessários", logo após a verificação do hostname e antes das instalações, na interface e no console.
  - **Pós-Formatação:** remove os 39 itens da lista para todos os usuários e também o pacote provisionado, para o app não voltar em perfis novos.
  - **Compliance:** remove só os 29 itens sem uso corporativo (jogos, Xbox, conteúdo de consumo e apps descontinuados). Apps patrocinados (Spotify, Netflix, Prime Video, Disney+, TikTok, Instagram) e os itens de governança (Copilot consumidor, Power Automate, Vincular ao Celular, OneNote para Windows 10) ficam só na Pós-Formatação, porque o usuário pode estar usando.
  - Lista em `Padrao/RemoverAppsWindows.json`. A lista `NuncaRemover` (33 itens: Store, winget, Segurança do Windows, Portal da Empresa, Teams corporativo, Edge, Outlook novo, Microsoft 365, To Do, Media Player, codecs e bibliotecas do sistema) sempre tem prioridade.
  - Um app que não pôde ser removido conta como falha da sessão (código de saída 2).
  - O resumo antes de executar informa a remoção.
- Novo módulo `core/Debloat.ps1`.

### Alterado

- O resumo do fim da sessão no console passou de "N instalados com sucesso" para "N etapas concluídas", porque apps já instalados e a remoção de apps do Windows também contam como etapa.
- User-Agent e versão de fallback atualizados para 3.6.0.

---

## v3.5.2 — Nova tentativa automática, instalador reserva do Chrome e interface maximizada

### Adicionado

- **Nova tentativa automática:** falhas passageiras são repetidas uma vez, após 30 segundos, no winget (instalar e atualizar) e nos instaladores EXE/MSI. Códigos tratados: `0x80070020` e `0x8A150103` (arquivo em uso), `1618`, `0x80070652` e `0x8A150102` (outra instalação em andamento). Motivo: o Adobe Reader falhou em produção com `0x80070020` e instalou na segunda execução.
- **Método `UrlMsi`:** instala MSI baixado de URL oficial com `msiexec /i`. Exige `Install.Signer` e assinatura digital válida, e confere o cabeçalho do arquivo MSI após o download.
- **Instalador reserva (`Fallback`):** quando o winget falha na instalação porque o hash do instalador não confere com o manifesto (`0x8A150011`), o instalador reserva do app é usado. Os 42 clientes receberam o MSI enterprise oficial do Google Chrome como reserva (assinante "Google LLC"). Motivo: o Chrome falhou em produção com `0x8A150011`, pois a Google troca o MSI na mesma URL antes de o manifesto do winget ser atualizado.
- **Interface:** a coluna "Origem" mostra "Winget (reserva MSI)" para apps com instalador reserva.

### Alterado

- **Interface:** a janela abre maximizada. Ao restaurar, volta ao tamanho padrão (1280 × 800), centralizada.
- A execução dos instaladores `RepoExePublic` e `UrlExe` passou para uma função única. Se o instalador não puder ser executado, o arquivo em cache também é apagado quando `CleanAfterInstall` está ativo (antes, no `UrlExe`, ficava no cache da sessão até a limpeza final).
- User-Agent e versão de fallback atualizados para 3.5.2.

### Limitação conhecida

- O instalador reserva só é usado na instalação. Se o Chrome já estiver instalado e a atualização via winget falhar por hash, a falha continua sendo registrada (o Chrome se atualiza sozinho em seguida).

---

## v3.5.1 — Correções após o primeiro uso em produção

### Corrigido

- **Interface:** erro "Não é possível chamar um método em uma expressão de valor nulo" ao terminar a identificação do cliente, antes de qualquer cliente ser aberto. Com o erro, a faixa ficava presa em "Identificando o cliente desta máquina…" e o cursor de "ocupado" podia continuar ativo. Além da correção, uma falha ao reabilitar a tela não impede mais que o resultado da tarefa seja exibido.
- **Log:** a versão aparecia duplicada (`vv3.4.3`).
- **Log:** a saída do winget aparecia com acentos quebrados (`VersÃ£o`). Ela é UTF-8 e agora é lida como tal no Windows PowerShell 5.1.

### Alterado

- User-Agent e versão de fallback atualizados para 3.5.1.

---

## v3.5.0 — Interface gráfica (WPF)

### Adicionado

- **Interface gráfica em WPF** (`core/Gui.ps1`), aberta automaticamente quando há um técnico logado na máquina. Telas:
  - **Clientes:** cards com busca por nome.
  - **Painel do cliente:**
    - hostname atual × esperado;
    - os modos Pós-Formatação, Compliance, Atualizar apps e Renomear hostname;
    - tabela de apps com origem do instalador (winget, repositório com SHA256, URL com assinatura) e status (Instalado, Faltando, Versão antiga);
    - **Instalar selecionados:** checkboxes que substituem o modo manual do console.
  - **Execução:** progresso geral, etapas e log ao vivo. "Cancelar após o app atual" nunca interrompe um instalador no meio.
  - **Resumo:** sucesso, falhas, código de saída da sessão (RMM), duração, resultado por etapa e aviso de reinício pendente, com a opção "Reiniciar ao fechar".
  - **Upgrade geral:** lista os apps da máquina com atualização no winget, para escolher o que atualizar. Se a saída do winget vier em formato desconhecido, ela é exibida como texto, sem leitura arriscada.
  - **Logs:** arquivos de `C:\TrivorInstaller\Logs` com filtro por nível (INFO, WARN, ERROR) e busca.
  - **Sobre:** versão, canal, ambiente, pastas e retenção.
- **Funcionamento:**
  - Identidade visual da Trivor: logo, azul `#3568B1` e fonte Segoe UI.
  - As ações rodam em segundo plano, então a janela não congela durante as instalações.
  - Não é possível fechar a janela no meio de uma execução.
  - A interface usa as mesmas funções de instalação e detecção do console. A lógica do motor não mudou.
- **Console como fallback:** o menu de console continua igual e é usado automaticamente:
  - em contexto SYSTEM/RMM (sem desktop);
  - quando o WPF não está disponível;
  - se a janela falhar ao abrir (o motivo vai para o log);
  - ou quando forçado com `$env:TRIVOR_UI = 'console'`.
- **`$env:TRIVOR_BRANCH`:** permite testar uma branch antes do merge. O nome é validado contra injeção de comando, e a branch é repassada na reelevação via UAC.
- O resumo do console também passa a avisar o reinício pendente após a renomeação do hostname feita pela interface.

### Adicionado — proteções contra erro do analista (console e interface)

O Trivor Installer é de uso **sob demanda**: pelo terminal remoto (menu de console) ou na tela da máquina (interface gráfica). Ele não deve ser usado como tarefa agendada do RMM.

- **Cliente sugerido:**
  - O instalador identifica o cliente da máquina pelo prefixo do hostname (ex.: `FMC-8H2K93L` → FMCSV) e o sugere: no console basta Enter; na interface aparece um botão "Abrir cliente detectado".
  - Só sugere quando **um único** cliente corresponde. Nunca adivinha.
  - Novos campos opcionais no JSON do cliente, `Domain` (domínio AD) e `EntraTenantId` (tenant do Entra ID), para identificar também clientes sem prefixo.
- **Alerta de divergência:** se o cliente escolhido não bate com a máquina (ou se mais de um cliente bate), é preciso **digitar o nome do cliente** para continuar. A decisão fica registrada no log como WARN.
- **Pós-Formatação em máquina já configurada:** com metade ou mais dos apps já instalados (mínimo 2), o instalador avisa e sugere o Compliance. Manter a Pós-Formatação fica registrado no log como WARN.
- **Resumo antes de executar:** cliente, modo, aplicativos e hostname (atual → esperado). Nada é executado sem confirmação.
- **Tempo-limite na primeira pergunta do console:** sem resposta em 10 minutos, ou com a entrada fechada (ninguém conectado), o script encerra **sem executar nada**, com código de saída 1. Evita que fique travado se for disparado sem terminal interativo.
- **Índice dos clientes:** os JSONs dos clientes passam a ser baixados **em paralelo** no início (cerca de 1 s nos testes, com os 42 clientes) e reaproveitados ao abrir cada cliente.
- **Novo módulo `core/Guard.ps1`.**

### Observações

- O item "Relatórios" aparece no menu como "em breve" e será entregue na Sprint 3.
- `Gui.ps1` é salvo em UTF-8 com BOM, para os acentos aparecerem corretamente no Windows PowerShell 5.1. Os demais módulos continuam em ASCII.

### Alterado

- User-Agent e versão de fallback atualizados para 3.5.0.

---

## v3.4.5 — Sprint 2: segurança

### Corrigido (vulnerabilidades)

- **Execução de código como SYSTEM via cache plantado.** Em contexto RMM/SYSTEM, a pasta de trabalho era `C:\Windows\Temp\TrivorInstaller`, com nome fixo, num local onde usuários comuns podem criar arquivos. Um usuário podia deixar ali, antes da execução, um instalador (ex.: `TakeControlAgent.exe`), um módulo `.ps1` ou um JSON de cliente, e o instalador executava ou carregava esse arquivo como SYSTEM.
  - O trabalho passa a ser feito em `C:\TrivorInstaller`, protegido (dono Administradores, sem herança, acesso só para SYSTEM e Administradores) antes de qualquer download. Se não for possível proteger a pasta, a execução é abortada.
  - Cada execução usa a própria subpasta `Sessao_<data>_<id>`, com módulos, JSONs de clientes, cache e saída do winget.
- **Exclusão arbitrária como SYSTEM via junction.** A limpeza fazia `Remove-Item -Recurse` no caminho fixo. Uma junction criada ali por um usuário comum levava o PowerShell 5.1 a apagar o conteúdo do destino. A remoção agora nunca segue links: junctions e symlinks são removidos sem tocar no destino.
- **`C:\TrivorInstaller` gravável por usuários comuns.** A pasta herdava de `C:\` permissão de modificação para Usuários Autenticados, o que permitia alterar ou ler logs (que contêm URLs de instalação dos clientes) e plantar junctions nos caminhos em que o SYSTEM grava.
  - A pasta e todo o conteúdo existente passam a ter dono Administradores, sem herança, com acesso apenas para SYSTEM e Administradores.
  - Links encontrados dentro dela são removidos antes da aplicação da ACL.
- **Winget via Scheduled Task:** cada chamada usa uma subpasta própria dentro de `Sessao_<data>_<id>\winget`. Somente o usuário logado (pelo SID) recebe permissão de Modificar, e apenas nessa subpasta.

### Adicionado

- **Pasta de trabalho única em `C:\TrivorInstaller`:**

  ```
  C:\TrivorInstaller\
    Logs\                        mantido
    Sessao_<data>_<id>\          arquivos desta execução, apagados ao final
  ```

  - No início, são apagadas as sessões que sobraram de execuções interrompidas e a pasta `Winget` legada da v3.4.4.
  - Execuções simultâneas (técnico + RMM) não interferem entre si: cada sessão fica bloqueada por um arquivo de lock exclusivo enquanto está ativa.
  - Ao final, a execução apaga a própria sessão. Só os logs permanecem.
- **Retenção de logs:** arquivos `.log` com mais de 90 dias são apagados automaticamente.
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
