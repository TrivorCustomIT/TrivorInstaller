
Trivor Installer

     _______ _____  _______      ______  _____  
    |__   __|  __ \|_   _\ \    / / __ \|  __ \ 
       | |  | |__) | | |  \ \  / / |  | | |__) |
       | |  |  _  /  | |   \ \/ /| |  | |  _  / 
       | |  | | \ \ _| |_   \  / | |__| | | \ \ 
       |_|  |_|  \_\_____|   \/   \____/|_|  \_\


Aplicativo desenvolvido para padronizar a instalação de softwares e aplicativos gerenciados.

Foi pensado na dificuldade de manter o parque de equipamentos tecnológicos em um padrão, o que pode
causar horas de retrabalho, além de facilitar a instalação de softwares de gerenciamento e inventário
e a gestão do parque tecnológico.

====================================================
     Developed by Fernando B. Oliveira
     GitHub: github.com/nandinhooliveira
====================================================


Como executar
-------------

Em um PowerShell aberto como Administrador:

    irm https://raw.githubusercontent.com/TrivorCustomIT/TrivorInstaller/main/Install.ps1 | iex

- Com um técnico logado na máquina, abre a **interface gráfica** (WPF).
- Em contexto SYSTEM/RMM, ou se o WPF não estiver disponível, usa o **menu de console**.
- Para forçar o console: `$env:TRIVOR_UI = 'console'` antes do comando.
- Para testar uma branch antes do merge (nunca em produção):

      $env:TRIVOR_BRANCH = 'nome-da-branch'
      irm https://raw.githubusercontent.com/TrivorCustomIT/TrivorInstaller/nome-da-branch/Install.ps1 | iex

Os arquivos ficam em `C:\TrivorInstaller` (logs mantidos por 90 dias; os arquivos de cada execução
são apagados ao final).

O Trivor Installer é de uso **sob demanda** (terminal remoto ou na tela da máquina). **Não use como
tarefa agendada do RMM**: sem ninguém respondendo, ele encerra em até 10 minutos sem executar nada
(código de saída 1).


Proteções contra erro do analista
---------------------------------

- O cliente da máquina é **sugerido** pelo prefixo do hostname (ex.: `FMC-8H2K93L` → FMCSV).
- Se o cliente escolhido não bater com a máquina, é preciso **digitar o nome do cliente** para continuar.
- Pós-Formatação em máquina que já parece configurada gera um aviso, com a sugestão de usar o Compliance.
- Antes de executar, aparece um **resumo**: cliente, modo, aplicativos e hostname.

Para identificar também clientes sem prefixo de hostname, informe no JSON do cliente:

    "Domain": "empresa.local",
    "EntraTenantId": "00000000-0000-0000-0000-000000000000"


Remoção de apps do Windows
--------------------------

A Pós-Formatação e o Compliance removem apps do Windows (Appx/MSIX) sem uso corporativo, conforme
[`Padrao/RemoverAppsWindows.json`](Padrao/RemoverAppsWindows.json):

- **Pós-Formatação:** todos os itens de `Remover`, para todos os usuários, inclusive o pacote provisionado
  (o app não volta em perfis novos).
- **Compliance:** só os itens com `"Compliance"` em `Modos` (jogos, Xbox, consumo e apps descontinuados).
- `NuncaRemover` sempre tem prioridade. O `Id` é o nome do pacote Appx e aceita curinga (`*`).
- Um app que não pôde ser removido conta como falha da sessão.

Para incluir ou retirar um app, edite o JSON; não é preciso mudar o código.


Histórico de versões
--------------------

Todas as alterações de cada versão estão em [CHANGELOG.md](CHANGELOG.md).


Configuração opcional por app (JSON do cliente)
-----------------------------------------------

Instaladores EXE/MSI (`RepoExePublic` e `UrlExe`) são considerados bem-sucedidos com os exit codes
`0`, `3010` e `1641`. Para instaladores que usam outros códigos de sucesso, informe-os em
`Install.SuccessExitCodes`:

    "Install": {
      "Method": "UrlExe",
      "Url": "https://...",
      "SilentArgs": "/silent",
      "SuccessExitCodes": [0, 1]
    }

Instaladores sem `Sha256` só são executados se tiverem assinatura digital válida (Authenticode).
Para exigir também um fabricante específico, informe a organização do certificado (campo O=) em
`Install.Signer`:

    "Install": {
      "Method": "UrlExe",
      "Url": "https://api.us0.swi-rc.com/download/getpcinstall.php?iid=...",
      "Signer": "N-ABLE TECHNOLOGIES LTD",
      "SilentArgs": "/silent"
    }

Quando o `Sha256` é informado, ele tem prioridade e a assinatura não é verificada.

Instaladores MSI baixados de uma URL oficial usam o método `UrlMsi`. Ele sempre exige
`Install.Signer` e assinatura digital válida, e executa `msiexec /i` com `SilentArgs`
(padrão: `/qn /norestart`):

    "Install": {
      "Method": "UrlMsi",
      "Url": "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi",
      "Signer": "Google LLC",
      "CleanAfterInstall": true
    }

Apps instalados via winget podem ter um instalador reserva em `Fallback` (mesmo formato de
`Install`). Ele só é usado na instalação, quando o winget falha porque o hash do instalador não
confere com o manifesto (`0x8A150011`). Hoje o Google Chrome usa o MSI enterprise como reserva.

Falhas passageiras (arquivo em uso `0x80070020`/`0x8A150103`, outra instalação em andamento
`1618`/`0x80070652`/`0x8A150102`) são repetidas automaticamente uma vez, após 30 segundos, tanto
no winget quanto nos instaladores EXE/MSI.
