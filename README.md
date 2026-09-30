
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
