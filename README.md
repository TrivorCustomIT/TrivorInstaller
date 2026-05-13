
Trivor Installer

     _______ _____  _______      ______  _____  
    |__   __|  __ \|_   _\ \    / / __ \|  __ \ 
       | |  | |__) | | |  \ \  / / |  | | |__) |
       | |  |  _  /  | |   \ \/ /| |  | |  _  / 
       | |  | | \ \ _| |_   \  / | |__| | | \ \ 
       |_|  |_|  \_\_____|   \/   \____/|_|  \_\


Aplicativo Desenvolvido para padronizar a instalação de Softwares e Aplicativos Gereciados

Foi pensado na dificuldade de se manter o parque de equipamentos tecnologicos sem um padrão, podendo
causar horas de retrabalho, além da instalação de softwares de gerenciamento e inventário, facilitando 
a gestão do parque tecnológico.

====================================================
     Developed by Fernando B. Oliveira                 
     GitHub: github.com/nandinhooliveira            
====================================================




V3.37

Nova opção no menu de cliente: Winget Upgrade --all

5 - Winget upgrade --all (atualizar todos os apps da maquina)
  └─ Exibe na tela todos os apps instalados com atualização disponível (winget upgrade)
  └─ Solicita confirmação antes de prosseguir
  └─ Executa winget upgrade --all e mostra o progresso em tempo real
  └─ Compatível com contexto RMM/SYSTEM (executa via Scheduled Task como usuário logado)

Ajuste no menu de cliente:
  └─ Opção 3 renomeada: "Update todos os programas do cliente (Winget)"
  └─ Opção 5 nova: "Winget upgrade --all (atualizar todos os apps da maquina)"
  └─ Opção 6: Voltar ao menu principal

====================================================

V3.36

====================================================

V3.32

Update Modo Manual

2 - Modo manual
  └─ Exibe grid com todos os apps do cliente
  └─ Técnico digita o número do app
  └─ Aparece o prompt [I] Install / [U] Update / [S] Skip / [Q] Quit
  └─ Volta pro grid para selecionar o próximo

