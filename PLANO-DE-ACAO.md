# Plano de ação — Trivor Installer

Documento vivo com o estado do projeto, os testes pendentes e **todas as decisões de arquitetura em aberto**.
Atualizado a cada etapa. Última atualização: 30/10/2026.

> Para retomar: peça "mostre as decisões pendentes" e este arquivo é a referência.
> Para responder às decisões, use os códigos (ex.: **D1-A, D2-junto, D3-ok**).

---

## 1. Onde estamos

| Item | Situação |
|---|---|
| Produção (`main`) | v3.5.2 — interface gráfica WPF, proteções contra erro do analista, nova tentativa automática e MSI reserva do Chrome |
| Versões publicadas desde a v3.4.3 | v3.4.4 (bugs), v3.4.5 (segurança), v3.5.0 (interface), v3.5.1 (correções do 1º uso), v3.5.2 |
| Validação no Windows | `Validar-Sprint2-Windows.ps1`: 30 OK · `Validar-v3.5.2-Windows.ps1`: 21 OK · interface e Compliance testados em máquina real (TRV-PE0F7Q77) sem erros |
| Testes automatizados | Perdidos junto com o scratchpad da sessão; voltam versionados em `tests/` na Sprint 3 |

---

## 2. Testes que ainda faltam

Em uma máquina de **teste**, Windows PowerShell **como Administrador**:

```powershell
irm https://raw.githubusercontent.com/TrivorCustomIT/TrivorInstaller/main/Install.ps1 | iex
```

Já validado em 30/10/2026: a janela abre maximizada, o cliente é detectado pelo hostname, a escolha de outro cliente
exige confirmação, o Compliance roda sem erros, e o log mostra a versão e os acentos corretos.

### T1. Interface gráfica (técnico na tela)
- [ ] A janela abre com o logo e a lista de clientes; a busca filtra
- [x] Em máquina com hostname de cliente (ex.: `FMC-...`), aparece "Cliente detectado" e o botão abre o cliente
- [x] Escolher **outro** cliente pede para digitar o nome; com nome errado, não abre
- [x] Ao abrir um cliente, o status dos apps aparece em alguns segundos
- [ ] **Instalar selecionados** (1 ou 2 apps): o progresso e o log andam ao vivo, a janela não congela e o resumo aparece no final
- [ ] **Pós-Formatação** em máquina já configurada mostra o aviso de Compliance
- [ ] Antes de cada execução aparece o resumo (cliente, modo, apps, hostname)
- [ ] **Upgrade geral** lista as atualizações
- [ ] **Logs** e **Sobre** abrem
- [ ] Se a janela não abrir: o instalador cai no console; procurar no log a linha `Falha na interface grafica` e me enviar

### T2. Menu de console
- [ ] Com `$env:TRIVOR_UI = 'console'` o menu antigo aparece, com a sugestão de cliente (`Enter = ...`)
- [ ] Resumo antes de executar (S/N) e aviso de Pós-Formatação funcionando

### T3. Terminal remoto do N-sight (segundo plano, como SYSTEM)
- [ ] O menu de console abre (não a janela) e responde à digitação normalmente
- [ ] O tempo-limite não atrapalha: responda à primeira pergunta em menos de 10 minutos

### T4. Via RMM com **usuário comum** logado (de preferência máquina Entra ID)
- [ ] Rodar Compliance ou Update de um cliente; os apps winget devem atualizar
- [ ] No log em `C:\TrivorInstaller\Logs`, **não** pode aparecer `SID do usuario logado nao resolvido`
      (se aparecer, me envie o trecho: a correção é pequena)

**Ainda não testado:** Pós-Formatação em máquina limpa, aviso de Pós-Formatação, Upgrade geral executando, T2, T3 e T4.

**O que me enviar:** o resultado de cada item (OK/falha) e, nas falhas, o trecho do log.

---

## 3. Decisões de arquitetura pendentes

### Bloco A — decidir quando voltar (Fase 1: JSON padrão)

Hoje cada cliente repete os mesmos apps. Dados reais: 7-Zip, Firefox e Chrome estão em 42/42 clientes,
Adobe Reader em 40/42 e Zoom em 38/42, sempre com definição idêntica. 27 clientes têm **apenas** esses 5.

| Código | Decisão | Opções | Recomendação |
|---|---|---|---|
| **D1** | Modelo | **A)** `_Padrao.json` + JSON do cliente só com os apps específicos · **B)** perfis combináveis (`"Perfis": [...]`) · **C)** manter como está | **A** |
| **D2** | Quando | **junto** desta Sprint (antes do merge) · **depois** do merge (1º item da Sprint 3) | Depende dos testes: se já começou, **depois** |
| **D3** | Campo para excluir um app do padrão | `IgnorarPadrao` · outro nome | `IgnorarPadrao` |
| **D4** | Id do Kaspersky (hoje `Kaspersky`, `kaspersky` e `` `kaspersky` ``) | padronizar como `kaspersky` · manter | padronizar |

Garantia na conversão: um teste compara, cliente por cliente, a lista final de apps antes e depois, com **zero diferença**.

### Bloco B — Sprint 3 (qualidade e relatório)

| Código | Decisão | Opções | Recomendação |
|---|---|---|---|
| **D5** | Aprovações no PR da `main` | **0** (o CI é a trava; você faz o merge do seu próprio PR) · **1** (outra pessoa aprova) | 0, se você trabalha sozinho |
| **D6** | Pasta dos relatórios da máquina | **`C:\TrivorInstaller\Relatorios`** sem expiração · dentro de **`Logs`** (90 dias) | `Relatorios` |
| **D7** | Ativar a regra "merge só via PR com CI verde" | sim, após o CI existir · não | sim (você aplica nas configurações do GitHub; eu passo o passo a passo) |
| **D8** | Itens do checklist manual | lista de vocês (em desenvolvimento) | aguardando |

### Bloco C — Fase 2: remover apps do Windows (Appx) no padrão

Roda só na Pós-Formatação e na ação "Limpeza de fábrica" (nunca no Compliance), com uma lista fixa de nunca
remover (Store, App Installer/winget, Segurança do Windows, Teams corporativo `MSTeams`, Portal da Empresa,
bibliotecas do sistema). A primeira versão roda em **modo simulação**.

| Código | App | Opções | Sugestão |
|---|---|---|---|
| **D9** | Xbox / Game Bar | remover · manter | decisão sua (a Game Bar também grava a tela) |
| **D10** | Clima / Notícias | remover · manter | remover |
| **D11** | Teams pessoal (`MicrosoftTeams`) | remover · manter | remover |
| **D12** | Outlook novo / Mail | remover · manter | conforme o uso dos clientes |
| — | OneDrive | — | **manter** (M365 corporativo) |
| **D13** | Demais itens da lista inicial (Candy Crush, Solitaire, Spotify, Clipchamp, Feedback Hub, Dicas, Obter Ajuda) | aprovar · ajustar | aprovar |

### Bloco D — Fase 3: remover apps de fábrica (Win32)

| Código | Decisão | Por quê |
|---|---|---|
| **D14** | Fabricantes do parque (Dell, Lenovo, HP, Positivo...) | Cada um traz apps diferentes; alguns são úteis (atualização de drivers) |
| **D15** | Algum cliente usa McAfee/Trellix **corporativo**? | Para proteger com `IgnorarPadrao` e nunca remover por engano |
| **D16** | Ordem: remover o antivírus de fábrica antes de instalar o Kaspersky | sim · não (sugestão: sim) |

O McAfee de fábrica normalmente não tem desinstalação silenciosa (provavelmente vai exigir a ferramenta oficial MCPR).
Será testado em máquina real, um fabricante por vez.

### Bloco E — Sprint 4: distribuição segura dos instaladores

O repositório `TrivorInstallerRepository` é **público**: qualquer pessoa consegue baixar os agentes RMM (8 clientes),
as configurações de VPN (2) e outros EXEs (5). Os links do Take Control (12) e do Kaspersky (3) estão nos JSONs públicos.

| Código | Decisão | Opções | Recomendação |
|---|---|---|---|
| **D17** | Modelo de distribuição | **A)** repositório privado + token só de leitura · **B)** Azure Blob privado + links temporários · **C)** intermediário (Azure Function) que entrega só o instalador pedido | **C** |
| **D18** | Vocês têm Azure (ou outra nuvem)? | sim · não | — |
| **D19** | RMM e API (N-sight, endpoint que gera o instalador por cliente) | informar | — |
| **D20** | Trocar os tokens/links de instalação já expostos | sim · não | sim (medida imediata, independente de código) |

### Bloco F — itens menores

| Código | Decisão |
|---|---|
| **D21** | `O=` do certificado do Kaspersky e do FortiClient, para fixar o assinante (o comando está no histórico; rodar numa máquina com os instaladores) |
| **D22** | Ajustes de layout da interface após o T1 (pode comentar direto no mockup do canvas) |
| **D23** | 3 clientes apontam para o instalador do agente de outro cliente (Prospectiva SP → Trivor, ANK → Abrael, Arapyau → FMCSV). O painel está correto: corrigir os JSONs para cada um usar o próprio instalador, ou manter? |

### Já decidido (registro)

| Tema | Decisão |
|---|---|
| Interface | WPF, fonte Segoe UI, identidade visual do trivor.com.br |
| Execução | Sob demanda (terminal remoto ou na tela). **Sem tarefas agendadas do N-sight** |
| Proteções | Opção 2 (cliente sugerido, alerta de divergência, aviso de Pós-Formatação, resumo) + tempo-limite de 10 min |
| Pasta de trabalho | `C:\TrivorInstaller\Sessao_*`, logs mantidos por 90 dias |
| Versões | Padrão `vMAIOR.MENOR.BUG` |
| Plugin oh-my-claudecode | Não instalar no projeto |
| Agentes RMM no painel | Verificados por você: sem máquinas em cliente errado |

---

## 4. Roadmap

| Etapa | Conteúdo | Depende de |
|---|---|---|
| **Agora** | Testes restantes da seção 2 (Pós-Formatação limpa, T2–T4) | Você |
| Fase 1 | JSON padrão | D1–D4 |
| Sprint 3 | CI no GitHub Actions (Windows), JSON Schema, regra da `main`, relatório da máquina, checklist | D5–D8 |
| Fase 2 | Remoção de apps do Windows (simulação → ligado) | D9–D13 |
| Fase 3 | Remoção de apps de fábrica | D14–D16 |
| Sprint 4 | Distribuição segura dos instaladores | D17–D20 |

---

## 5. Limitações conhecidas (para os testes)

- A interface WPF nunca foi aberta num Windows real: estrutura, lógica e processamento em segundo plano foram testados, o desenho na tela não. Se falhar, o instalador cai no console.
- A detecção do cliente funciona hoje só para os **11 clientes com prefixo de hostname**, em máquinas já renomeadas. Os campos `Domain` e `EntraTenantId` ampliam isso.
- No RMM com usuário comum, ainda não confirmei a conversão do SID para contas do Entra ID (T4).
- O comportamento do terminal remoto do N-sight com o tempo-limite não pôde ser reproduzido fora do N-sight (T3).
