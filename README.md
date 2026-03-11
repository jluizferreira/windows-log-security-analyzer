# 🛡️ Windows Log Security Analyzer

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![Security](https://img.shields.io/badge/Focus-Security%20Analysis-red?logo=shield)](.)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> Ferramenta em Python para análise de logs de segurança do Windows.  
> Detecta padrões suspeitos como brute force, criação de usuários e falhas de autenticação.

---

## 📋 Índice

- [Sobre o Projeto](#-sobre-o-projeto)
- [Funcionalidades](#-funcionalidades)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Pré-requisitos](#-pré-requisitos)
- [Instalação](#-instalação)
- [Como Executar](#-como-executar)
- [Modo Demonstração](#-modo-demonstração)
- [Exemplos de Saída](#-exemplos-de-saída)
- [Eventos Monitorados](#-eventos-monitorados)
- [Tecnologias](#-tecnologias)
- [Autor](#-autor)

---

## 🎯 Sobre o Projeto

O **Windows Log Security Analyzer** é uma ferramenta de linha de comando desenvolvida em Python que lê eventos reais do **Windows Event Viewer** (Security Log) e os analisa em busca de atividades potencialmente maliciosas.

O projeto foi desenvolvido como parte de um portfólio profissional em **Segurança da Informação**, demonstrando habilidades em:

- Integração com APIs nativas do Windows via `pywin32`
- Análise e correlação de eventos de segurança
- Detecção de padrões de ataque (brute force)
- Organização de código em módulos Python

---

## ✨ Funcionalidades

| Funcionalidade | Descrição |
|---|---|
| 📥 Leitura de eventos | Lê até N eventos do Security Event Log em tempo real |
| 🔐 Análise de logins | Conta logins bem-sucedidos e falhados por usuário |
| 🚨 Detecção de Brute Force | Identifica muitas falhas num curto intervalo de tempo |
| 👤 Gestão de usuários | Detecta criação e exclusão de contas (4720 / 4726) |
| 📊 Score de risco | Calcula um índice de risco geral (0–100) |
| 📋 Relatório no terminal | Exibe relatório formatado e colorido no console |
| 🎭 Modo Demo | Simula cenários de ataque sem precisar de permissão Admin |

---

## 📁 Estrutura do Projeto

```
windows-log-security-analyzer/
│
├── analyzer/
│   ├── __init__.py            # Exportações do pacote
│   ├── event_reader.py        # Leitura do Windows Event Log via pywin32
│   ├── login_analyzer.py      # Análise de eventos 4624 / 4625
│   ├── suspicious_detector.py # Detecção de brute force e gestão de usuários
│   └── demo_generator.py      # Gerador de eventos simulados (modo --demo)
│
├── main.py                    # Ponto de entrada — orquestra a análise
├── requirements.txt           # Dependências do projeto
└── README.md                  # Este arquivo
```

---

## 📦 Pré-requisitos

- **Sistema Operacional:** Windows 10 / Windows 11 / Windows Server
- **Python:** 3.12 ou superior
- **Permissões:** Execução como **Administrador** (necessário para acessar o Security Log)

---

## 🚀 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/windows-log-security-analyzer.git
cd windows-log-security-analyzer
```

### 2. (Opcional) Crie um ambiente virtual

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Instale as dependências

```bash
pip install -r requirements.txt
```

> ⚠️ A biblioteca `pywin32` só funciona no **Windows**. A instalação em Linux/macOS falhará.

---

## ▶️ Como Executar

> **Importante:** Execute o terminal como **Administrador**.

### Execução padrão (lê até 5000 eventos)

```bash
python main.py
```

### Limitar o número de eventos lidos

```bash
python main.py --max-events 1000
```

### Ver ajuda

```bash
python main.py --help
```

---

## 🎭 Modo Demonstração

Não precisa de permissão de Administrador e funciona em qualquer máquina.  
Simula um cenário realista de ataque com eventos fictícios.

```bash
python main.py --demo
```

> 💡 **Para desativar o modo demo** e analisar seu sistema real, basta executar `python main.py` sem a flag `--demo`.  
> Lembre-se de abrir o terminal como **Administrador**.

### Cenários simulados

| Cenário | Detalhes |
|---|---|
| Logins normais | 5 usuários com 10–30 logins bem-sucedidos |
| Falhas esporádicas | `joao.silva` errou a senha 3x antes de conseguir |
| **Brute force #1** | 14 tentativas contra `administrator` em 3 min (IP: `203.0.113.47`) |
| **Brute force #2** | 8 tentativas contra `backup_service` em 2 min (IP: `198.51.100.23`) |
| Usuário suspeito criado | `hacker_temp01` criado às 03h da manhã por `administrator` |
| Usuário deletado | `carlos.santos` deletado por `administrator` |

### Saída do modo demo

```
╔══════════════════════════════════════════════════════════════╗
║        Windows Log Security Analyzer  v1.0                  ║
║        Detecção de atividades suspeitas via Event Log        ║
╚══════════════════════════════════════════════════════════════╝

  Análise iniciada em: 11/03/2026 01:45:00

  ╔══════════════════════════════════════════════════════════════╗
  ║   ⚠️   MODO DEMONSTRAÇÃO ATIVO  —  DADOS SIMULADOS   ⚠️     ║
  ║                                                              ║
  ║  Os eventos abaixo são FICTÍCIOS e gerados localmente.       ║
  ║  Para analisar seu sistema real, execute sem --demo.         ║
  ╚══════════════════════════════════════════════════════════════╝

  [*] Gerando eventos simulados de ataque...
  [✓] 138 eventos simulados gerados.

────────────────────────────────────────────────────────────────
  📊  RESUMO GERAL
────────────────────────────────────────────────────────────────
  Total de eventos relevantes lidos : 138
  Logins bem-sucedidos (ID 4624)    : 97
  Falhas de login (ID 4625)         : 38
  Usuários criados (ID 4720)        : 1
  Usuários deletados (ID 4726)      : 1

────────────────────────────────────────────────────────────────
  ❌  TOP USUÁRIOS COM MAIS FALHAS DE LOGIN
────────────────────────────────────────────────────────────────
  Usuário                        Tentativas
  ────────────────────────────── ──────────
  administrator                          14 ⚠️
  backup_service                          8 ⚠️
  joao.silva                              3
  maria.souza                             1

────────────────────────────────────────────────────────────────
  🚨  ALERTAS DE POSSÍVEL BRUTE FORCE
────────────────────────────────────────────────────────────────

  ┌─────────────────────────────────────────────────────┐
  │                  [ALERT] BRUTE FORCE                │
  ├─────────────────────────────────────────────────────┤
  │  Usuário          : administrator                   │
  │  Tentativas falhas: 14                              │
  │  Janela de tempo  : 5 minutos                       │
  │  Início da janela : 11/03/2026 00:45:00             │
  │  Fim da janela    : 11/03/2026 00:50:00             │
  │  Total de falhas  : 14                              │
  └─────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────┐
  │                  [ALERT] BRUTE FORCE                │
  ├─────────────────────────────────────────────────────┤
  │  Usuário          : backup_service                  │
  │  Tentativas falhas: 8                               │
  │  Janela de tempo  : 5 minutos                       │
  │  Início da janela : 11/03/2026 01:15:00             │
  │  Fim da janela    : 11/03/2026 01:20:00             │
  │  Total de falhas  : 8                               │
  └─────────────────────────────────────────────────────┘

────────────────────────────────────────────────────────────────
  👤  CRIAÇÃO E EXCLUSÃO DE USUÁRIOS
────────────────────────────────────────────────────────────────

  ✅ Usuários CRIADOS (1 evento(s)):
  Usuário                   Criado por                Data/Hora
  ───────────────────────── ───────────────────────── ────────────────────
  hacker_temp01             administrator             03/11/2026 03:25:00

  🗑️  Usuários DELETADOS (1 evento(s)):
  Usuário                   Deletado por              Data/Hora
  ───────────────────────── ───────────────────────── ────────────────────
  carlos.santos             administrator             03/11/2026 01:30:00

────────────────────────────────────────────────────────────────
  🎯  SCORE DE RISCO GERAL
────────────────────────────────────────────────────────────────

  [████████████████░░░░] 75/100

  Nível de risco: CRITICAL 🔴

  ════════════════════════════════════════════════════════════════
  Relatório concluído em: 11/03/2026 01:45:03
  ════════════════════════════════════════════════════════════════
```

---

## 🖥️ Exemplos de Saída

```
╔══════════════════════════════════════════════════════════════╗
║        Windows Log Security Analyzer  v1.0                  ║
║        Detecção de atividades suspeitas via Event Log        ║
╚══════════════════════════════════════════════════════════════╝

  Análise iniciada em: 11/03/2025 14:35:02
  ────────────────────────────────────────────────────────────────

  [*] Lendo até 5000 eventos do Security Event Log...
  [✓] 342 eventos relevantes carregados.

  [*] Analisando eventos de login...
  [*] Verificando padrões de brute force...
  [*] Verificando criação/exclusão de usuários...

────────────────────────────────────────────────────────────────
  📊  RESUMO GERAL
────────────────────────────────────────────────────────────────
  Total de eventos relevantes lidos : 342
  Logins bem-sucedidos (ID 4624)    : 287
  Falhas de login (ID 4625)         : 53
  Usuários criados (ID 4720)        : 1
  Usuários deletados (ID 4726)      : 0

────────────────────────────────────────────────────────────────
  ❌  TOP USUÁRIOS COM MAIS FALHAS DE LOGIN
────────────────────────────────────────────────────────────────
  Usuário                        Tentativas
  ────────────────────────────── ──────────
  administrator                          12 ⚠️
  john.doe                                8 ⚠️
  guest                                   5
  maria.silva                             3

────────────────────────────────────────────────────────────────
  🚨  ALERTAS DE POSSÍVEL BRUTE FORCE
────────────────────────────────────────────────────────────────

  ┌─────────────────────────────────────────────────────┐
  │                  [ALERT] BRUTE FORCE                │
  ├─────────────────────────────────────────────────────┤
  │  Usuário          : administrator                   │
  │  Tentativas falhas: 12                              │
  │  Janela de tempo  : 5 minutos                       │
  │  Início da janela : 11/03/2025 14:12:30             │
  │  Fim da janela    : 11/03/2025 14:17:30             │
  │  Total de falhas  : 12                              │
  └─────────────────────────────────────────────────────┘

────────────────────────────────────────────────────────────────
  👤  CRIAÇÃO E EXCLUSÃO DE USUÁRIOS
────────────────────────────────────────────────────────────────

  ✅ Usuários CRIADOS (1 evento(s)):
  Usuário                   Criado por                Data/Hora
  ───────────────────────── ───────────────────────── ────────────────────
  testuser01                DESKTOP\admin             03/11/2025 09:15:42

────────────────────────────────────────────────────────────────
  🎯  SCORE DE RISCO GERAL
────────────────────────────────────────────────────────────────

  [████████░░░░░░░░░░░░] 40/100

  Nível de risco: HIGH 🟠

  ════════════════════════════════════════════════════════════════
  Relatório concluído em: 11/03/2025 14:35:05
  ════════════════════════════════════════════════════════════════
```

---

## 📌 Eventos Monitorados

| Event ID | Descrição |
|---|---|
| **4624** | Login bem-sucedido |
| **4625** | Falha de login |
| **4720** | Nova conta de usuário criada |
| **4726** | Conta de usuário deletada |

---

## 🛠️ Tecnologias

| Tecnologia | Uso |
|---|---|
| **Python 3.12** | Linguagem principal |
| **pywin32** | Acesso ao Windows Event Log |
| **win32evtlog** | Leitura dos eventos de segurança |
| **collections** | Estruturas de dados para análise |
| **datetime** | Manipulação de janelas de tempo |
| **argparse** | Interface de linha de comando |

---

## 🔒 Permissões Necessárias

O Security Event Log do Windows é restrito. Para executar a ferramenta:

1. Clique com botão direito no **Prompt de Comando** ou **PowerShell**
2. Selecione **"Executar como Administrador"**
3. Navegue até a pasta do projeto e execute `python main.py`

---

## 👤 Autor

**Jefferson Ferreira**  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Jefferson--Ferreira-blue?logo=linkedin)](https://www.linkedin.com/in/jefferson-ferreira-ti/)
[![GitHub](https://img.shields.io/badge/GitHub-jluizferreira-black?logo=github)](https://github.com/jluizferreira)

---

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
