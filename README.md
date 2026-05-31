# 🔐 Linux Fundamentals — SOC Lab

Laboratório prático de fundamentos Linux com foco em investigação forense e análise de segurança.  
Todos os exercícios foram realizados em ambiente real via **WSL (Ubuntu)**, simulando cenários de triagem SOC.

---

## 📂 Estrutura do repositório

```
linux-fundamentals-soc/
├── 01-permissions/
│   ├── README.md
│   ├── investigation-suid.md
│   └── incident-report-suid.md
├── 02-processes/
│   ├── README.md
│   └── process-investigation.md
├── reference/
│   └── soc-cheatsheet.pdf
└── README.md
```

---

## 🧪 Lab 01 — Investigação de Binário SUID Suspeito

### Contexto

Durante uma triagem de rotina, um binário com permissão **SUID** foi identificado em um diretório não padrão.  
Binários SUID executam com privilégios do proprietário (frequentemente `root`), independente de quem os executa — o que representa um vetor crítico de **escalada de privilégios**.

### Objetivo

Investigar o binário, determinar sua origem, comportamento e avaliar se representa uma ameaça real ao sistema.

---

### 🔍 Fluxo de investigação

#### Etapa 1 — Identificar binários SUID no sistema

```bash
find / -perm -4000 -type f 2>/dev/null
```

**O que faz:** varre todo o sistema em busca de arquivos com o bit SUID ativo.  
**Red flag:** binário encontrado fora de `/usr/bin` ou `/bin` — localização atípica é indicador imediato de suspeita.

---

#### Etapa 2 — Inspecionar permissões e metadados

```bash
ls -la /caminho/do/binario
stat /caminho/do/binario
```

**O que analisar:**
- Proprietário (`root`?)
- Data de modificação (recente e sem justificativa?)
- Permissões exatas (`-rwsr-xr-x` confirma SUID ativo)

---

#### Etapa 3 — Identificar tipo do arquivo

```bash
file /caminho/do/binario
```

**Por que importa:** distingue entre ELF executável legítimo, script disfarçado, ou arquivo corrompido.  
Um script `.sh` com SUID ativo é imediatamente suspeito — SUID em scripts é ignorado pelo kernel Linux, mas sua presença pode indicar tentativa de ofuscação.

---

#### Etapa 4 — Extrair strings legíveis

```bash
strings /caminho/do/binario
```

**O que procurar:**
- Comandos shell embutidos (`/bin/sh`, `bash`, `nc`, `curl`)
- IPs ou domínios hardcoded
- Mensagens de erro reveladoras
- Referências a outros arquivos ou usuários

---

#### Etapa 5 — Verificar processo em execução

```bash
ps aux | grep nome-do-binario
```

**O que analisar:**
- O binário está rodando? Com qual usuário?
- PPID (processo pai) — quem iniciou esse processo?
- Um processo rodando como `root` iniciado por usuário comum é red flag crítico

---

#### Etapa 6 — Verificar arquivos abertos pelo processo

```bash
lsof -p <PID>
```

**O que analisar:**
- Conexões de rede abertas (tipo `IPv4`, `IPv6`)
- Arquivos sensíveis acessados (`/etc/passwd`, `/etc/shadow`)
- Sockets suspeitos

---

#### Etapa 7 — Correlacionar com logs de autenticação

```bash
grep -i "nome-do-binario\|SUID\|su\|sudo" /var/log/auth.log
```

**O que procurar:**
- Tentativas de escalonamento de privilégio no horário de criação/modificação do binário
- Usuários executando `su` ou `sudo` de forma incomum
- Falhas de autenticação repetidas antes do evento

---

#### Etapa 8 — Gerar hash e verificar reputação

```bash
sha256sum /caminho/do/binario
md5sum /caminho/do/binario
```

Com o hash em mãos:
- Consultar no **VirusTotal** (virustotal.com)
- Comparar com hash esperado do binário legítimo (se aplicável)
- Hash não reconhecido + binário fora do padrão = escalar imediatamente

---

#### Etapa 9 — Contenção (se confirmado malicioso)

```bash
# Remover bit SUID sem apagar o arquivo (preserva evidência)
chmod -s /caminho/do/binario

# Encerrar processo se estiver em execução
kill -9 <PID>
```

> ⚠️ Em ambiente real de SOC, a contenção deve ser autorizada pelo analista sênior ou seguir o playbook do time antes de qualquer modificação no sistema.

---

### 📋 Relatório de Incidente

**Data:** [data do exercício]  
**Analista:** Natan Almeida  
**Severidade:** Alta  
**Status:** Contido

| Campo | Detalhe |
|---|---|
| Tipo de incidente | Binário SUID suspeito fora de diretório padrão |
| Localização | `/tmp/` ou diretório atípico |
| Proprietário | root |
| Processo ativo | Sim / Não |
| Conexões de rede | Sim / Não |
| Hash SHA256 | `[hash gerado]` |
| Resultado VirusTotal | Limpo / Detectado / Não encontrado |
| Ação tomada | `chmod -s` aplicado, processo encerrado, log preservado |
| Escalonamento | Sim / Não |

---

## 🧪 Lab 02 — Investigação de Processos Anômalos

### Contexto

Alerta gerado por volume incomum de processos ativos. Objetivo: identificar processo suspeito, correlacionar com porta aberta e determinar se há comunicação externa não autorizada.

### Fluxo de investigação

```bash
# Listar todos os processos com detalhes
ps aux

# Identificar processo pelo nome
ps aux | grep nome-suspeito

# Ver arquivos e conexões abertas pelo PID
lsof -p <PID>

# Correlacionar processo com porta
lsof -i :<porta>

# Confirmar conexão ativa
ss -tulnp | grep <PID>

# Verificar logs
grep <PID> /var/log/syslog
```

**Critérios de suspeita:**
- Processo rodando como `root` sem justificativa
- Conexão de saída para IP externo desconhecido
- Nome de processo imitando serviço legítimo (`systemd` vs `systemd-fake`)
- Processo sem TTY associado iniciado recentemente

---

## 📎 Referências utilizadas

- [Linux man pages](https://man7.org/linux/man-pages/)
- [GTFOBins — SUID exploitation reference](https://gtfobins.github.io/)
- [VirusTotal](https://www.virustotal.com)
- Trilha SOC Analyst Júnior (estudo estruturado com foco em Blue Team)

---

## 🛠️ Ambiente

| Item | Detalhe |
|---|---|
| OS | Ubuntu (WSL) |
| Shell | Bash |
| Contexto | Exercícios práticos de triagem SOC |

---

*Laboratório em evolução — novos exercícios adicionados conforme avanço na trilha.*
