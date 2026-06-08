# Investigação Real — Processo Anômalo no Terminal

**Data:** 07/06/2026  
**Analista:** Natan Almeida  
**Ambiente:** WSL Ubuntu (Natan)  
**Severidade:** Média  
**Status:** Investigado e encerrado

---

## Contexto

Durante monitoramento de rotina, um processo desconhecido foi identificado em execução no sistema. O processo `sleep 1000` foi localizado rodando em background sem interação visível do usuário — comportamento que em ambiente real pode indicar processo de espera para execução de payload, persistência ou comunicação agendada com infraestrutura externa.

---

## Fluxo de Investigação

### Etapa 1 — Identificar o processo suspeito

```bash
ps aux | grep sleep
```

**Output real:**
```
hp   762  0.0  0.0   3124  1848 pts/0    S    23:47   0:00 sleep 1000
hp   764  0.0  0.0   4088  2032 pts/0    S+   23:47   0:00 grep --color=auto sleep
```

**Análise campo a campo:**

| Campo | Valor | Significado |
|---|---|---|
| USER | hp | Processo rodando como usuário comum — não root |
| PID | 762 | Identificador único do processo |
| %CPU / %MEM | 0.0 / 0.0 | Consumo mínimo — processo em espera |
| TTY | pts/0 | Associado ao terminal atual |
| STAT | S | Sleeping — processo dormindo, aguardando evento |
| COMMAND | sleep 1000 | Comando executado — dormindo por 1000 segundos |

**Red flags analisadas:**
- Processo em `S` (sleeping) por longo período sem justificativa clara
- Em ambiente real, `sleep` com valor alto é técnica usada para manter processo vivo aguardando conexão ou evento externo
- PID 762 iniciado no mesmo terminal (`pts/0`) — rastreável

---

### Etapa 2 — Inspecionar arquivos e conexões abertas pelo processo

```bash
lsof -p 762
```

**Output real:**
```
COMMAND PID USER   FD   TYPE DEVICE SIZE/OFF  NODE NAME
sleep   762   hp  cwd    DIR   8,48     4096 10435 /home/hp/linux-fundamentals-soc
sleep   762   hp  rtd    DIR   8,48     4096     2 /
sleep   762   hp  txt    REG   8,48    35336  2030 /usr/bin/sleep
sleep   762   hp  mem    REG   8,48  2125328 12801 /usr/lib/x86_64-linux-gnu/libc.so.6
sleep   762   hp    0u   CHR  136,0      0t0     3 /dev/pts/0
sleep   762   hp    1u   CHR  136,0      0t0     3 /dev/pts/0
sleep   762   hp    2u   CHR  136,0      0t0     3 /dev/pts/0
```

**Análise campo a campo:**

| Campo | Significado |
|---|---|
| `cwd` | Diretório de trabalho atual — `/home/hp/linux-fundamentals-soc` |
| `rtd` | Diretório raiz do processo — `/` (normal) |
| `txt` | Binário executado — `/usr/bin/sleep` (legítimo) |
| `mem` | Bibliotecas carregadas em memória — `libc.so.6` (padrão) |
| `0u / 1u / 2u` | stdin, stdout, stderr — todos apontando para `/dev/pts/0` |

**Análise de segurança:**
- Nenhuma conexão de rede aberta — ausência de `IPv4` ou `IPv6` no output
- Binário executado é o `/usr/bin/sleep` legítimo — sem substituição maliciosa
- Diretório de trabalho em `/home/hp/linux-fundamentals-soc` — rastreável e esperado
- Em um processo malicioso real, o `lsof` frequentemente revela conexões ativas para IPs externos ou acesso a arquivos sensíveis como `/etc/passwd` ou `/etc/shadow`

---

### Etapa 3 — Mapear portas e serviços ativos no sistema

```bash
ss -tulnp
```

**Output real:**
```
Netid  State   Recv-Q  Send-Q  Local Address:Port    Peer Address:Port
udp    UNCONN  0       0       127.0.0.54:53         0.0.0.0:*
udp    UNCONN  0       0       127.0.0.53%lo:53      0.0.0.0:*
udp    UNCONN  0       0       127.0.0.1:323         0.0.0.0:*
tcp    LISTEN  0       4096    0.0.0.0:22            0.0.0.0:*
tcp    LISTEN  0       4096    127.0.0.54:53         0.0.0.0:*
tcp    LISTEN  0       4096    127.0.0.53%lo:53      0.0.0.0:*
tcp    LISTEN  0       4096    [::]:22               [::]:*
```

**Análise porta a porta:**

| Porta | Protocolo | Serviço | Avaliação |
|---|---|---|---|
| 53 (127.0.0.53) | UDP/TCP | DNS local (systemd-resolved) | Normal — resolução de nomes interna |
| 53 (127.0.0.54) | UDP/TCP | DNS secundário | Normal — fallback do systemd-resolved |
| 323 | UDP | Chronyd (NTP) | Normal — sincronização de horário |
| 22 | TCP | SSH | Atenção — porta aberta para todas as interfaces (`0.0.0.0`) |

**Ponto de atenção — SSH na porta 22:**
- SSH escutando em `0.0.0.0:22` significa que aceita conexões de qualquer interface de rede
- Em ambiente WSL para estudo isso é esperado — foi configurado nas aulas anteriores
- Em servidor de produção, SSH exposto em `0.0.0.0` sem restrição de IP de origem seria red flag — recomendaria revisão de firewall e uso de `AllowUsers` no `sshd_config`
- Nenhuma porta inesperada ou não autorizada identificada

---

### Etapa 4 — Correlacionar processo com porta

```bash
# Verificar se o processo 762 tem alguma conexão de rede
lsof -i -p 762
```

**Resultado:** nenhuma saída — processo `sleep` não possui conexão de rede ativa.

Em um cenário real de comprometimento, esse comando revelaria conexões ativas:
```
# Exemplo de output malicioso (simulado):
COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME
nc       991  root  3u  IPv4  12345   0t0       TCP   192.168.1.10:4444->203.0.113.5:80 (ESTABLISHED)
```

---

### Etapa 5 — Encerrar o processo

```bash
kill -9 762
```

**Verificação pós-encerramento:**
```bash
ps aux | grep sleep
```

**Output esperado:**
```
hp   800  0.0  0.0   4088  2032 pts/0  S+  23:52  0:00 grep --color=auto sleep
```

Apenas o `grep` aparece — processo 762 encerrado com sucesso.

---

## Relatório de Incidente

**Data:** 07/06/2026  
**Analista:** Natan Almeida  
**Severidade:** Média  
**Status:** Encerrado

| Campo | Detalhe |
|---|---|
| Tipo de incidente | Processo desconhecido em execução em background |
| Processo | `sleep 1000` — PID 762 |
| Usuário | hp (uid=1000) |
| Diretório de trabalho | `/home/hp/linux-fundamentals-soc` |
| Conexões de rede | Nenhuma identificada |
| Arquivos sensíveis acessados | Nenhum |
| Binário executado | `/usr/bin/sleep` — legítimo |
| Portas abertas no sistema | 22 (SSH), 53 (DNS local), 323 (NTP) |
| Ponto de atenção | SSH escutando em `0.0.0.0:22` — revisar necessidade de exposição |
| Ação tomada | Processo encerrado via `kill -9 762` |
| Escalonamento | Não necessário — processo benigno confirmado |

---

## Conclusão

O processo `sleep 1000` (PID 762) foi investigado e classificado como benigno. Nenhuma conexão de rede ativa, nenhum acesso a arquivo sensível e binário executado legítimo (`/usr/bin/sleep`).

O mapeamento de portas via `ss -tulnp` não revelou serviços não autorizados. Ponto de atenção registrado para SSH exposto em todas as interfaces — recomendado revisão em ambiente de produção.

Processo encerrado via `kill -9`. Nenhuma ação adicional necessária.
