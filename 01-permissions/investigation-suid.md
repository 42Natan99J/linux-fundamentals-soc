# Investigação Real — Binário SUID Suspeito

**Data:** 07/06/2026  
**Analista:** Natan Almeida  
**Ambiente:** WSL Ubuntu (Natan)  
**Severidade:** Alta  
**Status:** Contido  

---

## Contexto

Durante verificação de rotina, um binário com permissão SUID foi identificado em `/tmp/` — diretório atípico para executáveis privilegiados. O binário se chamava `sys_check`, nome que imita nomenclatura de processo legítimo de sistema para dificultar detecção.

---

## Fluxo de Investigação

### Etapa 1 — Identificar permissões e metadados

```bash
ls -la /tmp/sys_check
```

**Output real:**
```
-rwsr-xr-x 1 hp hp 142312 Jun  7 22:59 /tmp/sys_check
```

**Análise:**  
O `s` na posição do `x` do proprietário confirma o bit SUID ativo (`-rwsr-xr-x`).  
Red flag imediata: binário com SUID fora de `/usr/bin` ou `/bin` é atípico e exige investigação.

---

### Etapa 2 — Inspecionar metadados completos

```bash
stat /tmp/sys_check
```

**Output real:**
```
File: /tmp/sys_check
Size: 142312          Blocks: 280        IO Block: 4096   regular file
Device: 8,48    Inode: 1977        Links: 1
Access: (4755/-rwsr-xr-x)  Uid: ( 1000/      hp)   Gid: ( 1000/      hp)
Access: 2026-06-07 22:59:49.694506586 -0300
Modify: 2026-06-07 22:59:49.694506586 -0300
Change: 2026-06-07 23:00:19.394029275 -0300
Birth:  2026-06-07 22:59:49.694506586 -0300
```

**Análise:**  
- Código octal `4755` — o `4` confirma SUID ativo  
- Timestamps de criação e modificação idênticos: binário criado hoje, sem histórico no sistema  
- Binários legítimos do sistema têm data de instalação do OS — um arquivo recém-criado em `/tmp/` com SUID é red flag crítica

---

### Etapa 3 — Identificar tipo do arquivo

```bash
file /tmp/sys_check
```

**Output real:**
```
/tmp/sys_check: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=05dad2c279f7651722809fa75adba6bf9ab1c209, for GNU/Linux 3.2.0, stripped
```

**Análise:**  
- `setuid` confirmado explicitamente pelo comando `file`  
- ELF 64-bit legítimo — não é script disfarçado, é executável real  
- `stripped`: símbolos de debug removidos, dificulta análise estática  
- `dynamically linked`: depende de bibliotecas externas em tempo de execução

---

### Etapa 4 — Extrair strings legíveis

```bash
strings /tmp/sys_check | head -20
```

**Output real:**
```
/lib64/ld-linux-x86-64.so.2
__libc_start_main
__cxa_finalize
__cxa_atexit
strcmp
obstack_alloc_failed_handler
stdout
__overflow
fwrite_unlocked
fputs_unlocked
__printf_chk
__mempcpy_chk
nl_langinfo
strchr
__ctype_b_loc
strlen
__ctype_get_mb_cur_max
mbstowcs
malloc
__mbstowcs_chk
```

**Análise:**  
Strings indicam funções padrão de manipulação de strings e I/O — perfil consistente com o binário `ls` original.  
Ausência de strings maliciosas como `/bin/sh`, `nc`, `curl` ou IPs hardcoded.  
Em um binário malicioso real, essa etapa frequentemente revela o comportamento do payload.

---

### Etapa 5 — Verificar processo em execução

```bash
ps aux | grep sys_check
```

**Output real:**
```
hp   680  0.0  0.0   4092  2040 pts/0    S+   23:10   0:00 grep --color=auto sys_check
```

**Análise:**  
Nenhum processo `sys_check` em execução — apenas o próprio `grep` aparece.  
O binário existe no sistema mas não está rodando ativamente no momento da investigação.  
Em um cenário de comprometimento real, um processo ativo com conexão de rede seria o indicador mais crítico.

---

### Etapa 6 — Correlacionar com auth.log

```bash
grep "sys_check\|SUID\|sudo\|su " /var/log/auth.log 2>/dev/null
```

**Output relevante:**
```
2026-06-07T23:00:19 Natan sudo: hp : TTY=pts/0 ; PWD=/home/hp ; USER=root ; COMMAND=/usr/bin/chmod u+s /tmp/sys_check
2026-06-07T23:00:19 Natan sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)
2026-06-07T23:00:19 Natan sudo: pam_unix(sudo:session): session closed for user root
```

**Análise — ponto crítico:**  
O auth.log registrou exatamente o momento em que o SUID foi aplicado ao binário.  
`COMMAND=/usr/bin/chmod u+s /tmp/sys_check` — evidência direta da ação privilegiada.  
Em um cenário real, esse log seria a prova de que houve elevação de privilégio não autorizada: um usuário comum (`uid=1000`) executou `sudo` para modificar um binário em `/tmp/`.  
Sessão root aberta e fechada em menos de 1 segundo — ação cirúrgica, sem interação adicional.

---

### Etapa 7 — Gerar hash e verificar reputação

```bash
sha256sum /tmp/sys_check
```

**Output real:**
```
0148f5ab3062a905281d8deb9645363da5131011c9e7b6dcaa38b504e41b68ea  /tmp/sys_check
```

**Análise:**  
Hash gerado e consultado no VirusTotal.  
Por ser uma cópia modificada do binário `ls` original (com SUID aplicado), o hash difere do binário legítimo — o que em um ambiente real já justificaria escalonamento imediato para análise mais profunda.

---

### Etapa 8 — Contenção

```bash
# Remover bit SUID sem apagar o arquivo (preserva evidência)
sudo chmod -s /tmp/sys_check

# Confirmar contenção
ls -la /tmp/sys_check
```

**Output esperado após contenção:**
```
-rwxr-xr-x 1 hp hp 142312 Jun  7 22:59 /tmp/sys_check
```

O `s` desaparece — SUID removido. Arquivo preservado para análise forense posterior.

---

## Relatório de Incidente

**Data:** 07/06/2026  
**Analista:** Natan Almeida  
**Severidade:** Alta  
**Status:** Contido

| Campo | Detalhe |
|---|---|
| Tipo de incidente | Binário SUID suspeito fora de diretório padrão |
| Localização | `/tmp/sys_check` |
| Proprietário | hp (uid=1000) |
| Processo ativo | Não |
| Conexões de rede | Não identificadas |
| Hash SHA256 | `0148f5ab3062a905281d8deb9645363da5131011c9e7b6dcaa38b504e41b68ea` |
| Resultado VirusTotal | Hash não reconhecido — binário modificado localmente |
| Evidência no auth.log | `chmod u+s` executado via sudo em 2026-06-07T23:00:19 |
| Ação tomada | `chmod -s` aplicado, SUID removido, arquivo preservado |
| Escalonamento | Recomendado para análise forense do binário original |

---

## Conclusão

O binário `sys_check` foi identificado como cópia do executável `/bin/ls` com bit SUID aplicado manualmente via `sudo`. Localizado em `/tmp/` — diretório de escrita universal — representa vetor potencial de escalada de privilégios caso o proprietário fosse `root`.

O auth.log forneceu evidência direta da ação: registro preciso do comando `chmod u+s` executado com privilégios root, com timestamp e usuário identificados.

Contenção realizada com remoção do SUID. Binário preservado para análise forense.
