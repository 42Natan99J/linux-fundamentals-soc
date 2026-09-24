# Script de Triagem de Logs — Evolução v1 → v5

Esse script nasceu como parte da minha trilha de estudos para SOC Analyst
Júnior, praticando Bash scripting aplicado a investigação de segurança.
Documento aqui a evolução para deixar claro o processo — não só o
resultado final.

## O problema que ele resolve

Dado um arquivo de log estruturado (`chave:valor,chave:valor,...`),
identificar quais valores se repetem além de um limite aceitável —
um padrão comum em triagem de brute force, port scan, ou qualquer
evento que "aparece demais" para ser normal.

## Evolução

| Versão | O que mudou |
|---|---|
| v1 | Script fixo — caminho do arquivo escrito direto no código |
| v2 | Parametrizado — recebe o arquivo via `$1`, com validação `-f` |
| v3 | Lógica extraída para função (`contar_ocorrencia`), com `local` |
| v4 | Validação de entrada explícita (`-z "$1"`, mensagem de uso, `exit`) |
| v5 | Termos extraídos dinamicamente para um **array**, iterados via `for` |

Cada versão corrigiu uma limitação real da anterior — não foi
planejado do zero, foi descoberto na prática (erros de sintaxe
inclusos, que também fizeram parte do aprendizado).

## Uso

```bash
./investigacao.sh <arquivo>
```

Exemplo de saída:

```
=== Investigacao de: acessos.txt ===

--- Verificacao individual ---
Total de termos unicos encontrados: 2

conexao: SUSPEITO (4 ocorrencias)
login: SUSPEITO (3 ocorrencias)
```
## Conceitos aplicados

- Pipelines (`cut`, `sort -u`, `grep -c`)
- Funções com escopo local (`local`)
- Arrays (`TERMOS=(...)`, `${TERMOS[@]}`, `${#TERMOS[@]}`)
- Validação de entrada e código de saída (`exit 0` / `exit 1`)
- Estruturas de controle (`for`, `if/else`)

## Limitações conhecidas (próximos passos)

- Threshold de "suspeito" (`-gt 2`) é fixo — poderia virar parâmetro
- Não trata arquivos com formato inconsistente entre linhas
- Próxima versão: aceitar o threshold como argumento (`$2`) e adicionar
  saída em formato JSON para integração com outras ferramentas
