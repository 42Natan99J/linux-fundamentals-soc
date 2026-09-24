#!/bin/bash

if [ -z "$1" ]
then
    echo "Uso: $0 <arquivo>"
    exit 1
fi

ARQUIVO=$1

contar_ocorrencia() {
    local palavra=$1
    local arquivo=$2
    local total=$(grep -c "$palavra" "$arquivo")
    if [ $total -gt 2 ]
    then
        echo "$palavra: SUSPEITO ($total ocorrencias)"
    else
        echo "$palavra: normal ($total ocorrencias)"
    fi
}

if [ -f $ARQUIVO ]
then
    echo "=== Investigacao de: $ARQUIVO ==="

    TERMOS=($(cut -d, -f1 "$ARQUIVO" | cut -d: -f2 | sort -u))

    echo "Total de termos unicos encontrados: ${#TERMOS[@]}"
    echo ""

    for termo in ${TERMOS[@]}
    do
        contar_ocorrencia "$termo" "$ARQUIVO"
    done
else
    echo "Erro: arquivo nao encontrado"
fi
