#!/bin/bash
# Script para adicionar GUNICORN_WORKERS=1 no docker-compose.yml
# Isso corrige o problema do scheduler iniciando múltiplas vezes

set -e

echo "=== Corrigindo configuração do Gunicorn ==="

# Verificar se estamos no diretório correto
if [ ! -f "docker-compose.yml" ]; then
    echo "ERRO: docker-compose.yml não encontrado!"
    echo "Execute este script no diretório: /root/network-backup/network-backup"
    exit 1
fi

# Backup do arquivo original
cp docker-compose.yml docker-compose.yml.backup
echo "✓ Backup criado: docker-compose.yml.backup"

# Verificar se já existe GUNICORN_WORKERS
if grep -q "GUNICORN_WORKERS" docker-compose.yml; then
    echo "⚠ GUNICORN_WORKERS já existe no docker-compose.yml"
    grep "GUNICORN_WORKERS" docker-compose.yml
    exit 0
fi

# Adicionar GUNICORN_WORKERS após DEBUG: "False"
sed -i '/DEBUG: "False"/a\      \n      # Gunicorn - 1 worker para scheduler funcionar corretamente\n      GUNICORN_WORKERS: "1"' docker-compose.yml

# Verificar se foi adicionado
if grep -q "GUNICORN_WORKERS" docker-compose.yml; then
    echo "✓ GUNICORN_WORKERS adicionado com sucesso!"
    grep -A1 "GUNICORN_WORKERS" docker-compose.yml
else
    echo "✗ Falha ao adicionar GUNICORN_WORKERS"
    echo "Restaurando backup..."
    mv docker-compose.yml.backup docker-compose.yml
    exit 1
fi

echo ""
echo "=== Reiniciando containers ==="
docker compose down
docker compose up -d

echo ""
echo "=== Verificando configuração ==="
sleep 5

# Verificar se a variável está no container
WORKERS=$(docker compose exec app printenv GUNICORN_WORKERS 2>/dev/null || echo "")
if [ "$WORKERS" = "1" ]; then
    echo "✓ GUNICORN_WORKERS=1 aplicado no container"
else
    echo "⚠ Verificando variável no container..."
    docker compose exec app printenv | grep -i gunicorn || echo "Variável não encontrada"
fi

# Verificar quantidade de schedulers
SCHEDULER_COUNT=$(docker compose logs app 2>/dev/null | grep -c "Scheduler started" || echo "0")
echo "✓ Scheduler iniciado $SCHEDULER_COUNT vez(es)"

if [ "$SCHEDULER_COUNT" -eq "1" ]; then
    echo ""
    echo "🎉 Sucesso! Scheduler configurado corretamente."
else
    echo ""
    echo "⚠ Scheduler pode ter iniciado múltiplas vezes. Verifique os logs:"
    echo "  docker compose logs app | grep -i scheduler"
fi

echo ""
echo "=== Concluído ==="
echo "Para verificar os jobs agendados:"
echo "  docker compose exec app python check_scheduler.py"
