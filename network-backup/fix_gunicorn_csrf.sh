#!/bin/bash
# Script para corrigir problema de CSRF e lentidão
# Configura 2 workers com preload para melhor performance

set -e

echo "=== Corrigindo configuração do Gunicorn (CSRF/Performance) ==="

# Verificar se estamos no diretório correto
if [ ! -f "docker-compose.yml" ]; then
    echo "ERRO: docker-compose.yml não encontrado!"
    echo "Execute este script no diretório: /root/network-backup/network-backup"
    exit 1
fi

# Backup do .env
if [ -f ".env" ]; then
    cp .env .env.backup
    echo "✓ Backup criado: .env.backup"
fi

# Remover configurações antigas de GUNICORN se existirem
if [ -f ".env" ]; then
    sed -i '/GUNICORN_WORKERS/d' .env
    sed -i '/GUNICORN_PRELOAD/d' .env
fi

# Adicionar novas configurações
echo "" >> .env
echo "# Gunicorn - 2 workers com preload para performance e scheduler" >> .env
echo "GUNICORN_WORKERS=2" >> .env
echo "GUNICORN_PRELOAD=true" >> .env

echo "✓ Configurações adicionadas ao .env:"
grep GUNICORN .env

# Verificar se docker-compose.yml tem as variáveis de ambiente necessárias
if ! grep -q "GUNICORN_WORKERS" docker-compose.yml; then
    echo ""
    echo "⚠ GUNICORN_WORKERS não está no docker-compose.yml"
    echo "  Adicionando variável ao docker-compose.yml..."

    # Backup do docker-compose.yml
    cp docker-compose.yml docker-compose.yml.backup2

    # Adicionar após DEBUG: "False"
    sed -i '/DEBUG: "False"/a\      \n      # Gunicorn\n      GUNICORN_WORKERS: "${GUNICORN_WORKERS:-2}"\n      GUNICORN_PRELOAD: "${GUNICORN_PRELOAD:-true}"' docker-compose.yml

    echo "✓ Variáveis adicionadas ao docker-compose.yml"
fi

echo ""
echo "=== Reiniciando containers ==="
docker compose down
docker compose up -d

echo ""
echo "=== Aguardando inicialização (10s) ==="
sleep 10

echo ""
echo "=== Verificando configuração ==="

# Verificar variáveis no container
echo "Variáveis de ambiente:"
docker compose exec app printenv | grep -E "GUNICORN" || echo "  (não encontradas no container)"

# Verificar schedulers
SCHEDULER_COUNT=$(docker compose logs app 2>/dev/null | grep -c "Scheduler started" || echo "0")
echo ""
echo "Scheduler iniciado: $SCHEDULER_COUNT vez(es)"

# Testar acesso à página de login
echo ""
echo "Testando acesso à página de login..."
HTTP_CODE=$(docker compose exec app curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/auth/login 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Página de login acessível (HTTP $HTTP_CODE)"
else
    echo "⚠ Página de login retornou HTTP $HTTP_CODE"
fi

echo ""
echo "=== Concluído ==="
echo ""
echo "Agora teste no navegador:"
echo "1. Limpe os cookies do navegador (Ctrl+Shift+Delete)"
echo "2. Acesse: http://192.168.99.234:8000/auth/login"
echo ""
echo "Se ainda der erro de CSRF:"
echo "  - Abra em modo anônimo (Ctrl+Shift+N)"
echo "  - Ou use outro navegador"
