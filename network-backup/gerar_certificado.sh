#!/bin/bash
# Script para gerar certificado SSL auto-assinado
# Execute: chmod +x gerar_certificado.sh && ./gerar_certificado.sh

set -e

# Criar diretório para certificados
mkdir -p ssl

# Gerar chave privada e certificado
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ssl/nginx.key \
    -out ssl/nginx.crt \
    -subj "/C=BR/ST=RO/L=Porto Velho/O=Network Backup/CN=network-backup"

# Ajustar permissões
chmod 600 ssl/nginx.key
chmod 644 ssl/nginx.crt

echo ""
echo "============================================"
echo " Certificado SSL gerado com sucesso!"
echo "============================================"
echo ""
echo " Arquivos criados:"
echo "   - ssl/nginx.key (chave privada)"
echo "   - ssl/nginx.crt (certificado)"
echo ""
echo " Validade: 365 dias"
echo ""
echo " Próximo passo:"
echo "   docker compose up -d"
echo ""
