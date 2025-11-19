#!/bin/bash
#
# Script de Instalação Automatizada - Network Backup System
# Para Debian 13 / Ubuntu 22.04+
#
# Uso: curl -fsSL https://raw.githubusercontent.com/brunosaccoman/network-backup/NEXUSBACKUP/network-backup/install.sh | bash
#

set -e

echo "========================================="
echo "  Network Backup System - Instalação"
echo "========================================="
echo ""

# Verificar se é root
if [ "$EUID" -eq 0 ]; then
    echo "[AVISO] Não execute como root. Use seu usuário normal."
    echo "O script pedirá sudo quando necessário."
    exit 1
fi

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função de log
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERRO]${NC} $1"
}

# Verificar sistema operacional
log_info "Verificando sistema operacional..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
    log_info "Sistema detectado: $PRETTY_NAME"
else
    log_error "Sistema operacional não suportado"
    exit 1
fi

# Atualizar sistema
log_info "Atualizando pacotes do sistema..."
sudo apt update
sudo apt upgrade -y

# Instalar dependências básicas
log_info "Instalando dependências básicas..."
sudo apt install -y curl git vim wget python3 ca-certificates gnupg lsb-release

# Verificar se Docker já está instalado
if command -v docker &> /dev/null; then
    log_info "Docker já está instalado: $(docker --version)"
else
    log_info "Instalando Docker..."

    # Remover versões antigas
    sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

    # Adicionar chave GPG do Docker
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$OS/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    # Adicionar repositório
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Instalar Docker
    sudo apt update
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    # Iniciar Docker
    sudo systemctl start docker
    sudo systemctl enable docker

    # Adicionar usuário ao grupo docker
    sudo usermod -aG docker $USER

    log_info "Docker instalado com sucesso!"
fi

# Verificar Docker Compose
if docker compose version &> /dev/null; then
    log_info "Docker Compose já está instalado: $(docker compose version)"
else
    log_error "Docker Compose não encontrado. Instale manualmente."
    exit 1
fi

# Clonar repositório
log_info "Clonando repositório do GitHub..."
cd ~
if [ -d "network-backup" ]; then
    log_warn "Diretório network-backup já existe"
    read -p "Deseja fazer pull das atualizações? (s/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        cd network-backup
        git pull origin NEXUSBACKUP
    fi
else
    git clone -b NEXUSBACKUP https://github.com/brunosaccoman/network-backup.git
fi

cd network-backup/network-backup

# Configurar .env
log_info "Configurando variáveis de ambiente..."
if [ ! -f .env ]; then
    cp .env.example .env

    # Gerar chaves
    ENCRYPTION_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")

    # Atualizar .env
    sed -i "s/SUBSTITUA_COM_CHAVE_SEGURA_GERADA/$ENCRYPTION_KEY/g" .env
    sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/g" .env
    sed -i "s/backup_password_CHANGE_ME/$POSTGRES_PASSWORD/g" .env
    sed -i "s/FLASK_ENV=development/FLASK_ENV=production/g" .env
    sed -i "s/DEBUG=True/DEBUG=False/g" .env
    sed -i "s/SESSION_COOKIE_SECURE=False/SESSION_COOKIE_SECURE=True/g" .env

    log_info "Arquivo .env criado com chaves únicas!"
else
    log_warn "Arquivo .env já existe. Não foi modificado."
fi

# Iniciar containers
log_info "Iniciando containers Docker..."
docker compose up -d

# Aguardar PostgreSQL ficar pronto
log_info "Aguardando PostgreSQL inicializar..."
sleep 10

# Aplicar migrações
log_info "Aplicando migrações do banco de dados..."
docker compose exec -T app flask db upgrade || log_warn "Migrações podem já estar aplicadas"

# Aplicar índices de escalabilidade
log_info "Aplicando índices de escalabilidade..."
docker compose exec -T postgres psql -U backup_user -d network_backup <<'EOF'
CREATE INDEX IF NOT EXISTS idx_device_active_updated ON devices (active, updated_at);
CREATE INDEX IF NOT EXISTS idx_device_provedor ON devices (provedor);
CREATE INDEX IF NOT EXISTS idx_backup_device_date ON backups (device_id, backup_date);
CREATE INDEX IF NOT EXISTS idx_backup_status_date ON backups (status, backup_date);
EOF

log_info "Índices aplicados com sucesso!"

# Verificar status
log_info "Verificando status dos containers..."
docker compose ps

# Obter IP do servidor
SERVER_IP=$(ip addr show | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | head -n1)

echo ""
echo "========================================="
echo "  Instalação Concluída com Sucesso!"
echo "========================================="
echo ""
log_info "Sistema instalado e rodando!"
echo ""
echo "Próximos passos:"
echo ""
echo "1. Criar usuário administrador:"
echo "   docker compose exec app python manage.py create-admin"
echo ""
echo "2. Acessar o sistema:"
echo "   http://$SERVER_IP:8000"
echo ""
echo "3. Configurar firewall (se necessário):"
echo "   sudo ufw allow 8000/tcp"
echo ""
echo "4. Ver logs:"
echo "   docker compose logs -f app"
echo ""
echo "5. Configurar Nginx (opcional):"
echo "   Ver INSTALL_DEBIAN.md seção 'Configuração com Nginx'"
echo ""
log_warn "IMPORTANTE: Se foi adicionado ao grupo docker, faça logout/login para aplicar permissões"
echo ""
echo "Documentação completa: ~/network-backup/network-backup/INSTALL_DEBIAN.md"
echo ""
