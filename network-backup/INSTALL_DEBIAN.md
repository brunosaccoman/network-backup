# Guia de Instalação - Debian 13 (Production)

## 📋 Pré-requisitos

- Debian 13 (ou superior)
- Acesso root ou sudo
- Conexão com internet
- Mínimo: 4GB RAM, 2 CPUs, 20GB disco
- Recomendado: 8GB RAM, 4 CPUs, 50GB+ disco (para 3000 devices)

---

## 🚀 Instalação Rápida (Docker - Recomendado)

### Passo 1: Atualizar Sistema

```bash
# Atualizar pacotes
sudo apt update && sudo apt upgrade -y

# Instalar dependências básicas
sudo apt install -y curl git vim wget
```

### Passo 2: Instalar Docker e Docker Compose

```bash
# Remover versões antigas (se existir)
sudo apt remove docker docker-engine docker.io containerd runc 2>/dev/null

# Instalar dependências do Docker
sudo apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Adicionar chave GPG oficial do Docker
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Adicionar repositório do Docker
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Atualizar índice de pacotes
sudo apt update

# Instalar Docker Engine
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Iniciar e habilitar Docker
sudo systemctl start docker
sudo systemctl enable docker

# Adicionar seu usuário ao grupo docker (evita usar sudo)
sudo usermod -aG docker $USER

# Verificar instalação
docker --version
docker compose version
```

**IMPORTANTE:** Após adicionar ao grupo docker, faça logout e login novamente para aplicar as permissões.

### Passo 3: Clonar o Repositório

```bash
# Ir para o diretório home
cd ~

# Clonar o repositório
git clone https://github.com/brunosaccoman/network-backup.git

# Entrar no diretório
cd network-backup/network-backup
```

### Passo 4: Configurar Variáveis de Ambiente

```bash
# Copiar arquivo de exemplo
cp .env.example .env

# Gerar chaves de criptografia
ENCRYPTION_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Editar arquivo .env
nano .env
```

**Configuração mínima do .env:**
```bash
# Segurança (GERAR NOVAS CHAVES!)
ENCRYPTION_KEY=<cole_a_chave_gerada>
SECRET_KEY=<cole_a_chave_diferente>

# Banco de Dados
DATABASE_URL=postgresql://backup_user:SENHA_FORTE_AQUI@postgres:5432/network_backup

# Ambiente
FLASK_ENV=production
DEBUG=False

# PostgreSQL (para docker-compose)
POSTGRES_PASSWORD=SENHA_FORTE_AQUI

# Sessão
SESSION_COOKIE_SECURE=True

# Backup
BACKUP_MAX_WORKERS=50
BACKUP_RETENTION_COUNT=5

# Timezone
TIMEZONE=America/Porto_Velho
```

**Para gerar as chaves:**
```bash
python3 -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
```

### Passo 5: Iniciar Containers Docker

```bash
# Subir os containers em background
docker compose up -d

# Verificar se subiram corretamente
docker compose ps

# Ver logs
docker compose logs -f app
```

### Passo 6: Aplicar Índices de Escalabilidade

```bash
# Aplicar índices no banco de dados
docker compose exec postgres psql -U backup_user -d network_backup <<'EOF'
CREATE INDEX IF NOT EXISTS idx_device_active_updated ON devices (active, updated_at);
CREATE INDEX IF NOT EXISTS idx_device_provedor ON devices (provedor);
CREATE INDEX IF NOT EXISTS idx_backup_device_date ON backups (device_id, backup_date);
CREATE INDEX IF NOT EXISTS idx_backup_status_date ON backups (status, backup_date);
EOF

# Verificar índices criados
docker compose exec postgres psql -U backup_user -d network_backup -c "SELECT indexname FROM pg_indexes WHERE tablename IN ('devices', 'backups') ORDER BY indexname;"
```

### Passo 7: Aplicar Migrações do Banco de Dados

```bash
# Executar migrações
docker compose exec app flask db upgrade

# Verificar se aplicou
docker compose exec app flask db current
```

### Passo 8: Criar Usuário Administrador

```bash
# Criar admin
docker compose exec app python manage.py create-admin

# Seguir os prompts:
# Username: admin
# Email: admin@sua-empresa.com
# Password: (senha forte)
```

### Passo 9: Verificar Sistema

```bash
# Verificar status dos containers
docker compose ps

# Deve mostrar:
# network-backup-app   Up (healthy)
# network-backup-db    Up (healthy)

# Verificar logs
docker compose logs app | grep "BackupManager inicializado"
# Deve mostrar: max_workers: 50

# Verificar conexões do banco
docker compose exec postgres psql -U backup_user -d network_backup -c "SELECT count(*) FROM pg_stat_activity;"
```

### Passo 10: Configurar Firewall

```bash
# Liberar porta 8000 (ou a porta que você configurou)
sudo ufw allow 8000/tcp

# Se usar UFW
sudo ufw enable
sudo ufw status
```

### Passo 11: Acessar o Sistema

**URL:** http://SEU_IP_SERVIDOR:8000

```bash
# Descobrir IP do servidor
ip addr show | grep "inet " | grep -v 127.0.0.1
```

---

## 🔒 Configuração com Nginx (Produção - Opcional)

### Instalar Nginx

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

### Configurar Nginx como Reverse Proxy

```bash
sudo nano /etc/nginx/sites-available/network-backup
```

**Conteúdo:**
```nginx
server {
    listen 80;
    server_name seu-dominio.com;  # Altere aqui

    client_max_body_size 16M;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts para backup de muitos devices
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
    }
}
```

**Ativar site:**
```bash
sudo ln -s /etc/nginx/sites-available/network-backup /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Configurar HTTPS com Let's Encrypt

```bash
sudo certbot --nginx -d seu-dominio.com
```

---

## 📊 Gerenciamento do Sistema

### Comandos Úteis

```bash
# Ver logs em tempo real
docker compose logs -f app

# Reiniciar aplicação
docker compose restart app

# Parar sistema
docker compose down

# Iniciar sistema
docker compose up -d

# Ver status
docker compose ps

# Executar comando no container
docker compose exec app python manage.py list-users

# Backup do banco de dados
docker compose exec postgres pg_dump -U backup_user network_backup > backup_$(date +%Y%m%d_%H%M%S).sql

# Restaurar backup
cat backup_XXXXXXXX_XXXXXX.sql | docker compose exec -T postgres psql -U backup_user network_backup
```

### Criar Serviço Systemd (Auto-start)

```bash
sudo nano /etc/systemd/system/network-backup.service
```

**Conteúdo:**
```ini
[Unit]
Description=Network Backup System
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/seu-usuario/network-backup/network-backup
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

**Ativar:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable network-backup.service
sudo systemctl start network-backup.service
sudo systemctl status network-backup.service
```

---

## 🔧 Troubleshooting

### Containers não sobem

```bash
# Ver logs detalhados
docker compose logs

# Verificar se portas estão em uso
sudo netstat -tulpn | grep :8000
sudo netstat -tulpn | grep :5432

# Remover containers e volumes antigos
docker compose down -v
docker compose up -d --build
```

### Erro de permissão

```bash
# Garantir permissões corretas
sudo chown -R $USER:$USER ~/network-backup
chmod +x ~/network-backup/network-backup/*.sh
```

### PostgreSQL não conecta

```bash
# Verificar logs do PostgreSQL
docker compose logs postgres

# Verificar se está rodando
docker compose exec postgres pg_isready -U backup_user

# Resetar senha (se necessário)
docker compose down
docker volume rm network-backup_postgres_data
docker compose up -d
```

### Performance lenta

```bash
# Verificar recursos
docker stats

# Aumentar workers (se tiver mais CPU/RAM)
nano .env
# BACKUP_MAX_WORKERS=75

docker compose restart app
```

---

## 📈 Monitoramento

### Verificar Performance

```bash
# CPU e Memória dos containers
docker stats

# Espaço em disco
df -h

# Conexões do PostgreSQL
docker compose exec postgres psql -U backup_user -d network_backup -c "SELECT count(*), state FROM pg_stat_activity GROUP BY state;"

# Tamanho do banco de dados
docker compose exec postgres psql -U backup_user -d network_backup -c "SELECT pg_size_pretty(pg_database_size('network_backup'));"
```

### Logs Estruturados

```bash
# Ver logs em JSON
docker compose logs app --tail 100 | grep '"level"'

# Filtrar apenas erros
docker compose logs app | grep '"level":"error"'

# Ver backups realizados
docker compose logs app | grep "Backup completed"
```

---

## 🔄 Atualização do Sistema

```bash
# Parar sistema
docker compose down

# Atualizar código
cd ~/network-backup
git pull origin NEXUSBACKUP

cd network-backup

# Reconstruir containers
docker compose up -d --build

# Aplicar migrações (se houver)
docker compose exec app flask db upgrade

# Verificar
docker compose ps
docker compose logs -f app
```

---

## 🗂️ Backup e Restore

### Backup Completo

```bash
#!/bin/bash
# Script de backup completo
BACKUP_DIR="/backup/network-backup"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup do banco de dados
docker compose exec postgres pg_dump -U backup_user network_backup > "$BACKUP_DIR/db_$DATE.sql"

# Backup dos arquivos de backup
tar -czf "$BACKUP_DIR/backups_$DATE.tar.gz" backups/

# Backup do .env (criptografado)
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" .env docker-compose.yml

echo "Backup completo criado em $BACKUP_DIR"
```

### Restore

```bash
# Restaurar banco de dados
cat backup_db_XXXXXXXX_XXXXXX.sql | docker compose exec -T postgres psql -U backup_user network_backup

# Restaurar arquivos de backup
tar -xzf backups_XXXXXXXX_XXXXXX.tar.gz
```

---

## ✅ Checklist de Instalação

- [ ] Docker instalado e rodando
- [ ] Repositório clonado
- [ ] .env configurado com chaves únicas
- [ ] Containers iniciados (docker compose up -d)
- [ ] Índices aplicados no banco
- [ ] Migrações aplicadas (flask db upgrade)
- [ ] Usuário admin criado
- [ ] Sistema acessível via navegador
- [ ] Firewall configurado
- [ ] Nginx configurado (opcional)
- [ ] HTTPS configurado (opcional)
- [ ] Systemd service criado (opcional)
- [ ] Script de backup configurado

---

## 📞 Suporte

- **Documentação**: Ver `ESCALABILIDADE.md` e `CLAUDE.md`
- **Logs**: `docker compose logs -f app`
- **GitHub**: https://github.com/brunosaccoman/network-backup

---

**Última atualização:** 2025-11-19
**Versão:** Fase 2 - Otimizado para 3000+ devices
**Branch:** NEXUSBACKUP
