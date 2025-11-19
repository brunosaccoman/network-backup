# 🚀 Guia de Deploy para Produção

## Checklist Pré-Deploy

Antes de colocar em produção, certifique-se de ter:

- [ ] Servidor Linux (Ubuntu 20.04+ recomendado)
- [ ] PostgreSQL 12+ instalado e configurado
- [ ] Domínio (opcional, mas recomendado)
- [ ] Certificado SSL (Let's Encrypt gratuito)
- [ ] Acesso root/sudo ao servidor

---

## PASSO 1: Preparar o Servidor

### 1.1 Atualizar Sistema

```bash
sudo apt update && sudo apt upgrade -y
```

### 1.2 Instalar Dependências do Sistema

```bash
# Python e ferramentas
sudo apt install -y python3 python3-pip python3-venv

# PostgreSQL
sudo apt install -y postgresql postgresql-contrib libpq-dev

# Nginx (reverse proxy)
sudo apt install -y nginx

# Supervisor (gerenciador de processos)
sudo apt install -y supervisor

# Git (para deploy)
sudo apt install -y git

# Certbot (SSL gratuito)
sudo apt install -y certbot python3-certbot-nginx
```

---

## PASSO 2: Configurar PostgreSQL

### 2.1 Criar Usuário e Banco

```bash
# Acessar PostgreSQL
sudo -u postgres psql

# No psql, executar:
```

```sql
-- Criar usuário
CREATE USER backup_prod WITH PASSWORD 'SUA_SENHA_FORTE_AQUI_32_CARACTERES';

-- Criar banco
CREATE DATABASE network_backup_prod OWNER backup_prod;

-- Dar permissões
GRANT ALL PRIVILEGES ON DATABASE network_backup_prod TO backup_prod;

-- Sair
\q
```

### 2.2 Configurar PostgreSQL para Aceitar Conexões

```bash
# Editar pg_hba.conf
sudo nano /etc/postgresql/14/main/pg_hba.conf

# Adicionar linha (substitua 14 pela sua versão):
# local   network_backup_prod   backup_prod   md5

# Reiniciar PostgreSQL
sudo systemctl restart postgresql
```

### 2.3 Testar Conexão

```bash
psql -U backup_prod -d network_backup_prod -h localhost
# Deve pedir senha e conectar
```

---

## PASSO 3: Deploy da Aplicação

### 3.1 Criar Usuário de Deploy

```bash
# Criar usuário (não usar root)
sudo adduser backup-app
sudo usermod -aG sudo backup-app

# Trocar para o usuário
sudo su - backup-app
```

### 3.2 Fazer Deploy do Código

**Opção A: Via Git (Recomendado)**

```bash
cd /home/backup-app
git clone <seu-repositorio> network-backup
cd network-backup
```

**Opção B: Via SCP/SFTP**

```bash
# No seu computador local:
cd "C:\Users\Bruno\Documents\Pojeto de Backup"
scp -r network-backup backup-app@seu-servidor.com:/home/backup-app/
```

### 3.3 Criar Ambiente Virtual

```bash
cd /home/backup-app/network-backup
python3 -m venv venv
source venv/bin/activate
```

### 3.4 Instalar Dependências

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## PASSO 4: Configurar Ambiente

### 4.1 Criar Arquivo .env de Produção

```bash
cd /home/backup-app/network-backup
nano .env
```

**Conteúdo do .env (PRODUÇÃO):**

```env
# ============================================================================
# PRODUÇÃO - Network Backup System
# ============================================================================

# Ambiente
FLASK_ENV=production
DEBUG=False

# Segurança - GERE NOVAS CHAVES!
# python -c "import secrets; print(secrets.token_urlsafe(32))"
ENCRYPTION_KEY=GERE_UMA_CHAVE_FORTE_AQUI_32_CHARS
SECRET_KEY=GERE_OUTRA_CHAVE_FORTE_AQUI_32_CHARS

# Database
DATABASE_URL=postgresql://backup_prod:SUA_SENHA_FORTE_AQUI@localhost:5432/network_backup_prod
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20

# Sessão (HTTPS obrigatório em produção)
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
SESSION_PERMANENT_LIFETIME=7

# SSL/TLS
SSL_VERIFY=True
FORCE_HTTPS=True

# Backup
BACKUP_DIR=/home/backup-app/network-backup/backups
BACKUP_RETENTION_COUNT=10

# Rate Limiting
RATELIMIT_DEFAULT=100/minute
RATELIMIT_STORAGE_URL=memory://

# Timezone
TIMEZONE=America/Porto_Velho

# Logging
LOG_LEVEL=INFO
LOG_DIR=/home/backup-app/network-backup/logs
```

### 4.2 Gerar Chaves

```bash
# Gerar ENCRYPTION_KEY
python3 -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"

# Gerar SECRET_KEY
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"

# Copiar e colar no .env
```

### 4.3 Proteger .env

```bash
chmod 600 .env
```

---

## PASSO 5: Inicializar Banco de Dados

```bash
source venv/bin/activate

# Inicializar migrations
flask db init

# Criar primeira migration
flask db migrate -m "Initial production migration"

# Aplicar migrations
flask db upgrade

# Criar usuário admin
python manage.py create-admin
# Username: admin
# Email: admin@sua-empresa.com
# Password: <senha_forte_12+_caracteres>
```

---

## PASSO 6: Configurar Gunicorn

### 6.1 Criar Arquivo de Configuração

```bash
nano /home/backup-app/network-backup/gunicorn_config.py
```

**Conteúdo:**

```python
import multiprocessing

# Bind
bind = "127.0.0.1:8000"

# Workers
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Timeout
timeout = 120
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = "/home/backup-app/network-backup/logs/gunicorn-access.log"
errorlog = "/home/backup-app/network-backup/logs/gunicorn-error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "network-backup"

# Server mechanics
daemon = False
pidfile = "/home/backup-app/network-backup/gunicorn.pid"
```

### 6.2 Testar Gunicorn

```bash
source venv/bin/activate
gunicorn -c gunicorn_config.py app:app

# Se funcionar, Ctrl+C para parar
```

---

## PASSO 7: Configurar Supervisor

### 7.1 Criar Arquivo de Configuração

```bash
sudo nano /etc/supervisor/conf.d/network-backup.conf
```

**Conteúdo:**

```ini
[program:network-backup]
command=/home/backup-app/network-backup/venv/bin/gunicorn -c gunicorn_config.py app:app
directory=/home/backup-app/network-backup
user=backup-app
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/home/backup-app/network-backup/logs/supervisor.log
stderr_logfile=/home/backup-app/network-backup/logs/supervisor-error.log
environment=PATH="/home/backup-app/network-backup/venv/bin"
```

### 7.2 Ativar e Iniciar

```bash
# Recarregar configuração
sudo supervisorctl reread
sudo supervisorctl update

# Iniciar aplicação
sudo supervisorctl start network-backup

# Verificar status
sudo supervisorctl status network-backup
```

---

## PASSO 8: Configurar Nginx (Reverse Proxy)

### 8.1 Criar Configuração do Site

```bash
sudo nano /etc/nginx/sites-available/network-backup
```

**Conteúdo (SEM SSL inicialmente):**

```nginx
server {
    listen 80;
    server_name seu-dominio.com www.seu-dominio.com;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 120s;
    }

    location /static {
        alias /home/backup-app/network-backup/static;
        expires 30d;
    }

    access_log /var/log/nginx/network-backup-access.log;
    error_log /var/log/nginx/network-backup-error.log;
}
```

### 8.2 Ativar Site

```bash
# Criar symlink
sudo ln -s /etc/nginx/sites-available/network-backup /etc/nginx/sites-enabled/

# Remover site default
sudo rm /etc/nginx/sites-enabled/default

# Testar configuração
sudo nginx -t

# Reiniciar Nginx
sudo systemctl restart nginx
```

---

## PASSO 9: Configurar SSL (HTTPS)

### 9.1 Obter Certificado Let's Encrypt

```bash
# Parar Nginx temporariamente
sudo systemctl stop nginx

# Obter certificado
sudo certbot certonly --standalone -d seu-dominio.com -d www.seu-dominio.com

# Seguir instruções (fornecer email, aceitar termos)
```

### 9.2 Atualizar Configuração Nginx com SSL

```bash
sudo nano /etc/nginx/sites-available/network-backup
```

**Conteúdo COMPLETO (COM SSL):**

```nginx
# Redirecionar HTTP para HTTPS
server {
    listen 80;
    server_name seu-dominio.com www.seu-dominio.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS
server {
    listen 443 ssl http2;
    server_name seu-dominio.com www.seu-dominio.com;

    # Certificados SSL
    ssl_certificate /etc/letsencrypt/live/seu-dominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/seu-dominio.com/privkey.pem;

    # SSL Configuration (Mozilla Intermediate)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 120s;
    }

    location /static {
        alias /home/backup-app/network-backup/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    access_log /var/log/nginx/network-backup-access.log;
    error_log /var/log/nginx/network-backup-error.log;
}
```

### 9.3 Aplicar e Testar

```bash
# Testar configuração
sudo nginx -t

# Reiniciar Nginx
sudo systemctl restart nginx
```

### 9.4 Configurar Renovação Automática

```bash
# Testar renovação
sudo certbot renew --dry-run

# Certificados serão renovados automaticamente pelo cron
```

---

## PASSO 10: Configurar Firewall

```bash
# Permitir SSH
sudo ufw allow OpenSSH

# Permitir HTTP e HTTPS
sudo ufw allow 'Nginx Full'

# Ativar firewall
sudo ufw enable

# Verificar status
sudo ufw status
```

---

## PASSO 11: Configurar Backups do PostgreSQL

### 11.1 Criar Script de Backup

```bash
sudo nano /usr/local/bin/backup-postgres.sh
```

**Conteúdo:**

```bash
#!/bin/bash
BACKUP_DIR="/home/backup-app/postgres-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/network_backup_prod_$DATE.sql.gz"

mkdir -p $BACKUP_DIR

# Fazer backup
pg_dump -U backup_prod -h localhost network_backup_prod | gzip > $BACKUP_FILE

# Manter apenas últimos 30 backups
ls -t $BACKUP_DIR/*.sql.gz | tail -n +31 | xargs rm -f

echo "Backup criado: $BACKUP_FILE"
```

### 11.2 Tornar Executável

```bash
sudo chmod +x /usr/local/bin/backup-postgres.sh
```

### 11.3 Configurar Cron (Backup Diário)

```bash
sudo crontab -e

# Adicionar linha (backup diário às 3h da manhã):
0 3 * * * /usr/local/bin/backup-postgres.sh >> /var/log/postgres-backup.log 2>&1
```

---

## PASSO 12: Monitoramento e Logs

### 12.1 Ver Logs da Aplicação

```bash
# Logs do Supervisor
tail -f /home/backup-app/network-backup/logs/supervisor.log

# Logs do Gunicorn
tail -f /home/backup-app/network-backup/logs/gunicorn-error.log

# Logs do Nginx
sudo tail -f /var/log/nginx/network-backup-error.log
```

### 12.2 Ver Status dos Serviços

```bash
# Aplicação
sudo supervisorctl status network-backup

# Nginx
sudo systemctl status nginx

# PostgreSQL
sudo systemctl status postgresql
```

### 12.3 Restart de Serviços

```bash
# Reiniciar aplicação
sudo supervisorctl restart network-backup

# Reiniciar Nginx
sudo systemctl restart nginx

# Reiniciar PostgreSQL
sudo systemctl restart postgresql
```

---

## PASSO 13: Comandos Úteis de Manutenção

### Atualizar Aplicação

```bash
cd /home/backup-app/network-backup
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
flask db upgrade
sudo supervisorctl restart network-backup
```

### Criar Novo Usuário

```bash
cd /home/backup-app/network-backup
source venv/bin/activate
python manage.py create-user
```

### Ver Logs de Auditoria

```bash
# Conectar ao PostgreSQL
psql -U backup_prod -d network_backup_prod -h localhost

# Ver últimas ações
SELECT
    u.username,
    al.action,
    al.resource_type,
    al.timestamp
FROM audit_logs al
JOIN users u ON al.user_id = u.id
ORDER BY al.timestamp DESC
LIMIT 20;
```

---

## ✅ CHECKLIST FINAL DE SEGURANÇA

Antes de considerar pronto para produção:

- [ ] PostgreSQL com senha forte
- [ ] `.env` com chaves únicas e fortes
- [ ] `DEBUG=False` no `.env`
- [ ] SSL/HTTPS configurado e funcionando
- [ ] Firewall ativo (apenas portas 22, 80, 443)
- [ ] Backup automático do PostgreSQL configurado
- [ ] Certificado SSL válido e renovação automática
- [ ] Usuário admin criado com senha forte (12+ caracteres)
- [ ] Logs sendo salvos corretamente
- [ ] Aplicação acessível via HTTPS
- [ ] Login funcionando
- [ ] Backup manual testado
- [ ] Rate limiting ativo
- [ ] Headers de segurança configurados no Nginx

---

## 🎯 ACESSO PÓS-DEPLOY

Após completar todos os passos:

1. **URL**: https://seu-dominio.com
2. **Login**: admin / <senha_que_você_criou>
3. **Primeiro acesso**:
   - Criar operadores adicionais
   - Recadastrar devices com senhas (se migrou do SQLite)
   - Testar backup manual
   - Configurar schedules

---

## 🆘 TROUBLESHOOTING

### Erro 502 Bad Gateway

```bash
# Verificar se Gunicorn está rodando
sudo supervisorctl status network-backup

# Ver logs
tail -f /home/backup-app/network-backup/logs/supervisor.log
```

### Erro de conexão com PostgreSQL

```bash
# Testar conexão
psql -U backup_prod -d network_backup_prod -h localhost

# Verificar pg_hba.conf
sudo cat /etc/postgresql/14/main/pg_hba.conf
```

### Certificado SSL não funciona

```bash
# Verificar certificados
sudo certbot certificates

# Renovar manualmente
sudo certbot renew
```

---

## 📞 SUPORTE

- Logs da aplicação: `/home/backup-app/network-backup/logs/`
- Logs do Nginx: `/var/log/nginx/`
- Logs do PostgreSQL: `/var/log/postgresql/`

---

**Deploy preparado para produção! 🚀**

Última atualização: 2025-01-18
