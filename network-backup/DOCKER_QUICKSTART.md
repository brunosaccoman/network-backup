# 🐳 Docker Quick Start - Network Backup System

Deploy rápido e fácil usando Docker Compose.

---

## 🚀 OPÇÃO MAIS RÁPIDA (5 minutos)

### 1. Gerar Chaves de Segurança

```bash
# No diretório network-backup/
python -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))" > .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env
python -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(32))" >> .env
```

### 2. Iniciar Serviços

```bash
docker-compose up -d
```

### 3. Aguardar Inicialização (30-60 segundos)

```bash
# Ver logs
docker-compose logs -f app

# Aguardar mensagem: "Banco de dados inicializado"
```

### 4. Criar Administrador

```bash
docker-compose exec app python manage.py create-admin

# Seguir prompts:
# Username: admin
# Email: admin@empresa.com
# Password: ******
```

### 5. Acessar

**URL**: http://localhost:8000
**Login**: admin / <senha_criada>

**Pronto! Sistema funcionando! 🎉**

---

## 📋 COMANDOS ÚTEIS

### Gerenciamento de Containers

```bash
# Iniciar todos os serviços
docker-compose up -d

# Parar todos os serviços
docker-compose down

# Ver logs em tempo real
docker-compose logs -f

# Ver logs de um serviço específico
docker-compose logs -f app
docker-compose logs -f postgres

# Reiniciar aplicação
docker-compose restart app

# Ver status
docker-compose ps
```

### Gerenciamento de Usuários

```bash
# Criar admin
docker-compose exec app python manage.py create-admin

# Criar operator
docker-compose exec app python manage.py create-user

# Listar usuários
docker-compose exec app python manage.py list-users

# Desativar usuário
docker-compose exec app python manage.py deactivate-user joao
```

### Migrations

```bash
# Criar migration
docker-compose exec app flask db migrate -m "Descrição"

# Aplicar migrations
docker-compose exec app flask db upgrade

# Ver histórico
docker-compose exec app flask db history
```

### Backup e Restore

```bash
# Backup do PostgreSQL
docker-compose exec postgres pg_dump -U backup_user network_backup > backup_$(date +%Y%m%d).sql

# Restore
docker-compose exec -T postgres psql -U backup_user network_backup < backup_20250118.sql

# Backup dos arquivos de configuração
docker run --rm -v network-backup_backup_data:/data -v $(pwd):/backup alpine tar czf /backup/backups_$(date +%Y%m%d).tar.gz -C /data .
```

### Acessar Container

```bash
# Shell no container da aplicação
docker-compose exec app bash

# Shell no PostgreSQL
docker-compose exec postgres psql -U backup_user network_backup
```

---

## 🔧 CONFIGURAÇÃO AVANÇADA

### Alterar Portas

Edite `docker-compose.yml`:

```yaml
services:
  app:
    ports:
      - "8080:5000"  # Mudar de 8000 para 8080
```

### Usar Nginx (Reverse Proxy)

1. Descomentar seção `nginx` no `docker-compose.yml`
2. Criar `nginx.conf`
3. Reiniciar: `docker-compose up -d`

### Volumes Persistentes

Os dados são armazenados em volumes Docker:

```bash
# Ver volumes
docker volume ls | grep network-backup

# Volumes criados:
# - network-backup_postgres_data (banco de dados)
# - network-backup_backup_data (arquivos de backup)
# - network-backup_app_logs (logs da aplicação)
```

### Backup Completo (Volumes + Database)

```bash
# Parar serviços
docker-compose down

# Backup de volumes
docker run --rm -v network-backup_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_data_$(date +%Y%m%d).tar.gz -C /data .
docker run --rm -v network-backup_backup_data:/data -v $(pwd):/backup alpine tar czf /backup/backup_data_$(date +%Y%m%d).tar.gz -C /data .

# Reiniciar
docker-compose up -d
```

---

## 🌐 DEPLOY EM PRODUÇÃO (com Docker)

### 1. Configurar Variáveis de Ambiente

Criar arquivo `.env` de produção:

```env
# Segurança
ENCRYPTION_KEY=<chave_forte_32_chars>
SECRET_KEY=<chave_forte_32_chars>
POSTGRES_PASSWORD=<senha_forte_db>

# Flask
FLASK_ENV=production
DEBUG=False

# Session (HTTPS)
SESSION_COOKIE_SECURE=True

# SSL
SSL_VERIFY=True
FORCE_HTTPS=True
```

### 2. Usar Docker Compose em Produção

```bash
# Build e start
docker-compose -f docker-compose.yml up -d --build

# Ver logs
docker-compose logs -f
```

### 3. Configurar Nginx/Traefik na Frente

Recomendado usar um proxy reverso com SSL:

- **Nginx + Certbot** (manual)
- **Traefik** (automático com Let's Encrypt)
- **Caddy** (automático com Let's Encrypt)

### 4. Backup Automático

Criar script de backup diário:

```bash
#!/bin/bash
# /usr/local/bin/backup-docker-network-backup.sh

cd /path/to/network-backup

# Backup PostgreSQL
docker-compose exec -T postgres pg_dump -U backup_user network_backup | gzip > backup_$(date +%Y%m%d).sql.gz

# Manter últimos 30 dias
find . -name "backup_*.sql.gz" -mtime +30 -delete
```

Adicionar ao cron:
```bash
0 3 * * * /usr/local/bin/backup-docker-network-backup.sh
```

---

## 🐛 TROUBLESHOOTING

### Container não inicia

```bash
# Ver logs completos
docker-compose logs app

# Verificar variáveis de ambiente
docker-compose config

# Rebuild
docker-compose build --no-cache
docker-compose up -d
```

### Erro de conexão com PostgreSQL

```bash
# Verificar se PostgreSQL está rodando
docker-compose ps postgres

# Ver logs do PostgreSQL
docker-compose logs postgres

# Testar conexão
docker-compose exec postgres psql -U backup_user -d network_backup
```

### Erro "ENCRYPTION_KEY não configurada"

```bash
# Verificar .env
cat .env

# Gerar novamente se necessário
python -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
```

### Limpar tudo e recomeçar

```bash
# ATENÇÃO: Isso apaga TODOS os dados!
docker-compose down -v
docker-compose up -d
```

---

## 📊 MONITORAMENTO

### Ver Uso de Recursos

```bash
# CPU e Memória
docker stats

# Apenas containers do projeto
docker stats $(docker-compose ps -q)
```

### Health Checks

```bash
# Status de saúde dos containers
docker-compose ps

# Testar health check manualmente
curl http://localhost:8000/api/stats
```

---

## 🔄 ATUALIZAÇÃO

### Atualizar para Nova Versão

```bash
# Baixar código novo (Git)
git pull origin main

# Rebuild e restart
docker-compose up -d --build

# Aplicar migrations
docker-compose exec app flask db upgrade
```

---

## 💡 DICAS

### Desenvolvimento Local

Para desenvolvimento, use um override:

Criar `docker-compose.override.yml`:

```yaml
version: '3.8'

services:
  app:
    volumes:
      - .:/app
    environment:
      FLASK_ENV: development
      DEBUG: "True"
    command: python app.py
```

Agora `docker-compose up` automaticamente usa o override.

### Logs Estruturados

```bash
# Ver apenas erros
docker-compose logs app | grep ERROR

# Ver logs de hoje
docker-compose logs --since $(date +%Y-%m-%d) app

# Seguir logs em tempo real
docker-compose logs -f --tail=100 app
```

---

## ✅ CHECKLIST PRÉ-PRODUÇÃO

- [ ] `.env` com chaves fortes e únicas
- [ ] `POSTGRES_PASSWORD` forte (32+ caracteres)
- [ ] `DEBUG=False` no `.env`
- [ ] `FLASK_ENV=production`
- [ ] Backup automático configurado
- [ ] Monitoramento ativo
- [ ] HTTPS configurado (Nginx/Traefik)
- [ ] Firewall configurado
- [ ] Health checks funcionando

---

**Docker deployment pronto! 🐳🚀**

Última atualização: 2025-01-18
