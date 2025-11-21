# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Este arquivo fornece orientações ao Claude Code (claude.ai/code) ao trabalhar com código neste repositório.

## CRÍTICO: Diretório de Trabalho

**TODOS os comandos devem ser executados no subdiretório `network-backup/`:**

```bash
cd network-backup
```

## Comandos Essenciais

```bash
# Desenvolvimento
flask run                              # Iniciar servidor de desenvolvimento
flask db upgrade                       # Aplicar migrações
python manage.py create-admin          # Criar usuário administrador
python manage.py create-user           # Criar usuário operator/viewer
python manage.py list-users            # Listar todos os usuários
python manage.py activate-user <nome>  # Ativar usuário
python manage.py deactivate-user <nome># Desativar usuário
python manage.py init-db               # Inicializar tabelas do banco
python manage.py migrate-from-sqlite   # Migrar SQLite para PostgreSQL

# Testar componentes individuais
python crypto_manager.py               # Testar sistema de criptografia
python validators.py                   # Testar validadores de entrada
python test_notifications.py           # Testar sistema de notificações
python check_scheduler.py              # Verificar status do scheduler

# Diagnósticos
python diagnostico_login.py            # Debug de problemas de login
python diagnostico_csrf.py             # Debug de token CSRF
python diagnostico_mimosa.py           # Debug de backups Mimosa
python verificar_backup_mimosa.py      # Verificar conteúdo de backup Mimosa

# Produção
gunicorn -c gunicorn_config.py app:app
docker-compose up -d
docker-compose exec app python manage.py create-admin
docker-compose exec app flask db upgrade
docker-compose logs -f app             # Ver logs
```

**IMPORTANTE**: Produção deve usar `GUNICORN_WORKERS=1` para o scheduler funcionar corretamente (evita jobs duplicados).

## Arquivos Principais

- `app.py` - Aplicação Flask (rotas, blueprints, error handlers)
- `models.py` - Modelos SQLAlchemy ORM (User, Device, Backup, Schedule, Provedor, AuditLog)
- `backup_manager.py` - Handlers de protocolo (SSH/Telnet/HTTP), lógica de backup e `BackupValidator`
- `database.py` - Wrapper SQLAlchemy mantendo interface retrocompatível com criptografia automática
- `auth.py` - Decorators de autenticação (`@admin_required`, `@operator_required`)
- `config.py` - Configuração baseada em ambiente
- `crypto_manager.py` - Criptografia AES-256 de credenciais com PBKDF2
- `scheduler.py` - APScheduler para backups automatizados
- `validators.py` - Validação e sanitização de entrada (whitelists de device types e comandos)
- `health.py` - Sistema de health check (liveness/readiness probes)
- `notifications.py` - Sistema de notificações Email/Webhook
- `structured_logging.py` - Logging estruturado JSON
- `manage.py` - CLI para gerenciamento (create-admin, create-user, list-users, etc.)

## Visão Geral do Projeto

Sistema de gerenciamento de backup de dispositivos de rede construído com Flask. Automatiza backups de configuração para equipamentos de rede (roteadores, switches, access points) usando protocolos SSH, Telnet e HTTP/HTTPS. Otimizado para 1.000-3.000+ dispositivos.

**Funcionalidades Principais**:
- Controle de acesso baseado em roles (admin/operator/viewer)
- Criptografia AES-256 de credenciais com PBKDF2
- Suporte PostgreSQL/SQLite via SQLAlchemy ORM
- Notificações Email/Webhook
- 50 workers paralelos de backup
- Health checks (compatível com Kubernetes/Docker)

## Arquitetura Principal

### Autenticação e Autorização

Flask-Login com três roles em `models.py:User`:
- **admin**: Acesso completo (usuários, devices, backups, schedules)
- **operator**: Gerenciar devices e executar backups
- **viewer**: Acesso somente leitura

Decorators de `auth.py`: `@login_required`, `@admin_required`, `@operator_required`, `@role_required('admin', 'operator')`

**Requisitos de senha para usuários** (definidos em `validators.py:validate_password_strength:140`):
- Mínimo 8 caracteres
- Pelo menos 1 maiúscula, 1 minúscula, 1 número, 1 caractere especial

Todas as ações são logadas na tabela `audit_logs`.

### Criptografia de Credenciais

`crypto_manager.py:CredentialManager` criptografa senhas de dispositivos em repouso:
- AES-256 via Fernet com PBKDF2-HMAC-SHA256 (100k iterações)
- Chave mestre derivada da variável de ambiente `ENCRYPTION_KEY`

**Crítico**: Alterar `ENCRYPTION_KEY` invalida todas as credenciais criptografadas.

### Camada de Banco de Dados

Arquitetura de duas camadas:
- `models.py` - Modelos SQLAlchemy ORM (User, Device, Backup, Schedule, Provedor, AuditLog)
- `database.py` - Classe wrapper fornecendo interface retrocompatível baseada em dict com criptografia/descriptografia automática

Suporta SQLite (dev) e PostgreSQL (prod) via `DATABASE_URL`.

### Armazenamento e Protocolos de Backup

Estrutura de armazenamento: `backups/{Provedor}/{Device}/{IP}_{YYYYMMDD_HHMMSS}.txt`

`BackupManager` gerencia protocolos:
- **SSH/Telnet**: Via Netmiko com mapeamento de tipo de dispositivo
- **HTTP/HTTPS**: Implementações customizadas para dispositivos Mimosa e Intelbras

Limpeza automática mantém os N backups mais recentes por dispositivo (`BACKUP_RETENTION_COUNT`).

**Validação de Backup**: Classe `BackupValidator` valida completude do backup usando marcadores específicos do dispositivo (marcadores início/fim, tamanho mínimo). Status: `complete`, `incomplete`, `unknown`.

### Soft Delete

Dispositivos suportam soft delete para preservar histórico de backups:
- `deleted_at`: Timestamp de quando o device foi excluído
- `deleted_by`: ID do usuário que excluiu
- Backups mantêm info em cache do device (`device_name_cached`, `device_ip_cached`, `device_provedor_cached`)

### Tipos de Dispositivos Suportados

**SSH/Telnet** (via Netmiko):
- Cisco: `cisco_ios`, `cisco_nxos`, `cisco_asa`, `cisco_xr`
- Juniper: `juniper_junos`
- MikroTik: `mikrotik_routeros`
- Huawei: `huawei`, `huawei_vrpv8`
- Arista: `arista_eos`
- HP: `hp_comware`
- Ubiquiti: `ubiquiti_airos`, `ubiquiti_edge`
- Datacom: `datacom`, `datacom_dmos`
- Outros: `paloalto_panos`, `fortinet_fortios`, `dell_force10`, `extreme`, `checkpoint`

**SSH + SFTP** (backup especial): `mikrotik_dude` - Backup do banco de dados do Dude rodando em RouterOS

**HTTP/HTTPS**: `mimosa`, `mimosa_c5c`, `mimosa_b5c`, `mimosa_b5`, `mimosa_a5c`, `intelbras_radio`

Comandos padrão e mapeamentos Netmiko definidos em `backup_manager.py:_get_default_command():1385` e `device_type_map:1069`. A whitelist completa de device types está em `validators.py:InputValidator.ALLOWED_DEVICE_TYPES:36` e comandos permitidos em `ALLOWED_BACKUP_COMMANDS:47`.

### Fluxo de Dados do Backup

1. Request → Autenticação → Buscar device(s) com credenciais descriptografadas
2. `ThreadPoolExecutor` com `BACKUP_MAX_WORKERS` (padrão: 50)
3. Handler de protocolo roteia para método SSH/Telnet/HTTP
4. Salvar arquivo → Limpar backups antigos → Inserir registro no BD → Notificar → Log de auditoria

### Configuração

Configs baseadas em ambiente em `config.py`: `DevelopmentConfig`, `TestingConfig`, `StagingConfig`, `ProductionConfig`

Selecionado via variável de ambiente `FLASK_ENV`.

## Rotas e API Principais

### Rotas Web (em `app.py`)
- `/auth/login`, `/auth/logout` - Autenticação
- `/devices`, `/backups`, `/schedules`, `/provedores` - Páginas CRUD
- `/users`, `/audit-logs` - Somente admin
- `POST /backup/<id>`, `POST /backup/all` - Executar backups (operator+)
- `/backups/compare` - Comparar dois arquivos de backup

### Endpoints da API
- `GET /api/stats` - Estatísticas do dashboard (JSON)
- `GET /api/charts` - Dados de gráficos para dashboards
- `GET /api/provedores` - Listar provedores (paginado)
- `GET /api/provedores/all` - Todos os provedores (sem paginação)
- `GET /api/audit-logs` - Dados de logs de auditoria

### Health Probes
- `GET /health` - Liveness probe (app está rodando?)
- `GET /health/ready` - Readiness probe (pode receber tráfego?)
- `GET /health/detailed` - Status completo do sistema com métricas

## Setup e Deploy

### Setup Inicial

**Windows:**
```bash
cd network-backup
python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

# Gerar chaves
python -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"

copy .env.example .env  # Editar com as chaves geradas
flask db upgrade
python manage.py create-admin
```

**Linux/Mac:**
```bash
cd network-backup
python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Gerar chaves
python -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"

cp .env.example .env  # Editar com as chaves geradas
flask db upgrade
python manage.py create-admin
```

### Migrações de Banco
```bash
flask db migrate -m "Descrição"  # Criar
flask db upgrade                 # Aplicar
flask db downgrade               # Reverter
```

### Docker
```bash
docker-compose up -d
docker-compose exec app python manage.py create-admin
docker-compose exec app flask db upgrade
docker-compose logs -f app  # Ver logs
```

## Trabalhando com o Código

### Adicionando Novos Tipos de Dispositivos
1. Adicionar tipo à whitelist em `validators.py:InputValidator.ALLOWED_DEVICE_TYPES`
2. Adicionar comandos permitidos em `validators.py:InputValidator.ALLOWED_BACKUP_COMMANDS`
3. Adicionar comando padrão em `backup_manager.py:_get_default_command()`
4. Adicionar ao `device_type_map` se Netmiko precisar de nome de tipo diferente
5. Para dispositivos HTTP: implementar método como `_backup_mimosa_http()`
6. Opcional: adicionar regras de validação em `backup_manager.py:BackupValidator.VALIDATION_RULES`

### Adicionando Novas Rotas
```python
from auth import operator_required, log_audit

@app.route('/nova-rota')
@operator_required
def nova_rota():
    log_audit('acao', 'tipo_recurso', resource_id, {'chave': 'valor'})
    # ...
```

### Alterações de Schema
1. Modificar `models.py`
2. `flask db migrate -m "Descrição"`
3. Revisar migração em `migrations/versions/`
4. `flask db upgrade`

### Enviando Notificações
```python
from notifications import get_notification_manager

notification_manager = get_notification_manager()
notification_manager.send_backup_success(device_name, backup_file)
notification_manager.send_backup_failure(device_name, error_message)
```

## Variáveis de Ambiente

**Obrigatórias**:
- `ENCRYPTION_KEY` - Chave mestre para criptografia de credenciais (32+ chars)
- `SECRET_KEY` - Chave de assinatura de sessão Flask (32+ chars)

**Banco de Dados**:
- `DATABASE_URL` - String de conexão (padrão: `sqlite:///backups.db`)
- `DB_POOL_SIZE` - Tamanho do pool (padrão: 50)

**Aplicação**:
- `FLASK_ENV` - Ambiente: development/testing/staging/production
- `TIMEZONE` - Timezone do sistema (padrão: America/Porto_Velho)
- `BACKUP_RETENTION_COUNT` - Backups por dispositivo (padrão: 5)
- `BACKUP_MAX_WORKERS` - Workers concorrentes (padrão: 50)
- `GUNICORN_WORKERS` - Deve ser 1 para o scheduler (padrão: 1)

**Timeouts** (segundos):
- `SSH_CONNECT_TIMEOUT` - Conexão SSH (padrão: 30)
- `SSH_READ_TIMEOUT` - Leitura SSH (padrão: 30)
- `SSH_COMMAND_TIMEOUT` - Execução de comando SSH (padrão: 60)
- `HTTP_TIMEOUT` - Requisições HTTP (padrão: 30)
- `INTELBRAS_CONNECT_TIMEOUT` - Dispositivos Intelbras (padrão: 60, dispositivos mais lentos)

**Sessão/Segurança**:
- `SESSION_COOKIE_SECURE` - True para HTTPS (padrão: True em produção)
- `WTF_CSRF_TIME_LIMIT` - Expiração do token CSRF em segundos (padrão: 3600)

**Notificações** (ver `.env.notifications.example`):
- `NOTIFICATION_EMAIL_ENABLED`, `NOTIFICATION_EMAIL_SMTP_HOST`, etc.
- `NOTIFICATION_WEBHOOK_ENABLED`, `NOTIFICATION_WEBHOOK_URL`

**SSL**: `SSL_VERIFY` (padrão: True), `SSL_CA_BUNDLE`

## Troubleshooting

**"ENCRYPTION_KEY não configurada!"**
- Configurar no `.env`: `python -c "import secrets; print(secrets.token_urlsafe(32))"`

**"cryptography.fernet.InvalidToken"**
- ENCRYPTION_KEY foi alterada; restaurar original ou reinserir todas as senhas dos dispositivos

**"relation does not exist"**
- Executar `flask db upgrade`

**Login 400 Bad Request**
- Ver `TROUBLESHOOTING_LOGIN.md` para guia detalhado
- Executar `python diagnostico_login.py` e `python diagnostico_csrf.py`
- Causas comuns: SECRET_KEY faltando, SESSION_COOKIE_SECURE=True com HTTP

**Falhas de backup HTTP (Mimosa/Intelbras)**
- Verificar se HTTPS está habilitado no dispositivo, porta correta (80/443)
- Executar `python diagnostico_mimosa.py`
- Tentar `SSL_VERIFY=False` para certificados auto-assinados

**Falhas SSH/Telnet**
- Verificar porta (SSH=22, Telnet=23), credenciais, mapeamento de tipo de dispositivo
- Verificar se firewall permite conexão

**Verificação Rápida de Saúde**:
```bash
python -c "import flask, sqlalchemy, netmiko, paramiko, cryptography; print('OK')"
python manage.py list-users
python check_scheduler.py
curl http://localhost:5000/health/ready
```

## Documentação

Todos os docs em `network-backup/`:
- `SETUP.md` - Setup detalhado
- `DEPLOY_PRODUCAO.md` - Produção (Nginx, Gunicorn, PostgreSQL)
- `DOCKER_QUICKSTART.md` - Quick start Docker
- `ESCALABILIDADE.md` - Escalabilidade para 1.000-3.000+ dispositivos
- `NOTIFICACOES.md` - Notificações Email/Webhook
- `INSTALL_DEBIAN.md` - Instalação Debian/Ubuntu
- `TROUBLESHOOTING_LOGIN.md` - Troubleshooting de problemas de login

## Performance

Dashboard <100ms com 3.000 dispositivos. Para >3.000 dispositivos, aumentar `BACKUP_MAX_WORKERS` (75-100).

**Requisitos**: 4+ cores, 8GB RAM, SSD, PostgreSQL max_connections=200+
