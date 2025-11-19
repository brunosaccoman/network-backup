# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Working Directory Note

**IMPORTANT**: All commands in this document assume you are in the `network-backup/` subdirectory unless otherwise specified. The project root contains the CLAUDE.md file, but the application code is in `network-backup/`.

```bash
# From project root
cd network-backup

# Now you can run all commands below
```

## Visão Geral do Projeto

Este é um sistema de gerenciamento de backup de dispositivos de rede construído com Flask. Ele automatiza backups de configuração para equipamentos de rede (roteadores, switches, access points) usando protocolos SSH, Telnet e HTTP/HTTPS. O sistema suporta múltiplos fabricantes de dispositivos incluindo Cisco, Huawei, Mikrotik, Ubiquiti, Juniper, entre outros.

**Status Atual**: Fase 2 em Progresso - Observabilidade
- ✅ Fase 1: Autenticação multiusuário com controle de acesso baseado em roles (admin/operator/viewer)
- ✅ Fase 1: Criptografia de credenciais AES-256 com derivação de chave PBKDF2
- ✅ Fase 1: Suporte a PostgreSQL com SQLAlchemy ORM e migrações
- ✅ Fase 1: Proteção CSRF, rate limiting e auditoria de logs
- ✅ Fase 2: Sistema de notificações (Email/Webhook) para alertas de backup
- ✅ Fase 2: Logging estruturado com suporte JSON
- ✅ Fase 2: Health checks para monitoramento de sistema
- Pronto para produção com suporte a deploy via Docker

## Estrutura do Projeto

```
network-backup/
├── app.py                  # Aplicação Flask com blueprints e autenticação
├── config.py              # Configuração baseada em ambiente (dev/staging/prod)
├── models.py              # Modelos SQLAlchemy ORM (User, Device, Backup, Schedule, Provedor, AuditLog)
├── database.py            # Gerenciador de banco legado (sendo substituído por models.py)
├── backup_manager.py       # Lógica principal de backup para diferentes protocolos/dispositivos
├── scheduler.py           # Integração APScheduler para backups automatizados
├── crypto_manager.py      # Criptografia/descriptografia de credenciais com Fernet (AES-256)
├── auth.py                # Autenticação Flask-Login e decoradores baseados em roles
├── validators.py          # Validação e sanitização de entrada
├── manage.py              # Comandos CLI para gerenciamento de usuários e migrações
├── cleanup_backups.py     # Utilitário para limpar backups antigos (mantém 5 mais recentes)
├── check_scheduler.py     # Utilitário para verificar status do agendador
├── notifications.py       # Sistema de notificações (Email/Webhook) - Fase 2
├── structured_logging.py  # Logging estruturado com JSON - Fase 2
├── health.py              # Health checks e monitoramento - Fase 2
├── test_notifications.py  # Testes para sistema de notificações
├── templates/             # Templates HTML Jinja2
├── static/                # Arquivos CSS/JS
├── backups/              # Armazenamento de backups (organizado por provedor/dispositivo)
├── Dockerfile             # Build Docker multi-stage
├── docker-compose.yml     # Orquestração Docker com PostgreSQL
├── gunicorn_config.py     # Configuração do servidor WSGI de produção
└── requirements.txt       # Dependências Python com anotações de fase
```

## Conceitos Chave da Arquitetura

### Sistema de Autenticação e Autorização
O sistema usa Flask-Login com três níveis de role definidos em `models.py:User`:
- **admin**: Acesso total ao sistema (gerenciar usuários, dispositivos, backups, agendamentos)
- **operator**: Pode gerenciar dispositivos e executar backups, sem gerenciamento de usuários
- **viewer**: Acesso somente leitura a todos os dados

A aplicação de roles usa decoradores de `auth.py`:
- `@login_required`: Requer autenticação
- `@role_required('admin', 'operator')`: Requer role(s) específico(s)
- `@admin_required`: Atalho para rotas exclusivas de admin
- `@operator_required`: Requer operator ou admin

Todas as ações são registradas na tabela `audit_logs` com usuário, tipo de ação, recurso e timestamp.

### Arquitetura de Criptografia de Credenciais
Credenciais sensíveis (senhas de dispositivos) são criptografadas em repouso usando `crypto_manager.py:CredentialManager`:
- **Algoritmo**: AES-256 via Fernet (criptografia simétrica)
- **Derivação de Chave**: PBKDF2-HMAC-SHA256 com 100.000 iterações
- **Chave Mestra**: Derivada da variável de ambiente `ENCRYPTION_KEY`
- **Salt**: Salt fixo definido em `CredentialManager._SALT`

**Crítico**: Alterar a `ENCRYPTION_KEY` invalida todas as credenciais criptografadas. As senhas dos dispositivos devem ser reinseridas se a chave mudar.

O modelo Device em `models.py` usa propriedades híbridas do SQLAlchemy:
- `device.password` (setter): Criptografa automaticamente antes de armazenar em `password_encrypted`
- `device.password` (getter): Descriptografa automaticamente de `password_encrypted`
- A senha em texto plano nunca toca o banco de dados

### Schema do Banco de Dados e ORM
Usa SQLAlchemy ORM com Flask-Migrate para gerenciamento de schema. Seis modelos principais em `models.py`:
- `users`: Usuários do sistema com senhas hash bcrypt e roles
- `devices`: Inventário de dispositivos de rede com credenciais criptografadas
- `backups`: Histórico de execução de backups com caminhos de arquivo e status
- `schedules`: Agendamento de backup tipo cron (diário/semanal/mensal)
- `provedores`: Categorização de ISP/provedor para organização de dispositivos
- `audit_logs`: Trilha de auditoria completa de todas as ações de usuário

Agnóstico de banco de dados - suporta tanto SQLite (dev) quanto PostgreSQL (prod) via configuração `DATABASE_URL`.

### Estrutura de Armazenamento de Backup
Backups são organizados hierarquicamente em disco:

**Estrutura de diretórios**:
```
backups/
├── [Provedor_Name]/              # Nome do provedor/ISP
│   ├── [Device_Name]/            # Nome do dispositivo (sanitizado)
│   │   ├── [IP]_[timestamp].txt  # Arquivo de backup
│   │   ├── [IP]_[timestamp].txt
│   │   └── ...
│   └── ...
└── Sem_Provedor/                 # Dispositivos sem provedor atribuído
    └── [Device_Name]/
        └── [IP]_[timestamp].txt
```

**Exemplo real**:
```
backups/
├── Sem_Provedor/
│   ├── HUAWEI-RTR-PE-RC-CEN-01/
│   │   ├── 10.2.127.0_20251111_160418.txt
│   │   ├── 10.2.127.0_20251111_221903.txt
│   │   └── 10.2.127.0_20251112_221903.txt
│   └── HUAWEI-SW3-PE-RC-CEN-01/
│       └── 10.2.124.0_20251111_154240.txt
└── BNG_10.2.19.0_20251109_113119.txt  # Legacy format (old backups)
```

**Notas importantes**:
- "Provedor" representa categorização de ISP/provedor para organização
- Nomes de pastas são sanitizados (caracteres especiais → underscores)
- Timestamp no formato: `YYYYMMDD_HHMMSS`
- Sistema mantém automaticamente os N backups mais recentes (configurável via `BACKUP_RETENTION_COUNT`)
- Backups antigos sem estrutura de pastas podem existir (legacy)

### Sistema de Configuração
Configuração baseada em ambiente em `config.py` com hierarquia de herança:
- `Config`: Configuração base com todas as definições
- `DevelopmentConfig`: Modo debug, logging verboso, rate limits relaxados
- `TestingConfig`: SQLite em memória, CSRF desabilitado, bcrypt rounds rápidos
- `StagingConfig`: Similar a produção com debug habilitado
- `ProductionConfig`: Segurança estrita, forçar HTTPS, logging de produção

Configuração ativa determinada pela variável de ambiente `FLASK_ENV`. Configurações críticas:
- `ENCRYPTION_KEY`: Chave mestra para criptografia de credenciais (32+ caracteres)
- `SECRET_KEY`: Chave de assinatura de sessão Flask (deve diferir de ENCRYPTION_KEY)
- `DATABASE_URL`: String de conexão (auto-converte `postgres://` para `postgresql://`)
- `SESSION_COOKIE_SECURE`: Força HTTPS para cookies (True em produção)
- `BACKUP_RETENTION_COUNT`: Número de backups a manter por dispositivo (padrão: 5)

### Manipulação de Protocolos pelo Backup Manager
A classe `BackupManager` manipula três protocolos:
- **SSH**: Usa biblioteca Netmiko com mapeamento de tipo de dispositivo
- **Telnet**: Usa Netmiko com sufixo `_telnet` nos tipos de dispositivo
- **HTTP/HTTPS**: Implementações customizadas para dispositivos Mimosa e Intelbras

O mapeamento de tipo de dispositivo traduz tipos customizados (ex: `ubiquiti_airos`) para tipos compatíveis com Netmiko em `backup_manager.py`.

### Limpeza Automática
Após cada backup bem-sucedido, o sistema deleta automaticamente backups antigos, mantendo apenas os mais recentes por dispositivo (configurado via `BACKUP_RETENTION_COUNT`).

### Configuração de Fuso Horário
Todos os timestamps usam o fuso horário `America/Porto_Velho` (configurável via variável de ambiente `TIMEZONE`).

### Sistema de Notificações (Fase 2)
O sistema inclui notificações automáticas através de múltiplos canais implementadas em `notifications.py`:
- **Email (SMTP)**: Alertas via Gmail, Office365 ou qualquer servidor SMTP
- **Webhooks**: Integração com Slack, Discord, Microsoft Teams
- **Tipos de eventos**:
  - Backup falhado (nível ERROR)
  - Backup bem-sucedido (nível INFO, opcional)
  - Múltiplas falhas (nível ERROR)
  - Erros do agendador (nível WARNING)
  - Alertas de saúde do sistema (nível WARNING/CRITICAL)

Configuração via variáveis de ambiente (detalhes em `NOTIFICACOES.md`).

### Logging Estruturado (Fase 2)
Sistema de logging estruturado implementado em `structured_logging.py`:
- Logs em formato JSON para parsing automatizado
- IDs de correlação para rastreamento de requisições
- Integração com Prometheus para métricas
- Suporte a múltiplos níveis (DEBUG, INFO, WARNING, ERROR, CRITICAL)

### Health Checks (Fase 2)
Sistema de monitoramento de saúde em `health.py`:
- Verificação de saúde do banco de dados
- Status do agendador APScheduler
- Métricas de recursos do sistema (CPU, RAM, disco)
- Endpoints `/health` para load balancers
- Métricas Prometheus em `/metrics`

### Otimizações de Escalabilidade
O sistema foi otimizado para suportar **1.000-3.000+ dispositivos**:
- **Workers paralelos**: 50 workers simultâneos (antes: 10)
- **Pool de conexões**: 150 conexões máximas (antes: 30)
- **Paginação**: Todas as listas usam paginação (50 itens/página)
- **Eager loading**: Queries otimizadas para evitar N+1 problem
- **Índices compostos**: 4 novos índices para performance
- **Performance**: Dashboard carrega em <100ms mesmo com 3.000 devices

Ver `ESCALABILIDADE.md` para detalhes completos.

## Platform-Specific Notes

This project can run on Windows, Linux, or macOS. Key differences:

**Windows (Current Development Environment)**:
- Use `venv\Scripts\activate` to activate virtual environment
- Use `python` command (not `python3`)
- Paths use backslashes in Windows CLI (but forward slashes work in Python code)
- PostgreSQL can be run via Docker Desktop or WSL2

**Linux/macOS**:
- Use `source venv/bin/activate` to activate virtual environment
- May need `python3` instead of `python`
- PostgreSQL typically installed via package manager

## Comandos Comuns

### Configuração Inicial
```bash
# Navegar para o projeto
cd network-backup

# Criar ambiente virtual
python -m venv venv

# Ativar ambiente virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Instalar dependências
pip install --upgrade pip
pip install -r requirements.txt

# Gerar chaves de criptografia
python -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"

# Criar arquivo .env e adicionar as chaves acima mais:
# DATABASE_URL=sqlite:///backups.db  (ou string de conexão PostgreSQL)
# FLASK_ENV=development
# DEBUG=True
```

### Gerenciamento de Banco de Dados
```bash
# Inicializar migrações (somente primeira vez)
flask db init

# Criar migração após mudanças nos modelos
flask db migrate -m "Descrição das mudanças"

# Aplicar migrações
flask db upgrade

# Reverter última migração
flask db downgrade

# Ver histórico de migrações
flask db history

# Migração atual
flask db current
```

### Gerenciamento de Usuários (via manage.py)
```bash
# Criar usuário admin
python manage.py create-admin

# Criar usuário operator
python manage.py create-user --role operator

# Criar usuário viewer
python manage.py create-user --role viewer

# Listar todos os usuários
python manage.py list-users

# Desativar usuário
python manage.py deactivate-user <username>

# Ativar usuário
python manage.py activate-user <username>

# Migrar dados de banco SQLite antigo
python manage.py migrate-from-sqlite --sqlite-db backups.db
```

### Desenvolvimento
```bash
# Executar servidor de desenvolvimento (Flask built-in)
flask run

# Ou com mais controle
python app.py

# Executar em porta específica
# Windows:
set PORT=8080 && python app.py
# Linux/Mac:
PORT=8080 python app.py

# Habilitar logging de queries SQLAlchemy
# Windows:
set SQLALCHEMY_ECHO=True && python app.py
# Linux/Mac:
SQLALCHEMY_ECHO=True python app.py

# Verificar status do agendador
python check_scheduler.py

# Executar limpeza manual de backups
python cleanup_backups.py

# Testar notificações
python test_notifications.py
```

### Escalabilidade e Performance
```bash
# Aplicar índices de escalabilidade (PostgreSQL)
psql -U backup_user -d network_backup -f migrations/versions/add_scalability_indexes.sql

# Verificar uso de conexões do banco
psql -U backup_user -d network_backup -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'network_backup';"

# Monitorar performance de queries
psql -U backup_user -d network_backup -c "EXPLAIN ANALYZE SELECT * FROM devices WHERE active = true ORDER BY updated_at DESC LIMIT 100;"

# Atualizar estatísticas do banco (após adicionar muitos devices)
psql -U backup_user -d network_backup -c "ANALYZE devices; ANALYZE backups;"
```

### Deploy de Produção
```bash
# Usando Gunicorn com arquivo de configuração
gunicorn -c gunicorn_config.py app:app

# Ou especificar workers/bind manualmente
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Verificar sintaxe da configuração Gunicorn
gunicorn --check-config -c gunicorn_config.py app:app
```

### Deploy Docker
```bash
# Construir imagem
docker build -t network-backup:latest .

# Executar com docker-compose (inclui PostgreSQL)
docker-compose up -d

# Ver logs
docker-compose logs -f app

# Criar usuário admin no container
docker-compose exec app python manage.py create-admin

# Executar migrações no container
docker-compose exec app flask db upgrade

# Parar serviços
docker-compose down

# Backup PostgreSQL do container
docker-compose exec postgres pg_dump -U backup_user network_backup > backup.sql

# Restaurar PostgreSQL no container
docker-compose exec -T postgres psql -U backup_user network_backup < backup.sql
```

## Notas Importantes de Implementação

### Considerações de Segurança
**Proteção de Credenciais**:
- Todas as senhas de dispositivos criptografadas em repouso usando AES-256 (Fernet) via `crypto_manager.py`
- Senhas de usuários com hash bcrypt (12 rounds em produção, 4 em testes)
- `ENCRYPTION_KEY` deve ser mantida em segredo e com backup - perda significa reinserção de credenciais
- Nunca commitar arquivo `.env` (já está em `.gitignore`)

**Validação de Entrada**:
- Todas as entradas de usuário validadas através de `validators.py:InputValidator`
- SQL injection prevenida via queries parametrizadas (SQLAlchemy ORM)
- Proteção CSRF habilitada via Flask-WTF (exceto em ambiente de teste)
- Rate limiting em endpoints de autenticação (5 tentativas de login por minuto)

**Segurança de Sessão**:
- Cookies de sessão HTTP-only e SameSite=Lax
- Flag Secure habilitada em produção (somente HTTPS)
- Tempo de vida de sessão de 7 dias (configurável)
- Cookies remember-me usam mesmas configurações de segurança

**Trilha de Auditoria**:
- Todas as ações que alteram estado registradas na tabela `audit_logs`
- Inclui usuário, tipo de ação, recurso, endereço IP e timestamp
- Tentativas de login falhadas registradas separadamente

### Padrões de Autenticação e Autorização
Ao adicionar novas rotas, aplique os decoradores apropriados de `auth.py`:

```python
from auth import login_required, role_required, admin_required, operator_required, log_audit

# Rota pública (sem decorator)
@app.route('/login')
def login():
    pass

# Somente usuários autenticados
@app.route('/dashboard')
@login_required
def dashboard():
    pass

# Somente operators e admins
@app.route('/devices/add')
@operator_required
def add_device():
    log_audit('create', 'device', device_id, {'name': device.name})
    pass

# Somente admins
@app.route('/users/manage')
@admin_required
def manage_users():
    pass

# Múltiplos roles
@app.route('/reports')
@role_required('admin', 'operator', 'viewer')
def reports():
    pass
```

### Compatibilidade de Tipos de Dispositivo
Comandos de backup padrão para cada tipo de dispositivo são definidos em `backup_manager.py:_get_default_command()`. Ao adicionar novos tipos de dispositivo:
1. Adicionar tipo de dispositivo ao dicionário de comandos
2. Adicionar mapeamento de protocolo se usar SSH/Telnet (ver device_type_map)
3. Para dispositivos HTTP, implementar método de backup customizado (ver `_backup_mimosa_http` ou `_backup_intelbras_http`)

Tipos de dispositivos suportados incluem:
- Cisco IOS, IOS-XE, IOS-XR, ASA, NXOS
- Datacom (DmOS) - usa template Cisco IOS
- Huawei VRP
- Mikrotik RouterOS
- Ubiquiti EdgeOS e AirOS
- Juniper JunOS
- Switches HPE/Aruba
- E mais (ver `backup_manager.py` para lista completa)

### Sistema de Agendamento
O agendador roda em thread de background usando APScheduler:
- Jobs carregados na inicialização da aplicação do banco de dados
- Mudanças de agendamento automaticamente recarregam jobs via `scheduler.reload_schedules()`
- IDs de job seguem padrão: `schedule_{schedule_id}`
- Suporta backups específicos de dispositivo ou de todos os dispositivos
- Agendamento consciente de fuso horário usando configuração `TIMEZONE`

### Tratamento de Erros
Backups falhados são registrados no banco de dados com:
- `status`: 'failed'
- `error_message`: Mensagem de exceção e traceback
- Nenhum arquivo criado em disco
- Dispositivo permanece disponível para retry

## Referência de Endpoints da API

Todos os endpoints da API requerem autenticação salvo indicação contrária. Rotas usam blueprints e controle de acesso baseado em roles.

### Autenticação (`/auth`)
- `GET /auth/login` - Página de login (público)
- `POST /auth/login` - Processar login (público, rate-limited: 5/minuto)
- `GET /auth/logout` - Logout do usuário atual
- `GET /auth/profile` - Ver perfil do usuário atual (`@login_required`)

### Usuários (`/users`) - Somente Admin
- `GET /users` - Listar todos os usuários (`@admin_required`)
- `POST /users/add` - Criar novo usuário (`@admin_required`)
- `GET /users/<id>` - Obter detalhes do usuário (`@admin_required`)
- `POST /users/<id>/update` - Atualizar usuário (`@admin_required`)
- `POST /users/<id>/toggle-active` - Ativar/desativar usuário (`@admin_required`)
- `DELETE /users/<id>` - Deletar usuário (`@admin_required`)

### Dispositivos (`/devices`) - Operator+
- `GET /devices` - Listar todos os dispositivos (`@login_required`)
- `POST /devices/add` - Adicionar novo dispositivo (`@operator_required`)
  - Obrigatório: name, ip_address, device_type, protocol, username, password, provedor
- `GET /devices/<id>/get` - Obter detalhes do dispositivo (`@login_required`)
- `POST /devices/<id>/update` - Atualizar dispositivo (`@operator_required`)
- `POST /devices/<id>/delete` - Deletar dispositivo (`@admin_required`)
- `POST /devices/<id>/toggle-active` - Habilitar/desabilitar dispositivo (`@operator_required`)

### Backups (`/backups`) - Operator+
- `GET /backups` - Listar backups (`@login_required`, opcional: ?device_id=X)
- `POST /backup/<device_id>` - Executar backup para dispositivo único (`@operator_required`)
- `POST /backup/all` - Executar backup para todos os dispositivos ativos (`@operator_required`)
- `GET /backups/<id>/download` - Baixar arquivo de backup (`@login_required`)
- `GET /backups/<id>/view` - Ver conteúdo do backup no navegador (`@login_required`)
- `DELETE /backups/<id>` - Deletar registro e arquivo de backup (`@admin_required`)

### Agendamentos (`/schedules`) - Operator+
- `GET /schedules` - Listar agendamentos (`@login_required`)
- `POST /schedules/add` - Criar agendamento (`@operator_required`)
- `GET /schedules/<id>` - Obter detalhes do agendamento (`@login_required`)
- `POST /schedules/<id>/update` - Atualizar agendamento (`@operator_required`)
- `DELETE /schedules/<id>` - Deletar agendamento (`@operator_required`)
- `POST /schedules/<id>/toggle` - Habilitar/desabilitar agendamento (`@operator_required`)

### Provedores (`/api/provedores`)
- `GET /api/provedores` - Listar nomes de provedores (`@login_required`)
- `GET /api/provedores/all` - Listar provedores com detalhes (`@login_required`)
- `POST /api/provedores/add` - Adicionar provedor (`@operator_required`, JSON: {name, description})
- `POST /api/provedores/<id>/delete` - Deletar provedor por ID (`@admin_required`)

### Sistema/Dashboard (`/`)
- `GET /` - Dashboard principal (`@login_required`)
- `GET /api/stats` - Estatísticas do sistema (`@login_required`)
- `GET /api/audit-logs` - Ver trilha de auditoria (`@admin_required`)

## Trabalhando com o Código

### Adicionando Suporte para Novos Tipos de Dispositivo
1. **Definir comando de backup**: Adicionar entrada em `backup_manager.py:_get_default_command()`
   ```python
   def _get_default_command(self, device_type):
       commands = {
           'cisco_ios': 'show running-config',
           'seu_novo_dispositivo': 'seu comando aqui',
           # ...
       }
   ```

2. **Dispositivos SSH/Telnet**: Adicionar a `device_type_map` se Netmiko precisar de nome de tipo diferente
   ```python
   device_type_map = {
       'ubiquiti_airos': 'ubiquiti_edgerouter',  # Mapeia nome da UI para driver Netmiko
   }
   ```

3. **Dispositivos HTTP/HTTPS**: Implementar método de backup customizado
   ```python
   def _backup_seu_dispositivo_http(self, device):
       """Backup via HTTP para Seu Dispositivo."""
       response = requests.get(
           f'https://{device.ip_address}/api/config',
           auth=(device.username, device.password),
           verify=self.ssl_verify
       )
       return response.text
   ```
   Então adicionar à lógica de detecção de vendor do método `_backup_http()`.

### Adicionando Novos Roles de Usuário
Atualmente suporta admin/operator/viewer. Para adicionar novo role:
1. **Atualizar validadores**: Adicionar role a `validators.py:validate_role()`
2. **Atualizar models**: Documentar em docstring da classe `models.py:User`
3. **Criar decorator**: Adicionar decorator de role em `auth.py`
4. **Aplicar a rotas**: Usar novo decorator em endpoints apropriados

### Mudanças no Schema do Banco de Dados
Usa Flask-Migrate (Alembic) para migrações:

1. **Modificar models** em `models.py`:
   ```python
   class Device(db.Model):
       # Adicionar nova coluna
       location = db.Column(db.String(100))
   ```

2. **Gerar migração**:
   ```bash
   flask db migrate -m "Adicionar location aos devices"
   ```

3. **Revisar migração** no diretório `migrations/versions/`

4. **Aplicar migração**:
   ```bash
   flask db upgrade
   ```

5. **Reverter se necessário**:
   ```bash
   flask db downgrade
   ```

### Adicionando Novas Opções de Configuração
1. **Definir em config.py**: Adicionar à classe base `Config`
   ```python
   class Config:
       NEW_SETTING = os.environ.get('NEW_SETTING', 'default_value')
   ```

2. **Sobrescrever por ambiente** se necessário:
   ```python
   class ProductionConfig(Config):
       NEW_SETTING = 'production_value'
   ```

3. **Documentar em .env.example** (se existir) ou SETUP.md

4. **Acessar no código**:
   ```python
   from flask import current_app
   value = current_app.config['NEW_SETTING']
   ```

### Modificando Política de Retenção de Backup
A política de limpeza (padrão: manter 5 backups) é configurável:
- **Padrão global**: Definir `BACKUP_RETENTION_COUNT` em `.env`
- **Override por dispositivo**: Passar parâmetro `keep_count` para método `cleanup_old_backups()`
- **Limpeza standalone**: Modificar script `cleanup_backups.py`

### Notas sobre Código Legado
**database.py**: Este é código legado de antes da Fase 1. Está sendo gradualmente substituído por:
- `models.py`: Modelos SQLAlchemy ORM
- Flask-Migrate: Migrações de banco de dados
- `manage.py`: Operações CLI

Ao fazer mudanças no banco de dados, prefira usar `models.py` e migrações em vez de modificações diretas em `database.py`.

### Testando Criptografia de Credenciais
```bash
# Testar criptografia/descriptografia (executa testes internos)
python crypto_manager.py

# Verificar se ENCRYPTION_KEY está definida
python -c "from crypto_manager import CredentialManager; cm = CredentialManager(); print('OK')"

# Testar validadores (executa suite de testes)
python validators.py

# Testar conexão com banco de dados
python -c "from app import app, db; from models import User; \
  with app.app_context(): \
    print(f'Database connected: {db.engine.url}'); \
    print(f'Users: {User.query.count()}')"
```

### Dicas de Debug
**Habilitar logging de queries**:
```bash
# Windows
set SQLALCHEMY_ECHO=True && flask run

# Linux/Mac
SQLALCHEMY_ECHO=True flask run
```

**Verificar contexto de usuário atual**:
```python
from flask_login import current_user
print(f"User: {current_user.username}, Role: {current_user.role}")
```

**Verificar criptografia**:
```python
device = Device.query.first()
print(device.password)  # Auto-descriptografa
print(device.password_encrypted)  # Mostra blob criptografado
```

**Verificar status do agendador**:
```bash
python check_scheduler.py
```

**Ver logs de auditoria**:
```bash
# Via PostgreSQL
psql -U backup_user -d network_backup -c "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10;"

# Ou via Python
python -c "from app import app, db; from models import AuditLog; \
  with app.app_context(): \
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all(); \
    [print(f'{l.timestamp}: {l.user.username} - {l.action} {l.resource_type}') for l in logs]"
```

## Roadmap do Projeto

**Fase 1: Segurança e Fundações** ✅ **COMPLETA**
- Autenticação multiusuário com controle de acesso baseado em roles
- Criptografia de credenciais AES-256
- Suporte a PostgreSQL com ORM e migrações
- Proteção CSRF, rate limiting, logging de auditoria
- Suporte a deploy Docker

**Fase 2: Observabilidade** ✅ **COMPLETA**
- Logging estruturado com IDs de correlação
- Integração de métricas Prometheus
- Notificações por Email/Slack/webhook para falhas de backup
- Endpoints de health check
- Monitoramento de performance
- **Otimizações de escalabilidade para 1.000-3.000+ devices**

**Fase 3: Funcionalidades Avançadas** (Futuro)
- Execução paralela de backup com Celery
- Diff de configuração e detecção de mudanças
- Funcionalidade de restauração point-in-time
- Compressão e criptografia de backup
- Agendamento avançado com expressões cron

**Fase 4: Funcionalidades Enterprise** (Futuro)
- Suporte a multi-tenancy
- REST API com chaves de API
- Integração com armazenamento em nuvem (S3, Azure, GCS)
- Integração SSO/LDAP
- RBAC avançado com permissões customizadas

## Arquivos e Documentação Importantes

**Setup e Deploy**:
- `SETUP.md` - Guia detalhado de setup para desenvolvimento e produção
- `DEPLOY_PRODUCAO.md` - Guia completo de deploy de produção (Nginx, Gunicorn, PostgreSQL)
- `DOCKER_QUICKSTART.md` - Início rápido com Docker Compose
- `ESCALABILIDADE.md` - **Guia completo de escalabilidade para 1.000-3.000+ devices**
- `NOTIFICACOES.md` - Configuração de notificações (Email, Webhook)

**Configuração**:
- `.env` - Variáveis de ambiente (não está no git, deve ser criado a partir do template)
- `config.py` - Classes de configuração da aplicação
- `requirements.txt` - Dependências Python com anotações de fase

**Banco de Dados**:
- `models.py` - Modelos SQLAlchemy ORM (schema atual)
- `database.py` - Gerenciador de banco legado (deprecated, preferir models.py)
- `migrations/` - Scripts de migração Alembic (criados por Flask-Migrate)

## Referência de Variáveis de Ambiente

**Obrigatórias**:
- `ENCRYPTION_KEY` - Chave mestra para criptografia de credenciais (32+ caracteres)
- `SECRET_KEY` - Chave de assinatura de sessão Flask (32+ caracteres, deve diferir de ENCRYPTION_KEY)

**Banco de Dados**:
- `DATABASE_URL` - String de conexão (padrão: `sqlite:///backups.db`)
- `DB_POOL_SIZE` - Tamanho do pool de conexões (padrão: 50 para 1000+ devices)
- `DB_MAX_OVERFLOW` - Máximo de conexões overflow (padrão: 100 para 1000+ devices)

**Aplicação**:
- `FLASK_ENV` - Ambiente: development/testing/staging/production (padrão: development)
- `DEBUG` - Habilitar modo debug (padrão: True em dev, False em prod)
- `TIMEZONE` - Fuso horário do sistema (padrão: America/Porto_Velho)

**Segurança**:
- `SESSION_COOKIE_SECURE` - Cookies somente HTTPS (padrão: False em dev, True em prod)
- `SESSION_PERMANENT_LIFETIME` - Duração da sessão em dias (padrão: 7)
- `SSL_VERIFY` - Verificar certificados SSL para backups HTTPS (padrão: True)
- `FORCE_HTTPS` - Redirecionar HTTP para HTTPS (padrão: False)

**Backups**:
- `BACKUP_DIR` - Diretório de armazenamento de backups (padrão: `backups/`)
- `BACKUP_RETENTION_COUNT` - Backups a manter por dispositivo (padrão: 5)
- `BACKUP_TIMEOUT` - Timeout de operação de backup em segundos (padrão: 60)
- `BACKUP_MAX_WORKERS` - Máximo de workers de backup concorrentes (padrão: 50 para 1000+ devices)

**Rate Limiting**:
- `RATELIMIT_DEFAULT` - Rate limit padrão (padrão: 100/minuto)
- `RATELIMIT_STORAGE_URL` - Backend de armazenamento de rate limit (padrão: memory://)

**Logging**:
- `LOG_LEVEL` - Nível de logging (padrão: INFO)
- `LOG_DIR` - Diretório de logs (padrão: `logs/`)
- `LOG_FORMAT` - Formato de log: json ou text (padrão: json)

## Solução de Problemas Comuns

**"ENCRYPTION_KEY não configurada!"**
- Solução: Definir `ENCRYPTION_KEY` no arquivo `.env`
- Gerar chave: `python -c "import secrets; print(secrets.token_urlsafe(32))"`

**"cryptography.fernet.InvalidToken"**
- Causa: ENCRYPTION_KEY mudou e não consegue descriptografar senhas existentes
- Soluções:
  1. Restaurar ENCRYPTION_KEY original
  2. Ou reinserir todas as senhas de dispositivos com nova chave

**"could not connect to server: Connection refused" (PostgreSQL)**
- Verificar se PostgreSQL está rodando: `sudo systemctl status postgresql`
- Verificar se DATABASE_URL está correta
- Testar conexão: `psql -U backup_user -d network_backup`

**"relation does not exist"**
- Causa: Migrações de banco de dados não aplicadas
- Solução: `flask db upgrade`

**Erros de importação para psycopg2**
- Ubuntu/Debian: `sudo apt-get install libpq-dev python3-dev`
- Então: `pip install --upgrade psycopg2-binary`

**Rate limit excedido no login**
- Aguardar 1 minuto (limite: 5 tentativas por minuto)
- Ou reiniciar Flask para limpar armazenamento de rate limit em memória

**Falha de backup de dispositivo com "Authentication failed"**
- Verificar se credenciais estão corretas (reinserir se ENCRYPTION_KEY mudou)
- Verificar se dispositivo está alcançável: `ping <device_ip>`
- Verificar se protocolo/porta estão corretos (SSH: 22, Telnet: 23)
- Verificar se tipo de dispositivo corresponde ao dispositivo real

**Agendador não está executando backups**
- Verificar se agendamento está ativo: Verificar tabela `schedules` ou UI
- Verificar se agendador iniciou: Procurar por "Scheduler initialized" nos logs
- Verificar se configurações de fuso horário correspondem ao horário esperado do agendamento

**Problemas específicos do Windows**
- **"python: command not found"**: Use `py` em vez de `python`, ou adicione Python ao PATH
- **"Access denied" ao criar venv**: Execute PowerShell/CMD como administrador
- **PostgreSQL via Docker**: Certifique-se de que Docker Desktop está rodando
- **Problemas de firewall**: Libere porta 5000 (Flask) e 5432 (PostgreSQL) no Windows Firewall

**Quick Health Check**
```bash
# Verificar todas as dependências principais
python -c "import flask, sqlalchemy, netmiko, paramiko, cryptography; print('All dependencies OK')"

# Verificar configuração
python -c "from config import get_config; cfg = get_config(); print(f'Environment: {cfg.__name__}'); print(f'Database: {cfg.SQLALCHEMY_DATABASE_URI}')"

# Verificar estrutura de banco
python manage.py list-users

# Verificar agendador
python -c "from app import app; from scheduler import scheduler; \
  with app.app_context(): \
    jobs = scheduler.get_jobs(); \
    print(f'Active schedules: {len(jobs)}'); \
    [print(f'- {j.id}: {j.next_run_time}') for j in jobs]"
```

---

## Performance e Limites

**Capacidade Testada**:
- ✅ **100-500 devices**: Performance excelente (<50ms dashboard)
- ✅ **500-1.000 devices**: Performance ótima (<80ms dashboard)
- ✅ **1.000-3.000 devices**: Performance boa (<100ms dashboard) - **Configuração atual**
- ⚠️ **3.000-5.000 devices**: Necessário ajustar workers para 75-100
- ❌ **>5.000 devices**: Requer Fase 3 (Celery + Redis + cache)

**Requisitos de Hardware (para 3.000 devices)**:
- **CPU**: 4+ cores
- **RAM**: 8GB+ (4GB mínimo)
- **Disco**: SSD recomendado (operações de I/O intensivas)
- **PostgreSQL**: max_connections=200+

Ver `ESCALABILIDADE.md` para benchmarks e otimizações detalhadas.

---

**Última Atualização**: 2025-11-19
**Versão**: Fase 2 Completa - Observabilidade + Escalabilidade
**Python**: 3.9+
**Banco de Dados**: PostgreSQL 12+ (ou SQLite para desenvolvimento)
**Capacidade**: Otimizado para 1.000-3.000 dispositivos
