# Guia de Instalação - Network Backup System (Fase 1 - Segurança)

## Pré-requisitos

- Python 3.9+
- PostgreSQL 12+ (ou SQLite para desenvolvimento)
- Git

## Instalação Rápida

### 1. Clone e Navegue

```bash
cd network-backup
```

### 2. Crie Ambiente Virtual

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Instale Dependências

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure Variáveis de Ambiente

```bash
# Copie o arquivo de exemplo
cp .env.example .env

# Gere chaves seguras
python -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"

# Edite o arquivo .env e cole as chaves geradas
# No Windows: notepad .env
# No Linux/Mac: nano .env
```

**Configuração mínima para desenvolvimento (.env)**:
```env
ENCRYPTION_KEY=<chave_gerada_acima>
SECRET_KEY=<chave_gerada_acima>
DATABASE_URL=sqlite:///backups.db
DEBUG=True
FLASK_ENV=development
```

### 5. Configure PostgreSQL (Recomendado para Produção)

#### Opção A: PostgreSQL Local

```bash
# Instale PostgreSQL
# Windows: https://www.postgresql.org/download/windows/
# Linux (Ubuntu): sudo apt install postgresql postgresql-contrib

# Crie usuário e banco
sudo -u postgres psql
```

```sql
CREATE USER backup_user WITH PASSWORD 'sua_senha_forte';
CREATE DATABASE network_backup_dev OWNER backup_user;
GRANT ALL PRIVILEGES ON DATABASE network_backup_dev TO backup_user;
\q
```

Atualize .env:
```env
DATABASE_URL=postgresql://backup_user:sua_senha_forte@localhost:5432/network_backup_dev
```

#### Opção B: Docker Compose (Mais Fácil)

```bash
# Crie arquivo docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: backup_user
      POSTGRES_PASSWORD: backup_password
      POSTGRES_DB: network_backup_dev
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
EOF

# Inicie PostgreSQL
docker-compose up -d

# Atualize .env
# DATABASE_URL=postgresql://backup_user:backup_password@localhost:5432/network_backup_dev
```

### 6. Inicialize o Banco de Dados

```bash
# Inicialize as migrations
flask db init

# Crie a primeira migration
flask db migrate -m "Initial migration - Fase 1 security"

# Aplique as migrations
flask db upgrade
```

### 7. Crie Usuário Administrador

```bash
# Crie o primeiro usuário admin
flask create-admin

# Siga as instruções interativas:
# Username: admin
# Email: admin@sua-empresa.com
# Password: <senha_forte>
```

### 8. Migre Dados Existentes (Se Tiver SQLite Antigo)

```bash
# Se você já tinha dados no backups.db antigo
python migrate_to_postgres.py

# Siga as instruções para migrar:
# - Dispositivos
# - Backups
# - Schedules
# - Provedores
```

### 9. Teste a Criptografia

```bash
# Teste o sistema de criptografia
python crypto_manager.py

# Teste os validadores
python validators.py
```

### 10. Inicie a Aplicação

```bash
# Desenvolvimento
flask run

# Ou com mais controle
python app.py

# Produção (com Gunicorn)
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## Acesso

- **URL**: http://localhost:5000
- **Login**: Use as credenciais criadas no passo 7

## Comandos Úteis

### Gerenciamento de Banco

```bash
# Criar nova migration (após alterar models)
flask db migrate -m "Descrição da mudança"

# Aplicar migrations
flask db upgrade

# Reverter última migration
flask db downgrade

# Ver histórico de migrations
flask db history

# Ver status atual
flask db current
```

### Gerenciamento de Usuários

```bash
# Criar admin
flask create-admin

# Criar operador
flask create-user --role operator

# Criar viewer (apenas leitura)
flask create-user --role viewer

# Listar usuários
flask list-users

# Desativar usuário
flask deactivate-user <username>
```

### Testes

```bash
# Testar criptografia
python crypto_manager.py

# Testar validadores
python validators.py

# Testar conexão com banco
flask db current
```

## Troubleshooting

### Erro: "ENCRYPTION_KEY não configurada!"

**Solução**: Configure a variável no arquivo `.env`:
```bash
python -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
```
Cole o resultado no `.env`.

### Erro: "could not connect to server: Connection refused"

**Solução**: PostgreSQL não está rodando. Inicie o serviço:
```bash
# Linux
sudo systemctl start postgresql

# Docker
docker-compose up -d

# Windows
# Inicie pelo Services (services.msc)
```

### Erro: "relation does not exist"

**Solução**: Rode as migrations:
```bash
flask db upgrade
```

### Erro: "cryptography.fernet.InvalidToken"

**Solução**: A ENCRYPTION_KEY mudou e não consegue descriptografar senhas antigas. Opções:
1. Restaure a ENCRYPTION_KEY original
2. Ou recadastre os dispositivos com as senhas novamente

### Erro ao importar psycopg2

**Solução**: Instale as dependências do PostgreSQL:
```bash
# Ubuntu/Debian
sudo apt-get install libpq-dev python3-dev

# CentOS/RHEL
sudo yum install postgresql-devel python-devel

# Reinstale
pip install --upgrade psycopg2-binary
```

## Segurança - Checklist

- [ ] ENCRYPTION_KEY configurada e segura (32+ caracteres)
- [ ] SECRET_KEY configurada e diferente da ENCRYPTION_KEY
- [ ] `.env` adicionado ao `.gitignore`
- [ ] PostgreSQL com senha forte
- [ ] DEBUG=False em produção
- [ ] SSL_VERIFY=True em produção
- [ ] SESSION_COOKIE_SECURE=True em produção (se usar HTTPS)
- [ ] Firewall configurado (apenas portas 5000 e 5432 necessárias)
- [ ] Backups do PostgreSQL configurados
- [ ] Usuário admin com senha forte

## Próximos Passos

1. ✅ Fase 1 concluída (Segurança)
2. ⏭️ Fase 2: Observabilidade (Logs, Métricas, Notificações)
3. ⏭️ Fase 3: Funcionalidades Avançadas (Backup Paralelo, Diff, Restore)
4. ⏭️ Fase 4: Enterprise Features (Multi-tenancy, API, Cloud)

## Suporte

- Documentação completa: Ver `CLAUDE.md`
- Roadmap de melhorias: Ver `claude.rc`
- Issues: Reportar problemas encontrados

---

**Última atualização**: 2025-01-18
**Versão**: Fase 1 - Segurança e Fundações
