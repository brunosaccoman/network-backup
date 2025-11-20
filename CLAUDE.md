# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## CRITICAL: Working Directory

**ALL commands must be run from `network-backup/` subdirectory:**

```bash
cd network-backup
```

## Essential Commands

```bash
# Development
flask run                              # Start dev server
flask db upgrade                       # Apply migrations
python manage.py create-admin          # Create admin user
python manage.py list-users            # List all users

# Testing individual components
python crypto_manager.py               # Test encryption system
python validators.py                   # Test input validators
python test_notifications.py           # Test notification system
python check_scheduler.py              # Check scheduler status

# Diagnostics
python diagnostico_login.py            # Debug login issues
python diagnostico_mimosa.py           # Debug Mimosa device backups

# Production
gunicorn -c gunicorn_config.py app:app
docker-compose up -d
docker-compose exec app python manage.py create-admin
```

## Key Files

- `app.py` - Flask application (routes, blueprints, error handlers)
- `models.py` - SQLAlchemy ORM models
- `backup_manager.py` - Protocol handlers (SSH/Telnet/HTTP) and backup logic
- `database.py` - SQLAlchemy wrapper maintaining backward-compatible interface
- `auth.py` - Authentication decorators (`@admin_required`, `@operator_required`)
- `config.py` - Environment-based configuration
- `crypto_manager.py` - AES-256 credential encryption with PBKDF2
- `scheduler.py` - APScheduler for automated backups
- `validators.py` - Input validation and sanitization

## Project Overview

Network device backup management system built with Flask. Automates configuration backups for network equipment (routers, switches, access points) using SSH, Telnet, and HTTP/HTTPS protocols. Optimized for 1,000-3,000+ devices.

**Key Features**:
- Role-based access control (admin/operator/viewer)
- AES-256 credential encryption with PBKDF2
- PostgreSQL/SQLite support via SQLAlchemy ORM
- Email/Webhook notifications
- 50 parallel backup workers

## Core Architecture

### Authentication & Authorization

Flask-Login with three roles in `models.py:User`:
- **admin**: Full access (users, devices, backups, schedules)
- **operator**: Manage devices and run backups
- **viewer**: Read-only access

Decorators from `auth.py`: `@login_required`, `@admin_required`, `@operator_required`, `@role_required('admin', 'operator')`

All actions logged to `audit_logs` table.

### Credential Encryption

`crypto_manager.py:CredentialManager` encrypts device passwords at rest:
- AES-256 via Fernet with PBKDF2-HMAC-SHA256 (100k iterations)
- Master key derived from `ENCRYPTION_KEY` env var

**Critical**: Changing `ENCRYPTION_KEY` invalidates all encrypted credentials.

### Database Layer

Two-layer architecture:
- `models.py` - SQLAlchemy ORM models (User, Device, Backup, Schedule, Provedor, AuditLog)
- `database.py` - Wrapper class providing backward-compatible dict-based interface with automatic encryption/decryption

Supports SQLite (dev) and PostgreSQL (prod) via `DATABASE_URL`.

### Backup Storage & Protocols

Storage structure: `backups/{Provedor}/{Device}/{IP}_{YYYYMMDD_HHMMSS}.txt`

`BackupManager` handles protocols:
- **SSH/Telnet**: Via Netmiko with device type mapping
- **HTTP/HTTPS**: Custom implementations for Mimosa and Intelbras devices

Auto-cleanup keeps N most recent backups per device (`BACKUP_RETENTION_COUNT`).

### Supported Device Types

**SSH/Telnet** (via Netmiko): `cisco_ios`, `cisco_nxos`, `cisco_asa`, `cisco_xr`, `juniper_junos`, `mikrotik_routeros`, `huawei`, `arista_eos`, `ubiquiti_airos`, `ubiquiti_edge`, `datacom`, `datacom_dmos`, `intelbras_radio`

**HTTP/HTTPS**: `mimosa`, `mimosa_c5c`, `mimosa_b5c`, `mimosa_b5`, `mimosa_a5c`, `intelbras_radio`

Default commands and Netmiko mappings defined in `backup_manager.py:_get_default_command()` and device_type_map. Custom commands can be set per device.

### Backup Data Flow

1. Request → Authentication → Fetch device(s) with decrypted credentials
2. `ThreadPoolExecutor` with `BACKUP_MAX_WORKERS` (default: 50)
3. Protocol handler routes to SSH/Telnet/HTTP method
4. Save file → Cleanup old backups → Insert DB record → Notify → Audit log

### Configuration

Environment-based configs in `config.py`: `DevelopmentConfig`, `TestingConfig`, `StagingConfig`, `ProductionConfig`

Selected via `FLASK_ENV` environment variable.

## Key Routes

All routes defined in `app.py`. Key endpoints:

- `/auth/login`, `/auth/logout` - Authentication
- `/devices`, `/backups`, `/schedules`, `/provedores` - CRUD pages
- `/users`, `/audit-logs` - Admin only
- `POST /backup/<id>`, `POST /backup/all` - Run backups (operator+)
- `/health`, `/health/ready`, `/health/detailed` - Health probes

## Setup & Deployment

### Initial Setup
```bash
cd network-backup
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

pip install -r requirements.txt

# Generate keys
python -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"

cp .env.example .env  # Edit with generated keys
flask db upgrade
python manage.py create-admin
```

### Database Migrations
```bash
flask db migrate -m "Description"  # Create
flask db upgrade                   # Apply
flask db downgrade                 # Revert
```

### Docker
```bash
docker-compose up -d
docker-compose exec app python manage.py create-admin
docker-compose exec app flask db upgrade
```

## Working with the Code

### Adding New Device Types
1. Add backup command in `backup_manager.py:_get_default_command()`
2. Add to `device_type_map` if Netmiko needs different type name
3. For HTTP devices: implement method like `_backup_mimosa_http()`

### Adding New Routes
```python
from auth import operator_required, log_audit

@app.route('/new-route')
@operator_required
def new_route():
    log_audit('action', 'resource_type', resource_id, {'key': 'value'})
    # ...
```

### Schema Changes
1. Modify `models.py`
2. `flask db migrate -m "Description"`
3. Review migration in `migrations/versions/`
4. `flask db upgrade`

## Environment Variables

**Required**:
- `ENCRYPTION_KEY` - Master key for credential encryption (32+ chars)
- `SECRET_KEY` - Flask session signing key (32+ chars)

**Database**:
- `DATABASE_URL` - Connection string (default: `sqlite:///backups.db`)
- `DB_POOL_SIZE` - Pool size (default: 50)

**Application**:
- `FLASK_ENV` - Environment: development/testing/staging/production
- `TIMEZONE` - System timezone (default: America/Porto_Velho)
- `BACKUP_RETENTION_COUNT` - Backups per device (default: 5)
- `BACKUP_MAX_WORKERS` - Concurrent workers (default: 50)

**Notifications** (see `.env.notifications.example`):
- `NOTIFICATION_EMAIL_ENABLED`, `NOTIFICATION_EMAIL_SMTP_HOST`, etc.
- `NOTIFICATION_WEBHOOK_ENABLED`, `NOTIFICATION_WEBHOOK_URL`

**SSL**: `SSL_VERIFY` (default: True), `SSL_CA_BUNDLE`

## Troubleshooting

**"ENCRYPTION_KEY não configurada!"**
- Set in `.env`: `python -c "import secrets; print(secrets.token_urlsafe(32))"`

**"cryptography.fernet.InvalidToken"**
- ENCRYPTION_KEY changed; restore original or re-enter all device passwords

**"relation does not exist"**
- Run `flask db upgrade`

**HTTP backup failures (Mimosa/Intelbras)**
- Verify HTTPS enabled on device, correct port (80/443)
- Run `python diagnostico_mimosa.py`
- Try `SSL_VERIFY=False` for self-signed certificates

**SSH/Telnet failures**
- Verify port (SSH=22, Telnet=23), credentials, device type mapping
- Check firewall allows connection

**Quick Health Check**:
```bash
python -c "import flask, sqlalchemy, netmiko, paramiko, cryptography; print('OK')"
python manage.py list-users
python check_scheduler.py
curl http://localhost:5000/health/ready
```

## Documentation

All docs in `network-backup/`:
- `SETUP.md` - Detailed setup
- `DEPLOY_PRODUCAO.md` - Production (Nginx, Gunicorn, PostgreSQL)
- `DOCKER_QUICKSTART.md` - Docker quick start
- `ESCALABILIDADE.md` - Scalability for 1,000-3,000+ devices
- `NOTIFICACOES.md` - Email/Webhook notifications
- `INSTALL_DEBIAN.md` - Debian/Ubuntu installation

## Performance

Dashboard <100ms with 3,000 devices. For >3,000 devices, increase `BACKUP_MAX_WORKERS` (75-100).

**Requirements**: 4+ cores, 8GB RAM, SSD, PostgreSQL max_connections=200+
