#!/usr/bin/env python
"""
Manage.py - Comandos CLI para gerenciamento do sistema

Comandos disponíveis:
- create-admin: Cria um usuário administrador
- create-user: Cria um usuário (operator ou viewer)
- migrate-from-sqlite: Migra dados do SQLite para PostgreSQL
"""

import click
import os
import sys
from getpass import getpass

# Adicionar path do projeto
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User, Device, Backup, Schedule, Provedor
from validators import InputValidator
import sqlite3
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.group()
def cli():
    """Comandos de gerenciamento do Network Backup System."""
    pass


@cli.command()
@click.option('--username', prompt=True, help='Nome de usuário')
@click.option('--email', prompt=True, help='Email do administrador')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Senha')
def create_admin(username, email, password):
    """Cria um usuário administrador."""
    with app.app_context():
        try:
            validator = InputValidator()

            # Validar inputs
            username = validator.validate_username(username)
            email = validator.validate_email(email)

            # Verificar se já existe
            if User.query.filter_by(username=username).first():
                click.echo(f"Erro: Usuário '{username}' já existe.", err=True)
                sys.exit(1)

            if User.query.filter_by(email=email).first():
                click.echo(f"Erro: Email '{email}' já está em uso.", err=True)
                sys.exit(1)

            # Criar admin
            admin = User(
                username=username,
                email=email,
                role='admin',
                active=True
            )
            admin.set_password(password)

            db.session.add(admin)
            db.session.commit()

            click.echo(f"✓ Administrador '{username}' criado com sucesso!")
            click.echo(f"  Email: {email}")
            click.echo(f"  Role: admin")

        except Exception as e:
            click.echo(f"Erro ao criar administrador: {e}", err=True)
            sys.exit(1)


@cli.command()
@click.option('--username', prompt=True, help='Nome de usuário')
@click.option('--email', prompt=True, help='Email')
@click.option('--role', type=click.Choice(['operator', 'viewer']), prompt=True, help='Role do usuário')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Senha')
def create_user(username, email, role, password):
    """Cria um usuário (operator ou viewer)."""
    with app.app_context():
        try:
            validator = InputValidator()

            # Validar
            username = validator.validate_username(username)
            email = validator.validate_email(email)
            role = validator.validate_role(role)

            # Verificar duplicatas
            if User.query.filter_by(username=username).first():
                click.echo(f"Erro: Usuário '{username}' já existe.", err=True)
                sys.exit(1)

            if User.query.filter_by(email=email).first():
                click.echo(f"Erro: Email '{email}' já está em uso.", err=True)
                sys.exit(1)

            # Criar usuário
            user = User(
                username=username,
                email=email,
                role=role,
                active=True
            )
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            click.echo(f"✓ Usuário '{username}' criado com sucesso!")
            click.echo(f"  Email: {email}")
            click.echo(f"  Role: {role}")

        except Exception as e:
            click.echo(f"Erro ao criar usuário: {e}", err=True)
            sys.exit(1)


@cli.command()
def list_users():
    """Lista todos os usuários."""
    with app.app_context():
        users = User.query.order_by(User.username).all()

        if not users:
            click.echo("Nenhum usuário encontrado.")
            return

        click.echo("\n" + "="*60)
        click.echo("USUÁRIOS DO SISTEMA")
        click.echo("="*60)

        for user in users:
            status = "✓ Ativo" if user.active else "✗ Inativo"
            click.echo(f"\n{user.username} ({user.role})")
            click.echo(f"  Email: {user.email}")
            click.echo(f"  Status: {status}")
            click.echo(f"  Criado: {user.created_at}")
            if user.last_login:
                click.echo(f"  Último login: {user.last_login}")

        click.echo("\n" + "="*60)
        click.echo(f"Total: {len(users)} usuários")


@cli.command()
@click.argument('username')
def deactivate_user(username):
    """Desativa um usuário."""
    with app.app_context():
        user = User.query.filter_by(username=username).first()

        if not user:
            click.echo(f"Erro: Usuário '{username}' não encontrado.", err=True)
            sys.exit(1)

        user.active = False
        db.session.commit()

        click.echo(f"✓ Usuário '{username}' desativado com sucesso.")


@cli.command()
@click.argument('username')
def activate_user(username):
    """Ativa um usuário."""
    with app.app_context():
        user = User.query.filter_by(username=username).first()

        if not user:
            click.echo(f"Erro: Usuário '{username}' não encontrado.", err=True)
            sys.exit(1)

        user.active = True
        db.session.commit()

        click.echo(f"✓ Usuário '{username}' ativado com sucesso.")


@cli.command()
@click.option('--sqlite-db', default='backups.db', help='Caminho do banco SQLite antigo')
@click.confirmation_option(prompt='ATENÇÃO: Isso vai migrar dados do SQLite para o PostgreSQL configurado. Continuar?')
def migrate_from_sqlite(sqlite_db):
    """Migra dados do SQLite para PostgreSQL."""
    with app.app_context():
        try:
            click.echo(f"Conectando ao SQLite: {sqlite_db}")

            if not os.path.exists(sqlite_db):
                click.echo(f"Erro: Arquivo '{sqlite_db}' não encontrado.", err=True)
                sys.exit(1)

            # Conectar ao SQLite
            sqlite_conn = sqlite3.connect(sqlite_db)
            sqlite_conn.row_factory = sqlite3.Row
            sqlite_cursor = sqlite_conn.cursor()

            # Verificar tabelas
            sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in sqlite_cursor.fetchall()]
            click.echo(f"Tabelas encontradas: {', '.join(tables)}")

            # Migrar Provedores
            if 'provedores' in tables:
                click.echo("\n[1/4] Migrando provedores...")
                sqlite_cursor.execute("SELECT * FROM provedores")
                provedores_data = sqlite_cursor.fetchall()

                for row in provedores_data:
                    existing = Provedor.query.filter_by(name=row['name']).first()
                    if not existing:
                        provedor = Provedor(
                            name=row['name'],
                            description=row.get('description')
                        )
                        db.session.add(provedor)

                db.session.commit()
                click.echo(f"  ✓ {len(provedores_data)} provedores migrados")

            # Migrar Devices (SEM senhas - precisam ser reconfiguradas)
            click.echo("\n[2/4] Migrando devices (ATENÇÃO: Senhas precisam ser reconfiguradas)...")
            sqlite_cursor.execute("SELECT * FROM devices")
            devices_data = sqlite_cursor.fetchall()

            device_id_map = {}  # Mapear IDs antigos para novos

            for row in devices_data:
                # Verificar se já existe
                existing = Device.query.filter_by(ip_address=row['ip_address']).first()
                if existing:
                    device_id_map[row['id']] = existing.id
                    continue

                # AVISO: Senhas antigas não podem ser migradas pois estavam em texto plano
                # Criar com senha temporária que precisa ser mudada
                device = Device(
                    name=row['name'],
                    ip_address=row['ip_address'],
                    device_type=row['device_type'],
                    protocol=row['protocol'],
                    port=row.get('port', 22),
                    username=row['username'],
                    password='SENHA_TEMPORARIA_ALTERAR',  # Placeholder
                    enable_password=None,
                    backup_command=row.get('backup_command'),
                    provedor=row.get('provedor', 'Sem_Provedor'),
                    active=bool(row.get('active', 1))
                )
                db.session.add(device)
                db.session.flush()  # Get ID
                device_id_map[row['id']] = device.id

            db.session.commit()
            click.echo(f"  ✓ {len(devices_data)} devices migrados")
            click.echo("  ⚠ IMPORTANTE: Senhas dos devices precisam ser reconfiguradas!")

            # Migrar Schedules
            if 'schedules' in tables:
                click.echo("\n[3/4] Migrando schedules...")
                sqlite_cursor.execute("SELECT * FROM schedules")
                schedules_data = sqlite_cursor.fetchall()

                for row in schedules_data:
                    old_device_id = row['device_id']
                    new_device_id = device_id_map.get(old_device_id) if old_device_id else None

                    schedule = Schedule(
                        device_id=new_device_id,
                        frequency=row['frequency'],
                        time=row['time'],
                        day_of_week=row.get('day_of_week'),
                        day_of_month=row.get('day_of_month'),
                        active=bool(row.get('active', 1))
                    )
                    db.session.add(schedule)

                db.session.commit()
                click.echo(f"  ✓ {len(schedules_data)} schedules migrados")

            # Migrar Backups (apenas registros, arquivos já existem)
            click.echo("\n[4/4] Migrando registros de backups...")
            sqlite_cursor.execute("SELECT * FROM backups")
            backups_data = sqlite_cursor.fetchall()

            for row in backups_data:
                old_device_id = row['device_id']
                new_device_id = device_id_map.get(old_device_id)

                if not new_device_id:
                    continue  # Skip se device não foi migrado

                backup = Backup(
                    device_id=new_device_id,
                    filename=row['filename'],
                    file_path=row['file_path'],
                    file_size=row.get('file_size'),
                    status=row.get('status', 'success'),
                    error_message=row.get('error_message'),
                    backup_date=row.get('backup_date')
                )
                db.session.add(backup)

            db.session.commit()
            click.echo(f"  ✓ {len(backups_data)} registros de backup migrados")

            sqlite_conn.close()

            click.echo("\n" + "="*60)
            click.echo("MIGRAÇÃO CONCLUÍDA COM SUCESSO!")
            click.echo("="*60)
            click.echo("\n⚠ PRÓXIMOS PASSOS IMPORTANTES:")
            click.echo("1. Reconfigure as senhas de TODOS os devices")
            click.echo("2. Teste backups manualmente antes de confiar nos schedules")
            click.echo("3. Faça backup do banco PostgreSQL")
            click.echo("4. Considere renomear/arquivar o backups.db antigo")

        except Exception as e:
            db.session.rollback()
            click.echo(f"\nErro durante migração: {e}", err=True)
            import traceback
            traceback.print_exc()
            sys.exit(1)


@cli.command()
def init_db():
    """Inicializa o banco de dados (cria todas as tabelas)."""
    with app.app_context():
        try:
            db.create_all()
            click.echo("✓ Banco de dados inicializado com sucesso!")
            click.echo("  Todas as tabelas foram criadas.")

            # Verificar se existem usuários
            user_count = User.query.count()
            if user_count == 0:
                click.echo("\n⚠ Nenhum usuário encontrado.")
                click.echo("  Execute 'python manage.py create-admin' para criar um administrador.")

        except Exception as e:
            click.echo(f"Erro ao inicializar banco: {e}", err=True)
            sys.exit(1)


if __name__ == '__main__':
    cli()
