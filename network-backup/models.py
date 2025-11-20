"""
SQLAlchemy Models para Network Backup System

Define todos os modelos de dados usando SQLAlchemy ORM:
- User: Usuários do sistema com autenticação
- Device: Dispositivos de rede a serem backed up
- Backup: Registros de backups realizados
- Schedule: Agendamentos de backup
- Provedor: Provedores/ISPs
- AuditLog: Log de auditoria de todas as ações
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pytz

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """
    Modelo de Usuário com autenticação.

    Suporta 3 roles:
    - admin: Acesso completo
    - operator: Pode gerenciar devices e rodar backups
    - viewer: Apenas visualização
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')  # admin, operator, viewer
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)

    # Relações
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        """Hash e armazena a senha."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica se a senha está correta."""
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles):
        """Verifica se o usuário tem um dos roles especificados."""
        return self.role in roles

    def is_admin(self):
        """Verifica se o usuário é admin."""
        return self.role == 'admin'

    def is_operator(self):
        """Verifica se o usuário é operator ou admin."""
        return self.role in ('admin', 'operator')

    def can_view(self):
        """Todos os usuários ativos podem visualizar."""
        return self.active

    def can_edit(self):
        """Apenas admin e operator podem editar."""
        return self.active and self.role in ('admin', 'operator')

    def can_delete(self):
        """Apenas admin pode deletar."""
        return self.active and self.role == 'admin'

    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'active': self.active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class Provedor(db.Model):
    """
    Modelo de Provedor/ISP/Cliente.

    Usado para organizar devices por provedor e armazenar informações completas
    de provedores e clientes.
    """
    __tablename__ = 'provedores'

    id = db.Column(db.Integer, primary_key=True)

    # Informações Básicas
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)  # Mantido para compatibilidade
    razao_social = db.Column(db.String(200))
    nome_fantasia = db.Column(db.String(200))
    cnpj = db.Column(db.String(18))  # Formato: XX.XXX.XXX/XXXX-XX

    __table_args__ = (
        db.UniqueConstraint('cnpj', name='uq_provedor_cnpj'),
    )

    # Contato
    telefone = db.Column(db.String(20))
    whatsapp = db.Column(db.String(20))
    email = db.Column(db.String(120))
    website = db.Column(db.String(200))
    contato_principal = db.Column(db.String(100))

    # Endereço
    cep = db.Column(db.String(9))  # Formato: XXXXX-XXX
    endereco = db.Column(db.String(200))
    numero = db.Column(db.String(10))
    complemento = db.Column(db.String(100))
    bairro = db.Column(db.String(100))
    cidade = db.Column(db.String(100))
    estado = db.Column(db.String(2))  # UF

    # Outros
    description = db.Column(db.Text)
    observacoes = db.Column(db.Text)
    active = db.Column(db.Boolean, default=True, server_default='1', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relações
    devices = db.relationship('Device', backref='provedor_obj', lazy='dynamic')

    def to_dict(self, include_devices=False):
        """Converte para dicionário."""
        data = {
            'id': self.id,
            'name': self.name,
            'razao_social': self.razao_social,
            'nome_fantasia': self.nome_fantasia,
            'cnpj': self.cnpj,
            'telefone': self.telefone,
            'whatsapp': self.whatsapp,
            'email': self.email,
            'website': self.website,
            'contato_principal': self.contato_principal,
            'cep': self.cep,
            'endereco': self.endereco,
            'numero': self.numero,
            'complemento': self.complemento,
            'bairro': self.bairro,
            'cidade': self.cidade,
            'estado': self.estado,
            'description': self.description,
            'observacoes': self.observacoes,
            'active': self.active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'device_count': self.devices.count()
        }

        if include_devices:
            data['devices'] = [d.to_dict() for d in self.devices.all()]

        return data

    def __repr__(self):
        return f'<Provedor {self.name}>'


class Device(db.Model):
    """
    Modelo de Dispositivo de Rede.

    Representa um device a ser backed up (router, switch, etc).
    IMPORTANTE: Senhas são armazenadas criptografadas.
    """
    __tablename__ = 'devices'
    __table_args__ = (
        # Índice composto para query otimizada: active devices ordenados por updated_at
        db.Index('idx_device_active_updated', 'active', 'updated_at'),
        # Índice para filtros por provedor
        db.Index('idx_device_provedor', 'provedor'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)  # IPv6 = 45 chars
    device_type = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # ssh, telnet, http, https
    port = db.Column(db.Integer, default=22, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.Text, nullable=False)  # Criptografada!
    enable_password = db.Column(db.Text)  # Criptografada!
    ssh_key_path = db.Column(db.String(255))  # Caminho para chave SSH (Fase 3)
    backup_command = db.Column(db.Text)
    provedor = db.Column(db.String(100), db.ForeignKey('provedores.name'), default='Sem_Provedor')
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)

    # Soft delete
    deleted_at = db.Column(db.DateTime, nullable=True, index=True)
    deleted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Relações - removido cascade para preservar backups
    backups = db.relationship('Backup', backref='device', lazy='dynamic')
    schedules = db.relationship('Schedule', backref='device', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self, include_credentials=False):
        """
        Converte para dicionário.

        Args:
            include_credentials: Se True, inclui senhas (criptografadas)
        """
        data = {
            'id': self.id,
            'name': self.name,
            'ip_address': self.ip_address,
            'device_type': self.device_type,
            'protocol': self.protocol,
            'port': self.port,
            'username': self.username,
            'provedor': self.provedor,
            'active': self.active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'deleted_at': self.deleted_at.isoformat() if self.deleted_at else None,
            'backup_count': self.backups.count()
        }

        if include_credentials:
            data['password'] = self.password
            data['enable_password'] = self.enable_password
            data['backup_command'] = self.backup_command
            data['ssh_key_path'] = self.ssh_key_path

        return data

    def __repr__(self):
        return f'<Device {self.name} ({self.ip_address})>'


class Backup(db.Model):
    """
    Modelo de Backup.

    Registra cada backup realizado.
    """
    __tablename__ = 'backups'
    __table_args__ = (
        # Índice composto para queries de backups por device e data
        db.Index('idx_backup_device_date', 'device_id', 'backup_date'),
        # Índice composto para filtrar backups por status e data
        db.Index('idx_backup_status_date', 'status', 'backup_date'),
    )

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True, index=True)  # Nullable para devices excluídos
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.Text, nullable=False)
    file_size = db.Column(db.BigInteger)  # Em bytes
    file_hash = db.Column(db.String(64))  # SHA256 hash (Fase 3)
    compressed = db.Column(db.Boolean, default=False)  # Se foi comprimido (Fase 3)
    is_delta = db.Column(db.Boolean, default=False)  # Se é backup incremental (Fase 3)
    parent_backup_id = db.Column(db.Integer, db.ForeignKey('backups.id'))  # Para deltas (Fase 3)
    status = db.Column(db.String(20), default='success', nullable=False, index=True)  # success, failed, incomplete
    error_message = db.Column(db.Text)
    backup_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    duration_seconds = db.Column(db.Float)  # Tempo que levou o backup (Fase 2)
    # Campos de validação (Fase 2.1)
    validation_status = db.Column(db.String(20), default='unknown')  # complete, incomplete, unknown
    validation_message = db.Column(db.Text)  # Mensagem detalhada da validação

    # Cache do nome do device para quando for excluído
    device_name_cached = db.Column(db.String(100))  # Nome do device no momento do backup
    device_ip_cached = db.Column(db.String(45))  # IP do device no momento do backup
    device_provedor_cached = db.Column(db.String(100))  # Provedor do device no momento do backup

    # Auto-referência para backups incrementais
    parent_backup = db.relationship('Backup', remote_side=[id], backref='child_backups')

    def to_dict(self):
        """Converte para dicionário."""
        # Usa dados do device se existir, senão usa cache
        if self.device:
            device_name = self.device.name
            device_ip = self.device.ip_address
            device_provedor = self.device.provedor
            device_deleted = self.device.deleted_at is not None
        else:
            device_name = self.device_name_cached
            device_ip = self.device_ip_cached
            device_provedor = self.device_provedor_cached
            device_deleted = True

        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': device_name,
            'device_ip': device_ip,
            'provedor': device_provedor,
            'device_deleted': device_deleted,
            'filename': self.filename,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'compressed': self.compressed,
            'is_delta': self.is_delta,
            'status': self.status,
            'error_message': self.error_message,
            'backup_date': self.backup_date.isoformat() if self.backup_date else None,
            'duration_seconds': self.duration_seconds,
            'validation_status': self.validation_status,
            'validation_message': self.validation_message
        }

    def __repr__(self):
        return f'<Backup {self.filename} [{self.status}]>'


class Schedule(db.Model):
    """
    Modelo de Agendamento.

    Define quando backups devem ser executados automaticamente.
    """
    __tablename__ = 'schedules'

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))  # NULL = todos os devices
    frequency = db.Column(db.String(20), nullable=False)  # daily, weekly, monthly
    time = db.Column(db.String(5), nullable=False)  # HH:MM
    day_of_week = db.Column(db.Integer)  # 0-6 (Monday-Sunday) para weekly
    day_of_month = db.Column(db.Integer)  # 1-31 para monthly
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)  # Calculado pelo scheduler
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.name if self.device else 'Todos os dispositivos',
            'device_ip': self.device.ip_address if self.device else None,
            'frequency': self.frequency,
            'time': self.time,
            'day_of_week': self.day_of_week,
            'day_of_month': self.day_of_month,
            'active': self.active,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        device_name = self.device.name if self.device else 'ALL'
        return f'<Schedule {device_name} {self.frequency} @ {self.time}>'


class AuditLog(db.Model):
    """
    Modelo de Log de Auditoria.

    Registra todas as ações importantes dos usuários.
    """
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    action = db.Column(db.String(50), nullable=False, index=True)  # create, update, delete, backup, login, etc
    resource_type = db.Column(db.String(50), nullable=False)  # device, backup, schedule, user, etc
    resource_id = db.Column(db.Integer)  # ID do recurso afetado
    details = db.Column(db.Text)  # JSON com detalhes da ação
    ip_address = db.Column(db.String(45))  # IP de onde veio a ação
    user_agent = db.Column(db.String(255))  # Browser/client info
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    def to_dict(self):
        """Converte para dicionário."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

    def __repr__(self):
        username = self.user.username if self.user else 'Unknown'
        return f'<AuditLog {username} {self.action} {self.resource_type}>'


# Índices adicionais para performance
db.Index('idx_backup_device_status', Backup.device_id, Backup.status)
db.Index('idx_backup_device_date', Backup.device_id, Backup.backup_date.desc())
db.Index('idx_audit_user_action', AuditLog.user_id, AuditLog.action)
db.Index('idx_audit_timestamp', AuditLog.timestamp.desc())
