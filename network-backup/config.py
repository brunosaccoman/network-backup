"""
Configuração da Aplicação Flask

Carrega configurações de variáveis de ambiente e define
configurações para diferentes ambientes (dev, staging, prod).
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Carregar variáveis de ambiente do arquivo .env
load_dotenv()


class Config:
    """Configuração base (comum a todos os ambientes)."""

    # Base directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError(
            "SECRET_KEY não configurada! "
            "Configure a variável de ambiente SECRET_KEY.\n"
            "Para gerar: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )

    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    if not ENCRYPTION_KEY:
        raise ValueError(
            "ENCRYPTION_KEY não configurada! "
            "Configure a variável de ambiente ENCRYPTION_KEY.\n"
            "Para gerar: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///backups.db')

    # Fix for PostgreSQL URL (Heroku usa postgres://, SQLAlchemy precisa postgresql://)
    if SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = os.environ.get('SQLALCHEMY_ECHO', 'False').lower() == 'true'
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.environ.get('DB_POOL_SIZE', 50)),  # Aumentado de 10 para 50 (suporta 1000+ devices)
        'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', 100)),  # Aumentado de 20 para 100
        'pool_timeout': int(os.environ.get('DB_POOL_TIMEOUT', 30)),
        'pool_recycle': 3600,  # Recicla conexões a cada 1 hora
        'pool_pre_ping': True,  # Testa conexões antes de usar
    }

    # Session Configuration
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=int(os.environ.get('SESSION_PERMANENT_LIFETIME', 7)))

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # Token nunca expira
    WTF_CSRF_SSL_STRICT = os.environ.get('WTF_CSRF_SSL_STRICT', 'False').lower() == 'true'

    # Rate Limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '100/minute')
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')

    # Backup Configuration
    BACKUP_DIR = os.path.join(BASE_DIR, os.environ.get('BACKUP_DIR', 'backups'))
    BACKUP_RETENTION_COUNT = int(os.environ.get('BACKUP_RETENTION_COUNT', 5))
    BACKUP_TIMEOUT = int(os.environ.get('BACKUP_TIMEOUT', 60))
    BACKUP_MAX_WORKERS = int(os.environ.get('BACKUP_MAX_WORKERS', 50))  # Aumentado de 10 para 50 (otimizado para 1000+ devices)
    BACKUP_COMPRESSION = os.environ.get('BACKUP_COMPRESSION', 'False').lower() == 'true'

    # SSL/TLS
    SSL_VERIFY = os.environ.get('SSL_VERIFY', 'True').lower() == 'true'
    SSL_CA_BUNDLE = os.environ.get('SSL_CA_BUNDLE')
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'False').lower() == 'true'

    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_DIR = os.path.join(BASE_DIR, os.environ.get('LOG_DIR', 'logs'))
    LOG_MAX_SIZE = int(os.environ.get('LOG_MAX_SIZE', 10)) * 1024 * 1024  # MB to bytes
    LOG_BACKUP_COUNT = int(os.environ.get('LOG_BACKUP_COUNT', 10))
    LOG_FORMAT = os.environ.get('LOG_FORMAT', 'json')  # json or text

    # Timezone
    TIMEZONE = os.environ.get('TIMEZONE', 'America/Porto_Velho')

    # File Upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size

    # Flask-Login
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_HTTPONLY = True

    @staticmethod
    def init_app(app):
        """Initialize application."""
        # Criar diretórios necessários
        os.makedirs(Config.BACKUP_DIR, exist_ok=True)
        os.makedirs(Config.LOG_DIR, exist_ok=True)


class DevelopmentConfig(Config):
    """Configuração para desenvolvimento."""

    DEBUG = True
    TESTING = False

    # Auto-reload de templates em desenvolvimento
    TEMPLATES_AUTO_RELOAD = True

    # Mais verbose em desenvolvimento
    SQLALCHEMY_ECHO = os.environ.get('SQLALCHEMY_ECHO', 'True').lower() == 'true'

    # CSRF menos restrito em dev
    WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', 'True').lower() == 'true'

    # Rate limiting mais permissivo
    RATELIMIT_DEFAULT = '1000/minute'


class TestingConfig(Config):
    """Configuração para testes."""

    TESTING = True
    DEBUG = True

    # Usa banco em memória para testes
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

    # Desabilita CSRF em testes
    WTF_CSRF_ENABLED = False

    # Desabilita rate limiting em testes
    RATELIMIT_ENABLED = False

    # Senhas mais simples para testes
    BCRYPT_LOG_ROUNDS = 4  # Mais rápido para testes


class ProductionConfig(Config):
    """Configuração para produção."""

    DEBUG = False
    TESTING = False

    # HTTPS - lê do ambiente para permitir HTTP em redes internas
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
    REMEMBER_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME', 'https')

    # CSRF - lê do ambiente
    WTF_CSRF_SSL_STRICT = os.environ.get('WTF_CSRF_SSL_STRICT', 'True').lower() == 'true'

    # SSL - lê do ambiente
    SSL_VERIFY = os.environ.get('SSL_VERIFY', 'True').lower() == 'true'
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'True').lower() == 'true'

    @staticmethod
    def init_app(app):
        """Initialize production application."""
        Config.init_app(app)

        # Log para stderr em produção
        import logging
        from logging.handlers import SysLogHandler

        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.WARNING)
        app.logger.addHandler(syslog_handler)


class StagingConfig(ProductionConfig):
    """Configuração para staging (similar a produção mas com debug)."""

    DEBUG = True


# Mapeamento de ambientes
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config():
    """
    Retorna a configuração apropriada baseada em FLASK_ENV.

    Returns:
        Config class apropriada para o ambiente atual
    """
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
