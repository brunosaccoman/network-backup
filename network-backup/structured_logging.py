"""
Structured Logging System - Fase 2: Observabilidade

Sistema de logging estruturado usando structlog com:
- Logs em formato JSON para facilitar parsing
- IDs de correlação para rastrear requisições
- Contexto rico (usuário, dispositivo, operação)
- Integração com logging padrão do Python
"""

import logging
import structlog
import uuid
from datetime import datetime
from flask import g, request, has_request_context
from typing import Any, Dict
import os


def add_correlation_id(logger, method_name, event_dict):
    """
    Adiciona ID de correlação aos logs.

    Cada requisição HTTP recebe um UUID único que é propagado
    através de todos os logs relacionados.
    """
    if has_request_context():
        # Pega ou cria correlation_id para esta requisição
        if not hasattr(g, 'correlation_id'):
            g.correlation_id = str(uuid.uuid4())
        event_dict['correlation_id'] = g.correlation_id

    return event_dict


def add_request_context(logger, method_name, event_dict):
    """
    Adiciona contexto da requisição HTTP aos logs.

    Inclui: método HTTP, path, IP do cliente, user-agent.
    """
    if has_request_context():
        event_dict['request'] = {
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown')[:100]  # Limita tamanho
        }

        # Adiciona query params se não forem sensíveis
        if request.args:
            # Remove parâmetros sensíveis
            safe_args = {k: v for k, v in request.args.items()
                        if k.lower() not in ['password', 'token', 'secret', 'key']}
            if safe_args:
                event_dict['request']['query_params'] = safe_args

    return event_dict


def add_user_context(logger, method_name, event_dict):
    """
    Adiciona contexto do usuário autenticado aos logs.
    """
    if has_request_context():
        try:
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                event_dict['user'] = {
                    'id': current_user.id,
                    'username': current_user.username,
                    'role': current_user.role
                }
        except Exception:
            # Se não conseguir pegar usuário, ignora
            pass

    return event_dict


def add_timestamp(logger, method_name, event_dict):
    """Adiciona timestamp ISO 8601 aos logs."""
    event_dict['timestamp'] = datetime.utcnow().isoformat() + 'Z'
    return event_dict


def add_application_context(logger, method_name, event_dict):
    """Adiciona contexto da aplicação."""
    event_dict['application'] = {
        'name': 'network-backup',
        'environment': os.environ.get('FLASK_ENV', 'development'),
        'version': '1.0.0-fase2'
    }
    return event_dict


def censor_sensitive_data(logger, method_name, event_dict):
    """
    Remove ou mascara dados sensíveis dos logs.

    Procura por campos com nomes suspeitos e os substitui por [REDACTED].
    """
    sensitive_keys = [
        'password', 'secret', 'token', 'api_key', 'private_key',
        'access_token', 'refresh_token', 'encryption_key', 'credential'
    ]

    def censor_dict(d: Dict) -> Dict:
        """Recursivamente censura dicionários."""
        censored = {}
        for key, value in d.items():
            # Verifica se a chave é sensível
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                censored[key] = '[REDACTED]'
            # Se o valor é um dict, censura recursivamente
            elif isinstance(value, dict):
                censored[key] = censor_dict(value)
            # Se é uma lista, processa cada item
            elif isinstance(value, list):
                censored[key] = [
                    censor_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                censored[key] = value
        return censored

    return censor_dict(event_dict)


def configure_structured_logging(app=None, log_level='INFO', json_logs=True):
    """
    Configura o sistema de logging estruturado.

    Args:
        app: Instância Flask (opcional)
        log_level: Nível de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_logs: Se True, usa formato JSON. Se False, usa formato legível para humanos.

    Returns:
        Logger configurado
    """
    # Determina se deve usar JSON baseado no ambiente
    if app:
        environment = app.config.get('FLASK_ENV', 'development')
        # Em produção, sempre JSON. Em dev, pode ser legível
        if environment == 'production':
            json_logs = True
        elif environment == 'development' and json_logs is None:
            json_logs = False  # Formato legível em dev por padrão

    # Configura processors do structlog
    processors = [
        structlog.contextvars.merge_contextvars,
        add_timestamp,
        add_application_context,
        add_correlation_id,
        add_request_context,
        add_user_context,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        censor_sensitive_data,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Adiciona formatador apropriado
    if json_logs:
        # Formato JSON para produção
        processors.append(structlog.processors.JSONRenderer())
    else:
        # Formato legível para desenvolvimento
        processors.append(structlog.dev.ConsoleRenderer())

    # Configura structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configura logging padrão do Python para usar structlog
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, log_level.upper()),
        force=True  # Sobrescreve configuração existente
    )

    # Se tem app Flask, adiciona request logging
    if app:
        setup_request_logging(app)

    return structlog.get_logger()


def setup_request_logging(app):
    """
    Configura logging automático de requisições HTTP.

    Adiciona hooks before_request e after_request para logar
    todas as requisições com duração.
    """
    @app.before_request
    def before_request_logging():
        """Marca início da requisição."""
        g.request_start_time = datetime.utcnow()

    @app.after_request
    def after_request_logging(response):
        """
        Loga requisição completa com duração e status.

        Não loga health checks para evitar poluir logs.
        """
        # Pula health checks
        if request.path.startswith('/health'):
            return response

        # Calcula duração
        duration_ms = None
        if hasattr(g, 'request_start_time'):
            duration = datetime.utcnow() - g.request_start_time
            duration_ms = duration.total_seconds() * 1000

        # Pega logger
        logger = structlog.get_logger()

        # Log com nível apropriado baseado no status code
        log_method = logger.info
        if response.status_code >= 500:
            log_method = logger.error
        elif response.status_code >= 400:
            log_method = logger.warning

        log_method(
            "HTTP request completed",
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2) if duration_ms else None,
            response_size=response.content_length
        )

        return response


def get_logger(name=None):
    """
    Retorna um logger estruturado.

    Args:
        name: Nome do logger (geralmente __name__ do módulo)

    Returns:
        Logger configurado com structlog

    Example:
        logger = get_logger(__name__)
        logger.info("Backup started", device_id=123, device_name="Router-01")
    """
    return structlog.get_logger(name)


class StructuredLoggerAdapter:
    """
    Adapter para facilitar migração de código existente.

    Permite usar logger.info/warning/error mas com suporte a
    campos estruturados via keyword arguments.

    Example:
        logger = StructuredLoggerAdapter(__name__)
        logger.info("Backup completed",
                   device_id=123,
                   file_size=1024,
                   duration_seconds=5.2)
    """

    def __init__(self, name=None):
        self.logger = structlog.get_logger(name)

    def debug(self, message, **kwargs):
        self.logger.debug(message, **kwargs)

    def info(self, message, **kwargs):
        self.logger.info(message, **kwargs)

    def warning(self, message, **kwargs):
        self.logger.warning(message, **kwargs)

    def error(self, message, **kwargs):
        self.logger.error(message, **kwargs)

    def critical(self, message, **kwargs):
        self.logger.critical(message, **kwargs)

    def exception(self, message, **kwargs):
        """Loga exceção com traceback."""
        self.logger.exception(message, **kwargs)


# Funções helper para adicionar contexto aos logs

def log_backup_operation(device_id: int, device_name: str, operation: str):
    """
    Adiciona contexto de operação de backup aos logs da thread atual.

    Todos os logs subsequentes na mesma thread incluirão este contexto.

    Args:
        device_id: ID do dispositivo
        device_name: Nome do dispositivo
        operation: Tipo de operação (manual, scheduled, etc)
    """
    structlog.contextvars.bind_contextvars(
        backup_operation=operation,
        device_id=device_id,
        device_name=device_name
    )


def log_schedule_operation(schedule_id: int, frequency: str):
    """Adiciona contexto de agendamento aos logs."""
    structlog.contextvars.bind_contextvars(
        schedule_id=schedule_id,
        schedule_frequency=frequency
    )


def clear_context():
    """Limpa contexto de logging (útil em threads)."""
    structlog.contextvars.clear_contextvars()


# Configuração para testes
if __name__ == '__main__':
    # Testa logging estruturado
    logger = configure_structured_logging(log_level='DEBUG', json_logs=False)

    print("=== Teste de Logging Estruturado ===\n")

    logger.info("Simple log message")

    logger.info(
        "Backup started",
        device_id=123,
        device_name="Router-01",
        device_type="cisco_ios"
    )

    logger.warning(
        "Backup timeout",
        device_id=456,
        timeout_seconds=60
    )

    logger.error(
        "Backup failed",
        device_id=789,
        error="Connection refused",
        retry_count=3
    )

    # Testa censura de dados sensíveis
    logger.info(
        "User login",
        username="admin",
        password="secret123",  # Será censurado
        token="xyz789"  # Será censurado
    )

    print("\n✓ Testes concluídos!")
