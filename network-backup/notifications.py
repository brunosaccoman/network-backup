"""
Notification System - Fase 2: Observabilidade

Sistema de notificações para alertar sobre eventos importantes:
- Backup failures (falhas de backup)
- Backup success (opcional)
- System health issues
- Scheduler issues

Suporta múltiplos canais:
- Email (SMTP)
- Webhooks (genéricos - Slack, Discord, Teams, etc)
"""

import logging
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
import os
from config import NOTIFICATION_TIMEOUT

logger = logging.getLogger(__name__)


class NotificationLevel(Enum):
    """Níveis de notificação."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationChannel(Enum):
    """Canais de notificação disponíveis."""
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"


class NotificationConfig:
    """Configuração de notificações carregada de variáveis de ambiente."""

    def __init__(self):
        # Email configuration
        self.email_enabled = os.environ.get('NOTIFICATION_EMAIL_ENABLED', 'False').lower() == 'true'
        self.email_smtp_host = os.environ.get('NOTIFICATION_EMAIL_SMTP_HOST', 'smtp.gmail.com')
        self.email_smtp_port = int(os.environ.get('NOTIFICATION_EMAIL_SMTP_PORT', '587'))
        self.email_use_tls = os.environ.get('NOTIFICATION_EMAIL_USE_TLS', 'True').lower() == 'true'
        self.email_username = os.environ.get('NOTIFICATION_EMAIL_USERNAME', '')
        self.email_password = os.environ.get('NOTIFICATION_EMAIL_PASSWORD', '')
        self.email_from = os.environ.get('NOTIFICATION_EMAIL_FROM', self.email_username)
        self.email_to = os.environ.get('NOTIFICATION_EMAIL_TO', '').split(',')

        # Webhook configuration
        self.webhook_enabled = os.environ.get('NOTIFICATION_WEBHOOK_ENABLED', 'False').lower() == 'true'
        self.webhook_url = os.environ.get('NOTIFICATION_WEBHOOK_URL', '')
        self.webhook_headers = {}  # Pode ser expandido para headers customizados

        # Notification filters
        self.notify_on_success = os.environ.get('NOTIFICATION_ON_SUCCESS', 'False').lower() == 'true'
        self.notify_on_failure = os.environ.get('NOTIFICATION_ON_FAILURE', 'True').lower() == 'true'
        self.notify_on_warning = os.environ.get('NOTIFICATION_ON_WARNING', 'True').lower() == 'true'

        # Min level to notify (INFO, WARNING, ERROR, CRITICAL)
        self.min_level = os.environ.get('NOTIFICATION_MIN_LEVEL', 'WARNING').upper()

    def is_enabled(self) -> bool:
        """Verifica se algum canal de notificação está habilitado."""
        return self.email_enabled or self.webhook_enabled

    def should_notify(self, level: NotificationLevel) -> bool:
        """Verifica se deve notificar baseado no nível."""
        level_priority = {
            NotificationLevel.INFO: 0,
            NotificationLevel.WARNING: 1,
            NotificationLevel.ERROR: 2,
            NotificationLevel.CRITICAL: 3
        }
        min_priority = level_priority.get(NotificationLevel[self.min_level], 1)
        return level_priority.get(level, 0) >= min_priority


class NotificationManager:
    """Gerenciador central de notificações."""

    def __init__(self, config: Optional[NotificationConfig] = None):
        """
        Inicializa o notification manager.

        Args:
            config: Configuração de notificações (usa padrão se None)
        """
        self.config = config or NotificationConfig()
        self.logger = logging.getLogger(__name__)

        if self.config.is_enabled():
            self.logger.info("Notification system initialized",
                           extra={
                               'email_enabled': self.config.email_enabled,
                               'webhook_enabled': self.config.webhook_enabled,
                               'min_level': self.config.min_level
                           })
        else:
            self.logger.info("Notification system disabled")

    def notify_backup_failure(self, device_name: str, device_id: int, error: str):
        """
        Notifica sobre falha em backup.

        Args:
            device_name: Nome do dispositivo
            device_id: ID do dispositivo
            error: Mensagem de erro
        """
        subject = f"🔴 Backup Failed: {device_name}"
        message = f"""
Backup Failure Alert

Device: {device_name} (ID: {device_id})
Status: FAILED
Error: {error}
Time: {datetime.now().isoformat()}

Please check the device configuration and network connectivity.
"""

        self._send_notification(
            subject=subject,
            message=message,
            level=NotificationLevel.ERROR,
            event_type="backup_failure",
            context={
                'device_name': device_name,
                'device_id': device_id,
                'error': error
            }
        )

    def notify_backup_success(self, device_name: str, device_id: int, file_size: int):
        """
        Notifica sobre sucesso em backup.

        Args:
            device_name: Nome do dispositivo
            device_id: ID do dispositivo
            file_size: Tamanho do arquivo de backup
        """
        if not self.config.notify_on_success:
            return

        subject = f"✅ Backup Success: {device_name}"
        message = f"""
Backup Success

Device: {device_name} (ID: {device_id})
Status: SUCCESS
File Size: {file_size} bytes
Time: {datetime.now().isoformat()}
"""

        self._send_notification(
            subject=subject,
            message=message,
            level=NotificationLevel.INFO,
            event_type="backup_success",
            context={
                'device_name': device_name,
                'device_id': device_id,
                'file_size': file_size
            }
        )

    def notify_multiple_failures(self, failed_devices: List[Dict[str, Any]]):
        """
        Notifica sobre múltiplas falhas de backup (backup all).

        Args:
            failed_devices: Lista de dispositivos que falharam
        """
        if not failed_devices:
            return

        count = len(failed_devices)
        subject = f"🔴 Multiple Backup Failures: {count} devices"

        device_list = "\n".join([
            f"  - {d['name']} (ID: {d['id']}): {d['error']}"
            for d in failed_devices[:10]  # Limita a 10 para não ficar muito grande
        ])

        if count > 10:
            device_list += f"\n  ... and {count - 10} more devices"

        message = f"""
Multiple Backup Failures Detected

Total Failed: {count} devices
Time: {datetime.now().isoformat()}

Failed Devices:
{device_list}

Please review the backup configuration and device connectivity.
"""

        self._send_notification(
            subject=subject,
            message=message,
            level=NotificationLevel.ERROR,
            event_type="multiple_backup_failures",
            context={
                'failed_count': count,
                'devices': [d['name'] for d in failed_devices[:10]]
            }
        )

    def notify_scheduler_error(self, schedule_id: int, error: str):
        """
        Notifica sobre erro no scheduler.

        Args:
            schedule_id: ID do agendamento
            error: Mensagem de erro
        """
        subject = f"⚠️ Scheduler Error: Schedule {schedule_id}"
        message = f"""
Scheduler Error Alert

Schedule ID: {schedule_id}
Error: {error}
Time: {datetime.now().isoformat()}

The scheduled backup may not have executed. Please check the scheduler logs.
"""

        self._send_notification(
            subject=subject,
            message=message,
            level=NotificationLevel.WARNING,
            event_type="scheduler_error",
            context={
                'schedule_id': schedule_id,
                'error': error
            }
        )

    def notify_system_health(self, component: str, status: str, message: str):
        """
        Notifica sobre problemas de saúde do sistema.

        Args:
            component: Componente afetado (database, scheduler, etc)
            status: Status do componente (unhealthy, degraded)
            message: Mensagem detalhada
        """
        subject = f"⚠️ System Health Alert: {component}"
        alert_message = f"""
System Health Alert

Component: {component}
Status: {status}
Message: {message}
Time: {datetime.now().isoformat()}

Please check the system health endpoint for more details.
"""

        level = NotificationLevel.CRITICAL if status == 'unhealthy' else NotificationLevel.WARNING

        self._send_notification(
            subject=subject,
            message=alert_message,
            level=level,
            event_type="system_health",
            context={
                'component': component,
                'status': status
            }
        )

    def _send_notification(self, subject: str, message: str, level: NotificationLevel,
                          event_type: str, context: Dict[str, Any]):
        """
        Envia notificação através dos canais configurados.

        Args:
            subject: Assunto da notificação
            message: Corpo da mensagem
            level: Nível de severidade
            event_type: Tipo de evento
            context: Contexto adicional
        """
        if not self.config.is_enabled():
            return

        if not self.config.should_notify(level):
            self.logger.debug(f"Skipping notification (level {level.value} below threshold)")
            return

        # Email
        if self.config.email_enabled:
            try:
                self._send_email(subject, message)
            except Exception as e:
                self.logger.error(f"Failed to send email notification: {e}")

        # Webhook
        if self.config.webhook_enabled:
            try:
                self._send_webhook(subject, message, level, event_type, context)
            except Exception as e:
                self.logger.error(f"Failed to send webhook notification: {e}")

    def _send_email(self, subject: str, body: str):
        """Envia notificação por email via SMTP."""
        if not self.config.email_to or not self.config.email_to[0]:
            self.logger.warning("Email notification skipped: no recipients configured")
            return

        msg = MIMEMultipart()
        msg['From'] = self.config.email_from
        msg['To'] = ', '.join(self.config.email_to)
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(self.config.email_smtp_host, self.config.email_smtp_port) as server:
            if self.config.email_use_tls:
                server.starttls()

            if self.config.email_username and self.config.email_password:
                server.login(self.config.email_username, self.config.email_password)

            server.send_message(msg)

        self.logger.info(f"Email notification sent: {subject}")

    def _send_webhook(self, subject: str, message: str, level: NotificationLevel,
                     event_type: str, context: Dict[str, Any]):
        """Envia notificação via webhook."""
        if not self.config.webhook_url:
            self.logger.warning("Webhook notification skipped: no URL configured")
            return

        # Formato genérico que funciona com Slack, Discord, etc
        payload = {
            'text': subject,
            'level': level.value,
            'event_type': event_type,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'context': context
        }

        # Se for Slack, usa formato específico
        if 'slack.com' in self.config.webhook_url:
            payload = {
                'text': f"*{subject}*\n{message}",
                'attachments': [{
                    'color': self._get_slack_color(level),
                    'fields': [
                        {'title': k, 'value': str(v), 'short': True}
                        for k, v in context.items()
                    ]
                }]
            }

        response = requests.post(
            self.config.webhook_url,
            json=payload,
            headers=self.config.webhook_headers,
            timeout=NOTIFICATION_TIMEOUT
        )
        response.raise_for_status()

        self.logger.info(f"Webhook notification sent: {subject}")

    def _get_slack_color(self, level: NotificationLevel) -> str:
        """Retorna cor apropriada para Slack baseada no nível."""
        colors = {
            NotificationLevel.INFO: 'good',      # Verde
            NotificationLevel.WARNING: 'warning', # Amarelo
            NotificationLevel.ERROR: 'danger',    # Vermelho
            NotificationLevel.CRITICAL: 'danger'  # Vermelho
        }
        return colors.get(level, 'warning')


# Instância global
_notification_manager = None


def init_notifications(config: Optional[NotificationConfig] = None):
    """
    Inicializa o sistema de notificações.

    Args:
        config: Configuração customizada (usa env vars se None)
    """
    global _notification_manager
    _notification_manager = NotificationManager(config)
    return _notification_manager


def get_notification_manager() -> Optional[NotificationManager]:
    """Retorna a instância global do notification manager."""
    return _notification_manager


# Testes
if __name__ == '__main__':
    print("=== Teste do Sistema de Notificações ===\n")

    # Testa configuração
    config = NotificationConfig()
    print(f"Email enabled: {config.email_enabled}")
    print(f"Webhook enabled: {config.webhook_enabled}")
    print(f"Min level: {config.min_level}")
    print(f"Notify on success: {config.notify_on_success}")
    print(f"Notify on failure: {config.notify_on_failure}")

    print("\n✓ Testes de configuração concluídos!")
