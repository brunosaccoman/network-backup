#!/usr/bin/env python3
"""
Script de teste para o Sistema de Notificações

Testa todas as funcionalidades do sistema de notificações:
- Configuração
- Envio de emails
- Envio de webhooks
- Diferentes tipos de eventos
"""

import os
import sys
from datetime import datetime

# Adiciona o diretório atual ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from notifications import (
    NotificationConfig,
    NotificationManager,
    NotificationLevel
)


def print_section(title):
    """Imprime seção formatada."""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60 + "\n")


def test_configuration():
    """Testa leitura de configuração."""
    print_section("1. Teste de Configuração")

    config = NotificationConfig()

    print(f"Email Enabled:    {config.email_enabled}")
    if config.email_enabled:
        print(f"  SMTP Host:      {config.email_smtp_host}")
        print(f"  SMTP Port:      {config.email_smtp_port}")
        print(f"  Use TLS:        {config.email_use_tls}")
        print(f"  Username:       {config.email_username}")
        print(f"  Password:       {'*' * len(config.email_password) if config.email_password else 'Not set'}")
        print(f"  From:           {config.email_from}")
        print(f"  To:             {', '.join(config.email_to) if config.email_to else 'Not set'}")

    print(f"\nWebhook Enabled:  {config.webhook_enabled}")
    if config.webhook_enabled:
        print(f"  Webhook URL:    {config.webhook_url[:50]}..." if len(config.webhook_url) > 50 else f"  Webhook URL:    {config.webhook_url}")

    print(f"\nNotify on Success: {config.notify_on_success}")
    print(f"Notify on Failure: {config.notify_on_failure}")
    print(f"Notify on Warning: {config.notify_on_warning}")
    print(f"Min Level:         {config.min_level}")

    print(f"\nSystem Enabled:    {config.is_enabled()}")

    if not config.is_enabled():
        print("\n⚠️  AVISO: Sistema de notificações está DESABILITADO")
        print("   Configure as variáveis de ambiente para habilitar:")
        print("   - NOTIFICATION_EMAIL_ENABLED=True")
        print("   - NOTIFICATION_WEBHOOK_ENABLED=True")
        return False

    return True


def test_email_notification(manager):
    """Testa envio de notificação por email."""
    print_section("2. Teste de Notificação por Email")

    if not manager.config.email_enabled:
        print("⏭️  Email desabilitado, pulando teste...")
        return

    if not manager.config.email_to or not manager.config.email_to[0]:
        print("❌ Email habilitado mas nenhum destinatário configurado")
        print("   Configure: NOTIFICATION_EMAIL_TO=seu-email@exemplo.com")
        return

    try:
        print("Enviando email de teste...")
        manager.notify_backup_failure(
            device_name="Test-Router-99",
            device_id=999,
            error="This is a test notification - can be safely ignored"
        )
        print("✅ Email enviado com sucesso!")
        print(f"   Verifique: {', '.join(manager.config.email_to)}")
    except Exception as e:
        print(f"❌ Erro ao enviar email: {e}")
        print("\nPossíveis causas:")
        print("  - Credenciais SMTP incorretas")
        print("  - Porta bloqueada por firewall")
        print("  - Gmail requer senha de aplicativo (não senha normal)")
        print("\nVeja NOTIFICACOES.md para instruções de configuração")


def test_webhook_notification(manager):
    """Testa envio de notificação por webhook."""
    print_section("3. Teste de Notificação por Webhook")

    if not manager.config.webhook_enabled:
        print("⏭️  Webhook desabilitado, pulando teste...")
        return

    if not manager.config.webhook_url:
        print("❌ Webhook habilitado mas URL não configurada")
        print("   Configure: NOTIFICATION_WEBHOOK_URL=https://...")
        return

    try:
        print("Enviando webhook de teste...")
        manager.notify_backup_failure(
            device_name="Test-Router-99",
            device_id=999,
            error="This is a test notification - can be safely ignored"
        )
        print("✅ Webhook enviado com sucesso!")

        # Detecta tipo de webhook
        if 'slack.com' in manager.config.webhook_url:
            print("   Tipo: Slack")
        elif 'discord.com' in manager.config.webhook_url:
            print("   Tipo: Discord")
        elif 'office.com' in manager.config.webhook_url:
            print("   Tipo: Microsoft Teams")
        else:
            print("   Tipo: Genérico")

        print("   Verifique o canal/chat configurado")
    except Exception as e:
        print(f"❌ Erro ao enviar webhook: {e}")
        print("\nPossíveis causas:")
        print("  - URL do webhook incorreta ou expirada")
        print("  - Webhook foi deletado no serviço")
        print("  - Formato de payload incompatível")
        print("\nVeja NOTIFICACOES.md para instruções de configuração")


def test_all_notification_types(manager):
    """Testa todos os tipos de notificação."""
    print_section("4. Teste de Tipos de Notificação")

    if not manager.config.is_enabled():
        print("⏭️  Sistema desabilitado, pulando testes...")
        return

    print("Testando diferentes tipos de eventos...\n")

    # 1. Backup Success
    print("1️⃣  Backup Success (INFO)")
    if manager.config.notify_on_success:
        try:
            manager.notify_backup_success(
                device_name="Test-Device",
                device_id=1,
                file_size=12345
            )
            print("   ✅ Notificação enviada")
        except Exception as e:
            print(f"   ❌ Erro: {e}")
    else:
        print("   ⏭️  Pulado (notify_on_success=False)")

    # 2. Backup Failure
    print("\n2️⃣  Backup Failure (ERROR)")
    try:
        manager.notify_backup_failure(
            device_name="Test-Device",
            device_id=2,
            error="Connection timeout"
        )
        print("   ✅ Notificação enviada")
    except Exception as e:
        print(f"   ❌ Erro: {e}")

    # 3. Multiple Failures
    print("\n3️⃣  Multiple Failures (ERROR)")
    try:
        failed_devices = [
            {'name': 'Router-01', 'id': 1, 'error': 'Connection timeout'},
            {'name': 'Switch-02', 'id': 2, 'error': 'Auth failed'},
            {'name': 'AP-03', 'id': 3, 'error': 'SSH error'},
        ]
        manager.notify_multiple_failures(failed_devices)
        print("   ✅ Notificação enviada")
    except Exception as e:
        print(f"   ❌ Erro: {e}")

    # 4. Scheduler Error
    print("\n4️⃣  Scheduler Error (WARNING)")
    try:
        manager.notify_scheduler_error(
            schedule_id=1,
            error="Job execution failed"
        )
        print("   ✅ Notificação enviada")
    except Exception as e:
        print(f"   ❌ Erro: {e}")

    # 5. System Health
    print("\n5️⃣  System Health Alert (CRITICAL)")
    try:
        manager.notify_system_health(
            component="database",
            status="unhealthy",
            message="Connection pool exhausted"
        )
        print("   ✅ Notificação enviada")
    except Exception as e:
        print(f"   ❌ Erro: {e}")


def test_level_filtering():
    """Testa filtragem por nível."""
    print_section("5. Teste de Filtragem por Nível")

    config = NotificationConfig()

    levels = [
        NotificationLevel.INFO,
        NotificationLevel.WARNING,
        NotificationLevel.ERROR,
        NotificationLevel.CRITICAL
    ]

    print(f"Nível mínimo configurado: {config.min_level}\n")

    for level in levels:
        should_notify = config.should_notify(level)
        icon = "✅" if should_notify else "❌"
        print(f"{icon} {level.value.upper():10s} → {'Notifica' if should_notify else 'Ignora'}")


def main():
    """Função principal."""
    print("\n" + "╔" + "═" * 58 + "╗")
    print("║" + " " * 10 + "TESTE DO SISTEMA DE NOTIFICAÇÕES" + " " * 15 + "║")
    print("╚" + "═" * 58 + "╝")

    # Carrega configuração
    if not test_configuration():
        print("\n" + "=" * 60)
        print("❌ Sistema desabilitado - configure e tente novamente")
        print("=" * 60)
        return 1

    # Inicializa manager
    manager = NotificationManager()

    # Testa email
    test_email_notification(manager)

    # Testa webhook
    test_webhook_notification(manager)

    # Testa tipos de notificação
    test_all_notification_types(manager)

    # Testa filtragem
    test_level_filtering()

    # Resumo final
    print_section("Resumo")
    print("✅ Testes concluídos!")
    print("\nPróximos passos:")
    print("1. Verifique se recebeu as notificações de teste")
    print("2. Ajuste configurações conforme necessário")
    print("3. Execute um backup real para testar em produção")
    print("\nVeja NOTIFICACOES.md para documentação completa")
    print("=" * 60 + "\n")

    return 0


if __name__ == '__main__':
    sys.exit(main())
