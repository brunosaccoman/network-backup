# Sistema de Notificações - Fase 2

## Visão Geral

O sistema de notificações permite alertas automáticos sobre eventos importantes através de múltiplos canais:
- Email (SMTP)
- Webhooks (genéricos - compatível com Slack, Discord, Teams, etc)

## Tipos de Notificação

### 1. Backup Failure (Falha de Backup)
- **Quando**: Backup de dispositivo falha
- **Nível**: ERROR
- **Conteúdo**: Nome do dispositivo, ID, erro detalhado

### 2. Backup Success (Sucesso de Backup)
- **Quando**: Backup completado com sucesso
- **Nível**: INFO
- **Conteúdo**: Nome do dispositivo, ID, tamanho do arquivo
- **Nota**: Opcional, controlado por `NOTIFICATION_ON_SUCCESS`

### 3. Multiple Backup Failures (Múltiplas Falhas)
- **Quando**: Várias falhas em backup de todos os dispositivos
- **Nível**: ERROR
- **Conteúdo**: Lista dos primeiros 10 dispositivos que falharam

### 4. Scheduler Error (Erro do Agendador)
- **Quando**: Erro ao executar backup agendado
- **Nível**: WARNING
- **Conteúdo**: ID do agendamento, mensagem de erro

### 5. System Health Alert (Alerta de Saúde do Sistema)
- **Quando**: Problemas de saúde detectados (DB, scheduler, recursos)
- **Nível**: WARNING ou CRITICAL
- **Conteúdo**: Componente afetado, status, detalhes

## Configuração via Variáveis de Ambiente

Adicione ao arquivo `.env`:

### Configurações de Email

```bash
# Habilitar notificações por email
NOTIFICATION_EMAIL_ENABLED=True

# Servidor SMTP
NOTIFICATION_EMAIL_SMTP_HOST=smtp.gmail.com
NOTIFICATION_EMAIL_SMTP_PORT=587
NOTIFICATION_EMAIL_USE_TLS=True

# Credenciais SMTP
NOTIFICATION_EMAIL_USERNAME=seu-email@gmail.com
NOTIFICATION_EMAIL_PASSWORD=sua-senha-de-app

# Remetente e destinatários
NOTIFICATION_EMAIL_FROM=backup-system@empresa.com
NOTIFICATION_EMAIL_TO=admin@empresa.com,ops@empresa.com
```

#### Configurar Gmail para SMTP

1. Ative a verificação em 2 etapas na sua conta Google
2. Gere uma senha de aplicativo:
   - Acesse: https://myaccount.google.com/apppasswords
   - Selecione "Email" e "Outro (nome personalizado)"
   - Digite "Network Backup" e clique em "Gerar"
   - Use a senha gerada em `NOTIFICATION_EMAIL_PASSWORD`

### Configurações de Webhook

```bash
# Habilitar notificações por webhook
NOTIFICATION_WEBHOOK_ENABLED=True

# URL do webhook
NOTIFICATION_WEBHOOK_URL=https://hooks.slack.com/services/SEU/WEBHOOK/URL
```

#### Configurar Slack Webhook

1. Acesse: https://api.slack.com/messaging/webhooks
2. Crie um novo aplicativo ou use existente
3. Ative "Incoming Webhooks"
4. Adicione um novo webhook para o canal desejado
5. Copie a URL do webhook para `NOTIFICATION_WEBHOOK_URL`

#### Outros Webhooks (Discord, Teams)

**Discord**:
```bash
NOTIFICATION_WEBHOOK_URL=https://discord.com/api/webhooks/SEU_WEBHOOK_ID/SEU_WEBHOOK_TOKEN
```

**Microsoft Teams**:
```bash
NOTIFICATION_WEBHOOK_URL=https://outlook.office.com/webhook/SEU_WEBHOOK_URL
```

### Filtros de Notificação

```bash
# Notificar em sucessos (padrão: False)
NOTIFICATION_ON_SUCCESS=False

# Notificar em falhas (padrão: True)
NOTIFICATION_ON_FAILURE=True

# Notificar em avisos (padrão: True)
NOTIFICATION_ON_WARNING=True

# Nível mínimo para notificar: INFO, WARNING, ERROR, CRITICAL
NOTIFICATION_MIN_LEVEL=WARNING
```

## Exemplo de Configuração Completa

### Para Email (Gmail)

```bash
# .env
NOTIFICATION_EMAIL_ENABLED=True
NOTIFICATION_EMAIL_SMTP_HOST=smtp.gmail.com
NOTIFICATION_EMAIL_SMTP_PORT=587
NOTIFICATION_EMAIL_USE_TLS=True
NOTIFICATION_EMAIL_USERNAME=backup-alerts@gmail.com
NOTIFICATION_EMAIL_PASSWORD=xxxx-xxxx-xxxx-xxxx
NOTIFICATION_EMAIL_FROM=backup-alerts@gmail.com
NOTIFICATION_EMAIL_TO=admin@empresa.com,ops@empresa.com

NOTIFICATION_ON_SUCCESS=False
NOTIFICATION_ON_FAILURE=True
NOTIFICATION_MIN_LEVEL=WARNING
```

### Para Slack

```bash
# .env
NOTIFICATION_WEBHOOK_ENABLED=True
NOTIFICATION_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX

NOTIFICATION_ON_SUCCESS=False
NOTIFICATION_ON_FAILURE=True
NOTIFICATION_MIN_LEVEL=ERROR
```

### Para Email + Slack

```bash
# .env
# Email
NOTIFICATION_EMAIL_ENABLED=True
NOTIFICATION_EMAIL_SMTP_HOST=smtp.gmail.com
NOTIFICATION_EMAIL_SMTP_PORT=587
NOTIFICATION_EMAIL_USE_TLS=True
NOTIFICATION_EMAIL_USERNAME=backup-alerts@gmail.com
NOTIFICATION_EMAIL_PASSWORD=xxxx-xxxx-xxxx-xxxx
NOTIFICATION_EMAIL_FROM=backup-alerts@gmail.com
NOTIFICATION_EMAIL_TO=admin@empresa.com

# Slack
NOTIFICATION_WEBHOOK_ENABLED=True
NOTIFICATION_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX

# Filtros
NOTIFICATION_ON_SUCCESS=False
NOTIFICATION_ON_FAILURE=True
NOTIFICATION_MIN_LEVEL=ERROR
```

## Como Aplicar Configurações

### Modo Docker

1. Edite o arquivo `.env` com as configurações desejadas
2. Reconstrua e reinicie os containers:

```bash
docker-compose down
docker-compose up -d --build
```

3. Verifique os logs para confirmar inicialização:

```bash
docker-compose logs app | grep -i notification
```

Você deve ver:
```
Notification system initialized
  email_enabled: True
  webhook_enabled: True
  min_level: WARNING
```

### Modo Desenvolvimento

1. Edite o arquivo `.env`
2. Reinicie a aplicação Flask:

```bash
flask run
# ou
python app.py
```

## Testando Notificações

### Teste Manual de Backup

1. Faça login no sistema
2. Execute um backup de um dispositivo
3. Se falhar, você receberá uma notificação de falha
4. Se tiver sucesso e `NOTIFICATION_ON_SUCCESS=True`, receberá notificação de sucesso

### Teste de Webhook via Python

```python
import requests

# Seu webhook URL
webhook_url = "https://hooks.slack.com/services/SEU/WEBHOOK/URL"

# Payload de teste
payload = {
    "text": "🔴 *Backup Failed: Test Device*\n\nDevice: Test-Router (ID: 999)\nStatus: FAILED\nError: Connection timeout\nTime: 2025-11-18T18:00:00Z",
}

response = requests.post(webhook_url, json=payload)
print(f"Status: {response.status_code}")
```

### Teste de Email via Python

```python
import smtplib
from email.mime.text import MIMEText

msg = MIMEText("Este é um teste de notificação do sistema de backup.")
msg['Subject'] = '🔴 Backup Failed: Test Device'
msg['From'] = 'backup-alerts@gmail.com'
msg['To'] = 'admin@empresa.com'

with smtplib.SMTP('smtp.gmail.com', 587) as server:
    server.starttls()
    server.login('backup-alerts@gmail.com', 'sua-senha-de-app')
    server.send_message(msg)
print("Email enviado!")
```

## Exemplos de Notificações

### Email de Falha de Backup

```
Subject: 🔴 Backup Failed: HUAWEI-RTR-PE-RC-CEN-01

Backup Failure Alert

Device: HUAWEI-RTR-PE-RC-CEN-01 (ID: 123)
Status: FAILED
Error: Authentication failed (SSH)
Time: 2025-11-18T18:30:45.123456Z

Please check the device configuration and network connectivity.
```

### Slack/Webhook de Múltiplas Falhas

```
🔴 Multiple Backup Failures: 5 devices

Total Failed: 5 devices
Time: 2025-11-18T18:30:45Z

Failed Devices:
  - Router-01 (ID: 1): Connection timeout
  - Switch-02 (ID: 2): Authentication failed
  - AP-03 (ID: 3): SSH not responding
  - Router-04 (ID: 4): Command timeout
  - Switch-05 (ID: 5): Connection refused

Please review the backup configuration and device connectivity.
```

## Solução de Problemas

### Notificações não estão sendo enviadas

1. **Verifique se está habilitado**:
```bash
docker-compose logs app | grep "Notification system"
```

Deve mostrar:
```
Notification system initialized
```

Se mostrar:
```
Notification system disabled
```

Significa que nenhuma notificação está habilitada no `.env`.

2. **Verifique o nível mínimo**:
Se `NOTIFICATION_MIN_LEVEL=ERROR` mas o evento é WARNING, não será notificado.

3. **Verifique filtros**:
- `NOTIFICATION_ON_FAILURE=False` → Não notifica falhas
- `NOTIFICATION_ON_SUCCESS=False` → Não notifica sucessos

### Erro ao enviar email

**"Authentication failed"**:
- Verifique se a senha de aplicativo do Gmail está correta
- Certifique-se de que a verificação em 2 etapas está ativa

**"Connection refused"**:
- Verifique se a porta SMTP está correta (587 para TLS, 465 para SSL)
- Verifique se há firewall bloqueando a porta

**"TLS handshake failed"**:
- Tente mudar `NOTIFICATION_EMAIL_USE_TLS=False` e `NOTIFICATION_EMAIL_SMTP_PORT=465`

### Erro ao enviar webhook

**"Invalid webhook URL"**:
- Verifique se a URL está completa e correta
- Para Slack, deve começar com `https://hooks.slack.com/services/`

**"Webhook not found"**:
- O webhook pode ter sido deletado no Slack/Discord
- Recrie o webhook e atualize a URL

## Logs de Notificação

Todas as notificações enviadas são registradas nos logs:

```bash
docker-compose logs app | grep -i notification
```

Exemplos de logs:
```
Email notification sent: 🔴 Backup Failed: Router-01
Webhook notification sent: 🔴 Multiple Backup Failures: 5 devices
Failed to send email notification: Authentication failed
Skipping notification (level INFO below threshold WARNING)
```

## Boas Práticas

1. **Não notificar sucessos em produção** (`NOTIFICATION_ON_SUCCESS=False`)
   - Gera muito ruído
   - Use apenas em testes ou dispositivos críticos

2. **Use nível ERROR para produção** (`NOTIFICATION_MIN_LEVEL=ERROR`)
   - Reduz ruído
   - Alerta apenas em problemas reais

3. **Configure múltiplos destinatários**:
   ```bash
   NOTIFICATION_EMAIL_TO=admin@empresa.com,ops@empresa.com,suporte@empresa.com
   ```

4. **Use canais separados no Slack**:
   - `#backups-critical` para ERROR/CRITICAL
   - `#backups-all` para todos os níveis

5. **Teste antes de produção**:
   - Configure notificações em desenvolvimento
   - Execute backups de teste
   - Confirme recebimento de alertas

## Próximos Passos

Após configurar notificações básicas, considere:

1. **Adicionar mais canais**:
   - Microsoft Teams
   - Discord
   - PagerDuty
   - Telegram

2. **Notificações customizadas**:
   - Templates HTML para emails
   - Mensagens formatadas por tipo de dispositivo
   - Anexos com logs de erro

3. **Agregação de notificações**:
   - Agrupar múltiplas falhas em um único email
   - Enviar resumo diário de backups

4. **Integração com monitoramento**:
   - Prometheus AlertManager
   - Grafana Alerts
   - Datadog

---

**Documentação criada em**: 2025-11-18
**Versão**: Fase 2 - Observabilidade
