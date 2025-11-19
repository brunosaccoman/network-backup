# Network Backup System

Sistema profissional de backup automatizado para dispositivos de rede (roteadores, switches, access points).

**Branch Atual:** NEXUSBACKUP
**Versão:** Fase 2 - Escalabilidade
**Capacidade:** Otimizado para 1.000-3.000 dispositivos

---

## 🚀 Instalação Rápida (Debian/Ubuntu)

### Opção 1: Script Automatizado (Recomendado)

```bash
curl -fsSL https://raw.githubusercontent.com/brunosaccoman/network-backup/NEXUSBACKUP/network-backup/install.sh | bash
```

### Opção 2: Manual

```bash
# Clonar repositório
git clone -b NEXUSBACKUP https://github.com/brunosaccoman/network-backup.git
cd network-backup/network-backup

# Seguir instruções em:
cat INSTALL_DEBIAN.md
```

---

## 📚 Documentação

- **[INSTALL_DEBIAN.md](network-backup/INSTALL_DEBIAN.md)** - Guia completo de instalação para Debian/Ubuntu
- **[ESCALABILIDADE.md](network-backup/ESCALABILIDADE.md)** - Performance e otimizações para grande escala
- **[CLAUDE.md](network-backup/CLAUDE.md)** - Referência completa da arquitetura
- **[NOTIFICACOES.md](network-backup/NOTIFICACOES.md)** - Configuração de alertas

---

## ⚡ Features

### Fase 1 - Segurança ✅
- Autenticação multiusuário (admin/operator/viewer)
- Criptografia AES-256 de credenciais
- PostgreSQL com ORM e migrações
- Proteção CSRF + Rate Limiting
- Audit logs completo

### Fase 2 - Escalabilidade ✅
- **50 workers paralelos** (backup 5x mais rápido)
- **150 conexões de pool** PostgreSQL
- **Paginação** em todas as listas
- **13 índices otimizados** de banco
- **Performance**: Dashboard <100ms com 3000 devices
- Sistema de notificações (Email/Webhook)
- Logging estruturado JSON
- Health checks

---

## 🎯 Capacidade

| Dispositivos | Performance | Status |
|-------------|-------------|---------|
| 100-500 | Excelente (<50ms) | ✅ Pronto |
| 500-1.000 | Ótima (<80ms) | ✅ Pronto |
| **1.000-3.000** | **Boa (<100ms)** | ✅ **Otimizado** |
| 3.000-5.000 | Ajuste workers 75-100 | ⚠️ Configurável |

---

## 🔧 Requisitos

**Mínimo:**
- 4GB RAM
- 2 CPUs
- 20GB disco
- Debian 11+ / Ubuntu 20.04+

**Recomendado (3000 devices):**
- 8GB RAM
- 4 CPUs
- 50GB+ disco (SSD)
- PostgreSQL 12+

---

## 📊 Performance

| Métrica | Antes | Agora | Melhoria |
|---------|-------|-------|----------|
| Dashboard (3k devices) | 6.5s | <100ms | **65x** |
| Lista devices | 4.8s | <80ms | **60x** |
| Backup All (3k) | 25min | 5min | **5x** |

---

## 🛠️ Tecnologias

- **Backend:** Python 3.11, Flask
- **Database:** PostgreSQL 15
- **Deploy:** Docker + Docker Compose
- **Server:** Gunicorn
- **Auth:** Flask-Login + bcrypt
- **Crypto:** AES-256 (Fernet)
- **Monitoring:** Prometheus, Health Checks
- **Notifications:** SMTP, Webhooks

---

## 📞 Suporte

- **Issues:** https://github.com/brunosaccoman/network-backup/issues
- **Documentação:** Ver pasta `network-backup/`

---

## 📝 Licença

Proprietary - Todos os direitos reservados

---

**Desenvolvido por:** Bruno Saccoman
**Última atualização:** 2025-11-19
