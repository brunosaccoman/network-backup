/**
 * Sistema de Notificações Visuais
 * Toast Notifications + Alert Banners
 */

class NotificationSystem {
    constructor() {
        this.toastContainer = null;
        this.bannerContainer = null;
        this.toastCounter = 0;
        this.init();
    }

    init() {
        // Criar container para toasts
        this.toastContainer = document.createElement('div');
        this.toastContainer.className = 'toast-container';
        document.body.appendChild(this.toastContainer);

        // Criar container para banners
        this.bannerContainer = document.createElement('div');
        this.bannerContainer.className = 'alert-banner-container';
        document.body.appendChild(this.bannerContainer);

        // Processar flash messages do Flask (se existirem)
        this.processFlashMessages();
    }

    /**
     * Mostra um toast notification
     * @param {string} message - Mensagem a exibir
     * @param {string} type - Tipo: success, error, warning, info
     * @param {string} title - Título opcional
     * @param {number} duration - Duração em ms (0 = não fecha automaticamente)
     */
    toast(message, type = 'info', title = null, duration = 5000) {
        const id = `toast-${++this.toastCounter}`;

        // Título padrão baseado no tipo
        if (!title) {
            const titles = {
                success: 'Sucesso',
                error: 'Erro',
                warning: 'Atenção',
                info: 'Informação'
            };
            title = titles[type] || 'Notificação';
        }

        // Ícone baseado no tipo
        const icons = {
            success: '✓',
            error: '✕',
            warning: '⚠',
            info: 'ℹ'
        };
        const icon = icons[type] || 'ℹ';

        // Criar elemento toast
        const toast = document.createElement('div');
        toast.id = id;
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-icon">${icon}</div>
            <div class="toast-content">
                <div class="toast-title">${this.escapeHtml(title)}</div>
                <div class="toast-message">${this.escapeHtml(message)}</div>
            </div>
            <button class="toast-close" onclick="notifications.closeToast('${id}')">&times;</button>
            ${duration > 0 ? `<div class="toast-progress" style="width: 100%;"></div>` : ''}
        `;

        this.toastContainer.appendChild(toast);

        // Auto-close com animação de progresso
        if (duration > 0) {
            const progress = toast.querySelector('.toast-progress');
            if (progress) {
                // Animar barra de progresso
                setTimeout(() => {
                    progress.style.transition = `width ${duration}ms linear`;
                    progress.style.width = '0%';
                }, 10);
            }

            setTimeout(() => {
                this.closeToast(id);
            }, duration);
        }

        return id;
    }

    /**
     * Fecha um toast específico
     */
    closeToast(id) {
        const toast = document.getElementById(id);
        if (toast) {
            toast.classList.add('hiding');
            setTimeout(() => {
                toast.remove();
            }, 300);
        }
    }

    /**
     * Mostra um banner de alerta no topo
     * @param {string} message - Mensagem a exibir
     * @param {string} type - Tipo: success, error, warning, info
     * @param {string} title - Título opcional
     * @param {boolean} dismissible - Pode ser fechado manualmente
     * @param {number} duration - Duração em ms (0 = não fecha automaticamente)
     */
    banner(message, type = 'info', title = null, dismissible = true, duration = 0) {
        const id = `banner-${++this.toastCounter}`;

        // Ícone baseado no tipo
        const icons = {
            success: '✓',
            error: '✕',
            warning: '⚠',
            info: 'ℹ'
        };
        const icon = icons[type] || 'ℹ';

        // Criar elemento banner
        const banner = document.createElement('div');
        banner.id = id;
        banner.className = `alert-banner ${type}`;

        let html = `<div class="alert-banner-icon">${icon}</div>`;
        html += `<div class="alert-banner-content">`;
        if (title) {
            html += `<div class="alert-banner-title">${this.escapeHtml(title)}</div>`;
        }
        html += `<div class="alert-banner-message">${this.escapeHtml(message)}</div>`;
        html += `</div>`;
        if (dismissible) {
            html += `<button class="alert-banner-close" onclick="notifications.closeBanner('${id}')">&times;</button>`;
        }

        banner.innerHTML = html;

        this.bannerContainer.appendChild(banner);
        document.body.classList.add('has-alert-banner');

        // Auto-close
        if (duration > 0) {
            setTimeout(() => {
                this.closeBanner(id);
            }, duration);
        }

        return id;
    }

    /**
     * Fecha um banner específico
     */
    closeBanner(id) {
        const banner = document.getElementById(id);
        if (banner) {
            banner.classList.add('hiding');
            setTimeout(() => {
                banner.remove();
                // Remove classe do body se não houver mais banners
                if (this.bannerContainer.children.length === 0) {
                    document.body.classList.remove('has-alert-banner');
                }
            }, 300);
        }
    }

    /**
     * Atalhos para tipos específicos
     */
    success(message, title = null, useBanner = false) {
        if (useBanner) {
            return this.banner(message, 'success', title, true, 5000);
        }
        return this.toast(message, 'success', title);
    }

    error(message, title = null, useBanner = false) {
        if (useBanner) {
            return this.banner(message, 'error', title, true, 0); // Erro não fecha automaticamente
        }
        return this.toast(message, 'error', title, 7000); // Erro fica mais tempo
    }

    warning(message, title = null, useBanner = false) {
        if (useBanner) {
            return this.banner(message, 'warning', title, true, 8000);
        }
        return this.toast(message, 'warning', title, 6000);
    }

    info(message, title = null, useBanner = false) {
        if (useBanner) {
            return this.banner(message, 'info', title, true, 5000);
        }
        return this.toast(message, 'info', title);
    }

    /**
     * Processa flash messages do Flask (compatibilidade com sistema existente)
     */
    processFlashMessages() {
        const flashContainer = document.querySelector('.flash-messages');
        if (!flashContainer) return;

        const messages = flashContainer.querySelectorAll('.alert');
        messages.forEach(alert => {
            const type = alert.classList.contains('alert-success') ? 'success' :
                        alert.classList.contains('alert-danger') ? 'error' :
                        alert.classList.contains('alert-warning') ? 'warning' : 'info';

            const message = alert.textContent.trim();
            if (message) {
                this.toast(message, type);
            }
        });

        // Esconde container original
        flashContainer.style.display = 'none';
    }

    /**
     * Escape HTML para prevenir XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Mostra notificação de operação com dispositivo
     */
    deviceCreated(deviceName) {
        this.success(`Dispositivo "${deviceName}" criado com sucesso!`, 'Dispositivo Criado');
    }

    deviceUpdated(deviceName) {
        this.success(`Dispositivo "${deviceName}" atualizado com sucesso!`, 'Dispositivo Atualizado');
    }

    deviceDeleted(deviceName) {
        this.warning(`Dispositivo "${deviceName}" foi removido.`, 'Dispositivo Removido');
    }

    backupStarted(deviceName) {
        this.info(`Backup iniciado para "${deviceName}"...`, 'Backup em Andamento');
    }

    backupSuccess(deviceName) {
        this.success(`Backup de "${deviceName}" concluído!`, 'Backup Completo');
    }

    backupFailed(deviceName, error) {
        this.error(`Falha no backup de "${deviceName}": ${error}`, 'Backup Falhou', true); // Usa banner para erro
    }

    scheduleCreated(name) {
        this.success(`Agendamento "${name}" criado com sucesso!`, 'Agendamento Criado');
    }

    scheduleUpdated(name) {
        this.success(`Agendamento "${name}" atualizado!`, 'Agendamento Atualizado');
    }

    scheduleDeleted(name) {
        this.warning(`Agendamento "${name}" foi removido.`, 'Agendamento Removido');
    }

    userCreated(username) {
        this.success(`Usuário "${username}" criado com sucesso!`, 'Usuário Criado');
    }

    userUpdated(username) {
        this.success(`Usuário "${username}" atualizado!`, 'Usuário Atualizado');
    }

    configSaved() {
        this.success('Configurações salvas com sucesso!', 'Configurações Atualizadas');
    }
}

// Inicializar sistema de notificações imediatamente
let notifications;

function initNotifications() {
    if (!notifications) {
        notifications = new NotificationSystem();
        window.notifications = notifications;
        console.log('✅ Sistema de notificações visuais inicializado');
    }
    return notifications;
}

// Tentar inicializar imediatamente
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initNotifications);
} else {
    // DOM já carregado
    initNotifications();
}

// Garantir que está disponível globalmente
window.initNotifications = initNotifications;
