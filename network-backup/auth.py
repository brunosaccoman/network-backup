"""
Sistema de Autenticação e Autorização

Gerencia autenticação de usuários, roles e permissões usando Flask-Login.
"""

from functools import wraps
from flask import abort, flash, redirect, url_for, request
from flask_login import LoginManager, current_user
from models import User, db, AuditLog
import logging

logger = logging.getLogger(__name__)

# Inicializar Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    """
    Carrega usuário pelo ID.

    Callback necessário para Flask-Login.
    """
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    """
    Handler para usuários não autenticados.

    Redireciona para login ou retorna 401 para APIs.
    """
    if request.is_json or request.path.startswith('/api/'):
        abort(401)
    flash('Você precisa estar autenticado para acessar esta página.', 'warning')
    return redirect(url_for('auth.login', next=request.url))


def role_required(*roles):
    """
    Decorator para exigir roles específicos.

    Usage:
        @role_required('admin')
        def admin_only_view():
            pass

        @role_required('admin', 'operator')
        def admin_or_operator_view():
            pass

    Args:
        *roles: Roles permitidos (admin, operator, viewer)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()

            if not current_user.has_role(*roles):
                logger.warning(
                    f"User {current_user.username} (role: {current_user.role}) "
                    f"tentou acessar {request.path} que requer roles: {roles}"
                )
                abort(403)  # Forbidden

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """
    Decorator para exigir role admin.

    Usage:
        @admin_required
        def delete_device():
            pass
    """
    return role_required('admin')(f)


def operator_required(f):
    """
    Decorator para exigir role operator ou admin.

    Usage:
        @operator_required
        def create_backup():
            pass
    """
    return role_required('admin', 'operator')(f)


def permission_required(permission):
    """
    Decorator para verificar permissões específicas.

    Args:
        permission: Tipo de permissão (view, edit, delete)

    Usage:
        @permission_required('edit')
        def edit_device():
            pass
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()

            if permission == 'view' and not current_user.can_view():
                abort(403)
            elif permission == 'edit' and not current_user.can_edit():
                abort(403)
            elif permission == 'delete' and not current_user.can_delete():
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def log_audit(action, resource_type, resource_id=None, details=None):
    """
    Registra ação no audit log.

    Args:
        action: Tipo de ação (create, update, delete, backup, login, logout)
        resource_type: Tipo de recurso (device, backup, schedule, user)
        resource_id: ID do recurso afetado
        details: Detalhes adicionais (dict será convertido para JSON)
    """
    if not current_user.is_authenticated:
        return

    try:
        import json

        # Converter details para JSON se for dict
        details_str = None
        if details:
            if isinstance(details, dict):
                details_str = json.dumps(details, ensure_ascii=False)
            else:
                details_str = str(details)

        # Obter IP e User-Agent
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent', '')[:255] if request else None

        # Criar log
        audit_log = AuditLog(
            user_id=current_user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details_str,
            ip_address=ip_address,
            user_agent=user_agent
        )

        db.session.add(audit_log)
        db.session.commit()

        logger.info(
            f"Audit: {current_user.username} {action} {resource_type} "
            f"{resource_id if resource_id else ''} from {ip_address}"
        )

    except Exception as e:
        logger.error(f"Erro ao criar audit log: {e}")
        db.session.rollback()


def audit_log_decorator(action, resource_type):
    """
    Decorator para adicionar audit logging automaticamente.

    Usage:
        @audit_log_decorator('create', 'device')
        def create_device():
            # A ação será logada automaticamente
            pass

    Args:
        action: Tipo de ação
        resource_type: Tipo de recurso
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Executar função
            result = f(*args, **kwargs)

            # Tentar extrair resource_id do resultado ou kwargs
            resource_id = kwargs.get('id') or kwargs.get('device_id') or kwargs.get('backup_id')

            # Log audit
            log_audit(action, resource_type, resource_id)

            return result
        return decorated_function
    return decorator


def get_current_user_info():
    """
    Retorna informações do usuário atual.

    Returns:
        dict com informações do usuário ou None se não autenticado
    """
    if current_user.is_authenticated:
        return {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'role': current_user.role,
            'can_view': current_user.can_view(),
            'can_edit': current_user.can_edit(),
            'can_delete': current_user.can_delete(),
            'is_admin': current_user.is_admin(),
        }
    return None


def init_auth(app):
    """
    Inicializa o sistema de autenticação.

    Args:
        app: Instância do Flask
    """
    login_manager.init_app(app)

    # Adicionar contexto global para templates
    @app.context_processor
    def inject_user():
        """Injeta informações do usuário em todos os templates."""
        return {
            'current_user_info': get_current_user_info(),
        }

    logger.info("Sistema de autenticação inicializado")
