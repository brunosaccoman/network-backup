"""
Network Backup System - Aplicação Principal
Fase 1: Segurança e Fundações Completa
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, Blueprint
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
import os
import logging
from datetime import datetime, timezone, timedelta
import pytz

# Imports locais
from config import get_config
from models import db, User, Device, Backup, Schedule, Provedor, AuditLog
from database import Database
from backup_manager import BackupManager
from scheduler import BackupScheduler
from auth import init_auth, role_required, admin_required, operator_required, log_audit
from validators import validate_device_data, ValidationError, InputValidator

# Criar aplicação
app = Flask(__name__)
config_class = get_config()
app.config.from_object(config_class)

# Configuração de logging estruturado - Fase 2
from structured_logging import configure_structured_logging, get_logger, StructuredLoggerAdapter
logger = configure_structured_logging(
    app=app,
    log_level=app.config.get('LOG_LEVEL', 'INFO'),
    json_logs=(app.config.get('LOG_FORMAT', 'json') == 'json')
)
logger.info("Application starting", environment=app.config.get('FLASK_ENV', 'development'))

# Inicializar extensões
db.init_app(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[app.config['RATELIMIT_DEFAULT']],
    storage_uri=app.config['RATELIMIT_STORAGE_URL']
)

# Inicializar autenticação
init_auth(app)

# Filtro de data brasileiro
@app.template_filter('datetime_br')
def datetime_br_filter(value):
    """Formata datetime para formato brasileiro."""
    if not value:
        return 'N/A'

    # Se for string, converter para datetime
    if isinstance(value, str):
        try:
            # Tenta parsear ISO format
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except:
            return value

    # Se for datetime, processar timezone
    if isinstance(value, datetime):
        tz = pytz.timezone(app.config.get('TIMEZONE', 'America/Porto_Velho'))

        if value.tzinfo is None:
            # Datetime naive: assumir que está em UTC e converter para local
            value = pytz.utc.localize(value).astimezone(tz)
            return value.strftime('%d/%m/%Y às %H:%M:%S')
        else:
            # Datetime com timezone: converter para timezone local
            value = value.astimezone(tz)
            return value.strftime('%d/%m/%Y às %H:%M:%S')

    # Formatar no padrão brasileiro
    return value.strftime('%d/%m/%Y às %H:%M:%S')

# Inicializar managers
database_manager = Database()
backup_manager = BackupManager(
    backup_dir=app.config['BACKUP_DIR'],
    ssl_verify=app.config['SSL_VERIFY'],
    ssl_ca_bundle=app.config.get('SSL_CA_BUNDLE'),
    retention_count=app.config['BACKUP_RETENTION_COUNT'],
    max_workers=app.config['BACKUP_MAX_WORKERS'],
    app=app
)

# Inicializa scheduler apenas no processo principal (evita duplicação em debug mode)
# WERKZEUG_RUN_MAIN só existe no processo filho quando usa reloader
# Isso garante que apenas 1 scheduler rode, mesmo com auto-reload
import os
scheduler = None
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
    # Processo principal do reloader OU modo produção
    scheduler = BackupScheduler(app=app, backup_manager=backup_manager)
    logger.info("Scheduler inicializado no processo principal")
else:
    # Processo de reloader - não inicializa scheduler
    logger.info("Processo de reloader detectado - scheduler não inicializado")

# Health Checker - Fase 2
from health import init_health_checker
init_health_checker(app=app, db=db, scheduler=scheduler)

# Notification System - Fase 2
from notifications import init_notifications
notification_manager = init_notifications()

# Validador
validator = InputValidator()

# ============================================================================
# BLUEPRINT DE AUTENTICAÇÃO
# ============================================================================

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """Página de login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if not user.active:
                flash('Sua conta está desativada. Contate o administrador.', 'danger')
                return render_template('login.html')

            login_user(user, remember=remember)
            user.last_login = db.func.now()
            db.session.commit()

            log_audit('login', 'user', user.id, {'username': username})

            next_page = request.args.get('next')
            flash(f'Bem-vindo, {user.username}!', 'success')
            return redirect(next_page or url_for('index'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
            log_audit('login_failed', 'user', None, {'username': username})

    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout do usuário."""
    log_audit('logout', 'user', current_user.id)
    logout_user()
    flash('Você saiu com sucesso.', 'info')
    return redirect(url_for('auth.login'))

app.register_blueprint(auth_bp)

# ============================================================================
# ROTAS PRINCIPAIS
# ============================================================================

@app.route('/')
@login_required
def index():
    """Dashboard principal."""
    try:
        # Estatísticas - usar count() ao invés de carregar todos os devices
        total_devices = Device.query.filter_by(active=True).count()

        # Backups dos últimos 30 dias
        from datetime import datetime, timedelta
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)

        successful_backups = Backup.query.filter(
            Backup.backup_date >= thirty_days_ago,
            Backup.status == 'success'
        ).count()

        failed_backups = Backup.query.filter(
            Backup.backup_date >= thirty_days_ago,
            Backup.status == 'failed'
        ).count()

        # Tamanho total
        total_size = db.session.query(db.func.sum(Backup.file_size)).scalar() or 0
        # Formatar tamanho: MB se < 1GB, senão GB
        if total_size < 1024**3:  # Menos de 1 GB
            total_size_formatted = f"{round(total_size / (1024**2), 2)} MB"
        else:
            total_size_formatted = f"{round(total_size / (1024**3), 2)} GB"
        total_size_gb = round(total_size / (1024**3), 2)

        # Backups recentes (com eager loading para evitar N+1 queries)
        recent_backups = Backup.query.options(
            db.joinedload(Backup.device)
        ).order_by(Backup.backup_date.desc()).limit(20).all()

        # Total de backups
        total_backups = Backup.query.count()

        # Últimos erros
        last_errors = Backup.query.options(
            db.joinedload(Backup.device)
        ).filter_by(status='failed').order_by(
            Backup.backup_date.desc()
        ).limit(5).all()

        # Devices recentes (limitado a 100 mais recentes para performance)
        recent_devices = Device.query.filter_by(active=True).order_by(
            Device.updated_at.desc()
        ).limit(100).all()

        # Provedores
        provedores = database_manager.get_provedores()

        return render_template('dashboard.html',
            total_devices=total_devices,
            successful_backups=successful_backups,
            failed_backups=failed_backups,
            total_size_formatted=total_size_formatted,
            recent_backups=[b.to_dict() for b in recent_backups],
            total_backups=total_backups,
            devices=[d.to_dict() for d in recent_devices],  # Apenas 100 devices mais recentes
            provedores=provedores,
            last_errors=[e.to_dict() for e in last_errors]
        )
    except Exception as e:
        logger.error(f"Erro no dashboard: {e}")
        flash('Erro ao carregar dashboard.', 'danger')
        return render_template('dashboard.html', total_devices=0, successful_backups=0,
                             failed_backups=0, total_size_formatted="0 MB", recent_backups=[],
                             total_backups=0, devices=[], provedores=[], last_errors=[])

# ============================================================================
# DEVICES
# ============================================================================

@app.route('/devices')
@login_required
def devices():
    """Lista de dispositivos (paginação client-side via JavaScript)."""
    # Filtro opcional por provedor
    provedor_id = request.args.get('provedor_id', type=int)

    # Query base
    query = Device.query

    if provedor_id:
        query = query.filter_by(provedor_id=provedor_id)

    # Buscar todos os dispositivos (JavaScript faz a paginação)
    all_devices = query.order_by(Device.name).all()

    # Contadores totais
    total_devices = Device.query.count()
    active_devices = Device.query.filter_by(active=True).count()
    inactive_devices = Device.query.filter_by(active=False).count()

    return render_template('devices.html',
                         devices=[d.to_dict() for d in all_devices],
                         total_devices=total_devices,
                         active_devices=active_devices,
                         inactive_devices=inactive_devices)

@app.route('/devices/add', methods=['POST'])
@login_required
@operator_required
@limiter.limit("10 per minute")
def add_device():
    """Adiciona novo dispositivo."""
    try:
        # Validar dados
        data = {
            'name': request.form.get('name'),
            'ip_address': request.form.get('ip_address'),
            'device_type': request.form.get('device_type'),
            'protocol': request.form.get('protocol'),
            'username': request.form.get('username'),
            'password': request.form.get('password'),
            'port': request.form.get('port', 22),
            'enable_password': request.form.get('enable_password'),
            'backup_command': request.form.get('backup_command'),
            'provedor': request.form.get('provedor', 'Sem_Provedor')
        }

        validated_data = validate_device_data(data)

        # Adicionar device
        device_id = database_manager.add_device(**validated_data)

        log_audit('create', 'device', device_id, {'name': validated_data['name']})

        return jsonify({'success': True, 'device_id': device_id}), 201

    except ValidationError as e:
        return jsonify({'success': False, 'error': str(e)}), 422
    except Exception as e:
        logger.error(f"Erro ao adicionar device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/devices/<int:device_id>/get')
@login_required
def get_device_data(device_id):
    """Obtém dados de um dispositivo."""
    device = Device.query.get(device_id)
    if device:
        # Não retornar senhas para usuários não-operators
        if not current_user.can_edit():
            device_dict = device.to_dict(include_credentials=False)
        else:
            device_dict = device.to_dict(include_credentials=True)
            # Descriptografar senhas
            try:
                device_dict['password'] = database_manager.crypto_manager.decrypt(device.password)
                if device.enable_password:
                    device_dict['enable_password'] = database_manager.crypto_manager.decrypt(device.enable_password)
            except:
                pass
        return jsonify(device_dict)
    return jsonify({'error': 'Not found'}), 404

@app.route('/devices/<int:device_id>/update', methods=['POST'])
@login_required
@operator_required
def update_device(device_id):
    """Atualiza um dispositivo."""
    try:
        data = request.get_json()
        database_manager.update_device(device_id, **data)
        log_audit('update', 'device', device_id, data)
        return jsonify({'success': True}), 200
    except ValidationError as e:
        return jsonify({'success': False, 'error': str(e)}), 422
    except Exception as e:
        logger.error(f"Erro ao atualizar device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/devices/<int:device_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_device_permanent(device_id):
    """Deleta permanentemente um dispositivo."""
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'success': False, 'error': 'Dispositivo não encontrado'}), 404

        device_name = device.name
        db.session.delete(device)
        db.session.commit()

        log_audit('delete', 'device', device_id, {'name': device_name})
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao deletar device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# BACKUPS
# ============================================================================

@app.route('/backup/<int:device_id>', methods=['POST'])
@login_required
@operator_required
@limiter.limit("20 per minute")
def backup_device(device_id):
    """Executa backup de um dispositivo."""
    try:
        device = Device.query.get(device_id)
        if not device:
            logger.warning("Backup attempt for non-existent device", device_id=device_id)
            return jsonify({'success': False, 'error': 'Dispositivo não encontrado'}), 404

        logger.info("Starting manual backup",
                   device_id=device_id,
                   device_name=device.name,
                   device_type=device.device_type,
                   protocol=device.protocol)

        result = backup_manager.backup_device(device_id)
        log_audit('backup', 'device', device_id, result)

        if result.get('success'):
            logger.info("Backup completed successfully",
                       device_id=device_id,
                       file_path=result.get('file_path'),
                       file_size=result.get('file_size'))
            # Notifica sucesso (se configurado)
            if notification_manager:
                notification_manager.notify_backup_success(
                    device.name,
                    device_id,
                    result.get('file_size', 0)
                )
        else:
            logger.error("Backup failed",
                        device_id=device_id,
                        error=result.get('error'))
            # Notifica falha
            if notification_manager:
                notification_manager.notify_backup_failure(
                    device.name,
                    device_id,
                    result.get('error', 'Unknown error')
                )

        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 422
    except Exception as e:
        logger.error(f"Erro no backup: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/backup/all', methods=['POST'])
@login_required
@operator_required
def backup_all():
    """Executa backup paralelo de todos os dispositivos."""
    try:
        logger.info(f"Usuário {current_user.username} iniciou backup de todos os dispositivos")
        results = backup_manager.backup_all_devices_parallel()

        # Estatísticas do resultado
        total = len(results)
        success = sum(1 for r in results if r['result'].get('success'))
        failed = total - success

        log_audit('backup_all', 'device', None, {
            'count': total,
            'success': success,
            'failed': failed
        })

        logger.info(f"Backup all concluído: {success}/{total} sucessos")
        return jsonify({'success': True, 'results': results, 'stats': {'total': total, 'success': success, 'failed': failed}}), 200
    except Exception as e:
        logger.error(f"Erro no backup all: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/backups')
@login_required
def backups():
    """Lista de backups (paginação client-side via JavaScript)."""
    # Filtro opcional por device
    device_id = request.args.get('device_id', type=int)

    # Query base com eager loading - sem limite para permitir paginação client-side
    query = Backup.query.options(db.joinedload(Backup.device))

    if device_id:
        query = query.filter_by(device_id=device_id)

    # Buscar todos os backups (JavaScript faz a paginação)
    all_backups = query.order_by(Backup.backup_date.desc()).all()

    # Contadores totais
    total_backups = Backup.query.count()

    provedores = database_manager.get_provedores()

    return render_template('backups.html',
        recent_backups=[b.to_dict() for b in all_backups],
        total_backups=total_backups,
        provedores=provedores
    )

@app.route('/backups/<int:backup_id>/download')
@login_required
def download_backup(backup_id):
    """Download de arquivo de backup."""
    backup = Backup.query.get(backup_id)
    if backup and os.path.exists(backup.file_path):
        # Validar path traversal
        try:
            validated_path = validator.sanitize_path(backup.file_path, app.config['BACKUP_DIR'])
            log_audit('download', 'backup', backup_id)
            return send_file(validated_path, as_attachment=True, download_name=backup.filename)
        except ValidationError as e:
            logger.error(f"Path traversal detectado: {e}")
            return jsonify({'error': 'Acesso negado'}), 403
    return jsonify({'error': 'Backup não encontrado'}), 404

@app.route('/backups/<int:backup_id>/view')
@login_required
def view_backup(backup_id):
    """Visualiza conteúdo do backup."""
    content = backup_manager.get_backup_file(backup_id)
    if content:
        return render_template('view_backup.html', content=content, backup_id=backup_id)
    return jsonify({'error': 'Backup não encontrado'}), 404

@app.route('/backups/compare')
@login_required
def compare_backups():
    """Compara dois backups e mostra as diferenças."""
    import difflib

    backup1_id = request.args.get('backup1', type=int)
    backup2_id = request.args.get('backup2', type=int)

    if not backup1_id or not backup2_id:
        return jsonify({'error': 'Dois backups devem ser selecionados'}), 400

    # Buscar os backups
    backup1 = Backup.query.get(backup1_id)
    backup2 = Backup.query.get(backup2_id)

    if not backup1 or not backup2:
        return jsonify({'error': 'Backup não encontrado'}), 404

    # Verificar se são do mesmo dispositivo
    if backup1.device_id != backup2.device_id:
        return jsonify({'error': 'Os backups devem ser do mesmo dispositivo'}), 400

    # Ler conteúdo dos backups
    content1 = backup_manager.get_backup_file(backup1_id)
    content2 = backup_manager.get_backup_file(backup2_id)

    if not content1 or not content2:
        return jsonify({'error': 'Não foi possível ler os arquivos de backup'}), 404

    # Dividir em linhas para comparação
    lines1 = content1.splitlines()
    lines2 = content2.splitlines()

    # Gerar diff em formato HTML
    differ = difflib.HtmlDiff(wrapcolumn=80)
    diff_html = differ.make_table(
        lines1,
        lines2,
        fromdesc=f'Backup de {backup1.backup_date.strftime("%d/%m/%Y %H:%M:%S")}',
        todesc=f'Backup de {backup2.backup_date.strftime("%d/%m/%Y %H:%M:%S")}',
        context=True,
        numlines=3
    )

    # Log da ação
    log_audit('compare', 'backup', None, {'backup1_id': backup1_id, 'backup2_id': backup2_id})

    # Renderizar template com o diff
    return render_template('compare_backups.html',
                         diff_html=diff_html,
                         backup1=backup1,
                         backup2=backup2)

# ============================================================================
# NOTIFICATIONS DEMO
# ============================================================================

@app.route('/notifications-demo')
@login_required
def notifications_demo():
    """Página de demonstração do sistema de notificações visuais."""
    return render_template('notifications_demo.html')

# ============================================================================
# SCHEDULES
# ============================================================================

@app.route('/schedules')
@login_required
def schedules_page():
    """Página de agendamentos."""
    all_schedules = database_manager.get_schedules(active_only=False)
    all_devices = Device.query.order_by(Device.name).all()
    return render_template('schedules.html',
        schedules=all_schedules,
        devices=[d.to_dict() for d in all_devices]
    )

@app.route('/schedules/add', methods=['POST'])
@login_required
@operator_required
def add_schedule():
    """Adiciona agendamento."""
    try:
        device_id = request.form.get('device_id')
        device_id = int(device_id) if device_id else None

        frequency = validator.validate_frequency(request.form['frequency'])
        time = validator.validate_time(request.form['time'])
        day_of_week = int(request.form['day_of_week']) if request.form.get('day_of_week') else None
        day_of_month = int(request.form['day_of_month']) if request.form.get('day_of_month') else None

        schedule_id = database_manager.add_schedule(device_id, frequency, time, day_of_week, day_of_month)
        schedule = database_manager.get_schedule(schedule_id)

        # Adiciona job apenas se scheduler está ativo (processo principal)
        if scheduler:
            scheduler.add_job(schedule)

        log_audit('create', 'schedule', schedule_id)
        return jsonify({'success': True, 'schedule_id': schedule_id}), 201
    except ValidationError as e:
        return jsonify({'success': False, 'error': str(e)}), 422
    except Exception as e:
        logger.error(f"Erro ao criar schedule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/schedules/<int:schedule_id>/get')
@login_required
def get_schedule_data(schedule_id):
    """Obtém dados de um agendamento."""
    schedule = database_manager.get_schedule(schedule_id)
    if schedule:
        return jsonify(schedule)
    return jsonify({'error': 'Not found'}), 404

@app.route('/schedules/<int:schedule_id>/update', methods=['POST'])
@login_required
@operator_required
def update_schedule(schedule_id):
    """Atualiza agendamento."""
    try:
        data = request.get_json()
        schedule = Schedule.query.get(schedule_id)
        if not schedule:
            return jsonify({'success': False, 'error': 'Agendamento não encontrado'}), 404

        device_id = data.get('device_id')
        device_id = int(device_id) if device_id and device_id != 'null' else None

        schedule.device_id = device_id
        schedule.frequency = validator.validate_frequency(data['frequency'])
        schedule.time = validator.validate_time(data['time'])
        schedule.day_of_week = data.get('day_of_week')
        schedule.day_of_month = data.get('day_of_month')

        db.session.commit()

        # Atualiza job apenas se scheduler está ativo (processo principal)
        if scheduler:
            scheduler.remove_job(schedule_id)
            scheduler.add_job(schedule.to_dict())

        log_audit('update', 'schedule', schedule_id)
        return jsonify({'success': True}), 200
    except ValidationError as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 422
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao atualizar schedule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/schedules/<int:schedule_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_schedule(schedule_id):
    """Deleta agendamento."""
    try:
        schedule = Schedule.query.get(schedule_id)
        if not schedule:
            return jsonify({'success': False, 'error': 'Agendamento não encontrado'}), 404

        database_manager.delete_schedule(schedule_id)

        # Remove job apenas se scheduler está ativo (processo principal)
        if scheduler:
            scheduler.remove_job(schedule_id)

        log_audit('delete', 'schedule', schedule_id)
        return jsonify({'success': True}), 200
    except Exception as e:
        logger.error(f"Erro ao deletar schedule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# API / PROVEDORES
# ============================================================================

@app.route('/api/stats')
@login_required
def api_stats():
    """Estatísticas da API."""
    devices = Device.query.filter_by(active=True).all()
    backups = Backup.query.limit(1000).all()
    schedules = Schedule.query.filter_by(active=True).all()

    return jsonify({
        'total_devices': Device.query.count(),
        'active_devices': len(devices),
        'total_backups': Backup.query.count(),
        'successful_backups': Backup.query.filter_by(status='success').count(),
        'failed_backups': Backup.query.filter_by(status='failed').count(),
        'active_schedules': len(schedules),
        'next_jobs': scheduler.get_jobs() if scheduler else []
    })

@app.route('/api/charts')
@login_required
def api_charts():
    """Dados para gráficos do dashboard."""
    from sqlalchemy import func

    # Backups por dia (últimos 7 dias)
    today = datetime.now(timezone.utc).date()
    seven_days_ago = today - timedelta(days=6)

    backups_by_day = db.session.query(
        func.date(Backup.backup_date).label('date'),
        func.count(Backup.id).label('count'),
        func.sum(db.case((Backup.status == 'success', 1), else_=0)).label('success'),
        func.sum(db.case((Backup.status == 'failed', 1), else_=0)).label('failed')
    ).filter(
        func.date(Backup.backup_date) >= seven_days_ago
    ).group_by(
        func.date(Backup.backup_date)
    ).order_by('date').all()

    # Criar dicionário para todos os dias (incluindo dias sem backup)
    daily_data = {(seven_days_ago + timedelta(days=i)).isoformat(): {'total': 0, 'success': 0, 'failed': 0}
                  for i in range(7)}

    for row in backups_by_day:
        # row.date pode ser string (SQLite) ou date object
        if isinstance(row.date, str):
            date_str = row.date
        else:
            date_str = row.date.isoformat()
        daily_data[date_str] = {
            'total': row.count,
            'success': row.success,
            'failed': row.failed
        }

    # Dispositivos por provedor
    devices_by_provider = db.session.query(
        func.coalesce(Device.provedor, 'Sem Provedor').label('provedor'),
        func.count(Device.id).label('count')
    ).filter(
        Device.active == True
    ).group_by(
        Device.provedor
    ).all()

    # Taxa de sucesso total
    total_backups = Backup.query.count()
    successful = Backup.query.filter_by(status='success').count()
    failed = Backup.query.filter_by(status='failed').count()

    return jsonify({
        'backups_by_day': {
            'labels': sorted(daily_data.keys()),
            'data': {
                'total': [daily_data[date]['total'] for date in sorted(daily_data.keys())],
                'success': [daily_data[date]['success'] for date in sorted(daily_data.keys())],
                'failed': [daily_data[date]['failed'] for date in sorted(daily_data.keys())]
            }
        },
        'devices_by_provider': {
            'labels': [row.provedor for row in devices_by_provider],
            'data': [row.count for row in devices_by_provider]
        },
        'success_rate': {
            'labels': ['Sucesso', 'Falha'],
            'data': [successful, failed]
        }
    })

@app.route('/api/provedores')
@login_required
def api_provedores():
    """Lista de provedores."""
    provedores = database_manager.get_provedores()
    return jsonify({"provedores": provedores})

@app.route('/api/provedores/all')
@login_required
def api_provedores_all():
    """Todos os provedores com detalhes."""
    provedores = database_manager.get_all_provedores()
    return jsonify({"provedores": provedores})

@app.route('/api/provedores/add', methods=['POST'])
@login_required
@operator_required
def api_provedores_add():
    """Adiciona provedor."""
    try:
        data = request.get_json()
        name = validator.validate_provedor(data.get('name', ''))
        description = data.get('description')

        provedor_id = database_manager.add_provedor(name, description)
        log_audit('create', 'provedor', provedor_id, {'name': name})
        return jsonify({'success': True, 'provedor_id': provedor_id}), 201
    except ValidationError as e:
        return jsonify({'success': False, 'error': str(e)}), 422
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 409
    except Exception as e:
        logger.error(f"Erro ao adicionar provedor: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/provedores/<int:provedor_id>/delete', methods=['POST'])
@login_required
@admin_required
def api_provedores_delete(provedor_id):
    """Deleta provedor."""
    try:
        database_manager.delete_provedor(provedor_id)
        log_audit('delete', 'provedor', provedor_id)
        return jsonify({'success': True}), 200
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 404
    except Exception as e:
        logger.error(f"Erro ao deletar provedor: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# PROVEDORES PAGE (NEW - Full CRUD)
# ============================================================================

@app.route('/provedores')
@login_required
def provedores_page():
    """Página de gerenciamento de provedores."""
    return render_template('provedores.html')

@app.route('/provedores/<int:provedor_id>')
@login_required
def get_provedor(provedor_id):
    """Obter detalhes de um provedor."""
    try:
        provedor = Provedor.query.get_or_404(provedor_id)
        return jsonify(provedor.to_dict()), 200
    except Exception as e:
        logger.error(f"Erro ao buscar provedor {provedor_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/provedores/add', methods=['POST'])
@login_required
@operator_required
def add_provedor():
    """Adicionar novo provedor com campos completos."""
    try:
        data = request.get_json()

        # Validar nome único
        name = validator.validate_provedor(data.get('name', ''))
        if Provedor.query.filter_by(name=name).first():
            return jsonify({'error': 'Já existe um provedor com este nome'}), 409

        # Validar CNPJ único se fornecido
        cnpj = data.get('cnpj', '').strip()
        if cnpj and Provedor.query.filter_by(cnpj=cnpj).first():
            return jsonify({'error': 'Já existe um provedor com este CNPJ'}), 409

        # Criar novo provedor
        provedor = Provedor(
            name=name,
            razao_social=data.get('razao_social'),
            nome_fantasia=data.get('nome_fantasia'),
            cnpj=cnpj if cnpj else None,
            telefone=data.get('telefone'),
            whatsapp=data.get('whatsapp'),
            email=data.get('email'),
            website=data.get('website'),
            contato_principal=data.get('contato_principal'),
            cep=data.get('cep'),
            endereco=data.get('endereco'),
            numero=data.get('numero'),
            complemento=data.get('complemento'),
            bairro=data.get('bairro'),
            cidade=data.get('cidade'),
            estado=data.get('estado'),
            description=data.get('description'),
            observacoes=data.get('observacoes'),
            active=data.get('active', True)
        )

        db.session.add(provedor)
        db.session.commit()

        log_audit('create', 'provedor', provedor.id, {'name': provedor.name})
        return jsonify({'success': True, 'provedor_id': provedor.id}), 201

    except ValidationError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 422
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao adicionar provedor: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/provedores/<int:provedor_id>/update', methods=['POST'])
@login_required
@operator_required
def update_provedor(provedor_id):
    """Atualizar provedor existente."""
    try:
        provedor = Provedor.query.get_or_404(provedor_id)
        data = request.get_json()

        # Validar nome único (exceto próprio provedor)
        name = validator.validate_provedor(data.get('name', ''))
        existing = Provedor.query.filter_by(name=name).first()
        if existing and existing.id != provedor_id:
            return jsonify({'error': 'Já existe outro provedor com este nome'}), 409

        # Validar CNPJ único se fornecido (exceto próprio provedor)
        cnpj = data.get('cnpj', '').strip()
        if cnpj:
            existing = Provedor.query.filter_by(cnpj=cnpj).first()
            if existing and existing.id != provedor_id:
                return jsonify({'error': 'Já existe outro provedor com este CNPJ'}), 409

        # Atualizar campos
        provedor.name = name
        provedor.razao_social = data.get('razao_social')
        provedor.nome_fantasia = data.get('nome_fantasia')
        provedor.cnpj = cnpj if cnpj else None
        provedor.telefone = data.get('telefone')
        provedor.whatsapp = data.get('whatsapp')
        provedor.email = data.get('email')
        provedor.website = data.get('website')
        provedor.contato_principal = data.get('contato_principal')
        provedor.cep = data.get('cep')
        provedor.endereco = data.get('endereco')
        provedor.numero = data.get('numero')
        provedor.complemento = data.get('complemento')
        provedor.bairro = data.get('bairro')
        provedor.cidade = data.get('cidade')
        provedor.estado = data.get('estado')
        provedor.description = data.get('description')
        provedor.observacoes = data.get('observacoes')
        provedor.active = data.get('active', True)

        db.session.commit()

        log_audit('update', 'provedor', provedor.id, {'name': provedor.name})
        return jsonify({'success': True}), 200

    except ValidationError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 422
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao atualizar provedor {provedor_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/provedores/<int:provedor_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_provedor(provedor_id):
    """Deletar provedor."""
    try:
        provedor = Provedor.query.get_or_404(provedor_id)
        name = provedor.name

        # Verificar se há dispositivos associados
        device_count = provedor.devices.count()
        if device_count > 0:
            return jsonify({
                'error': f'Não é possível excluir. Existem {device_count} dispositivo(s) associado(s) a este provedor.'
            }), 409

        db.session.delete(provedor)
        db.session.commit()

        log_audit('delete', 'provedor', provedor_id, {'name': name})
        return jsonify({'success': True}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao deletar provedor {provedor_id}: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# AUDIT LOGS
# ============================================================================

@app.route('/audit-logs')
@login_required
@admin_required
def audit_logs_page():
    """Página de logs de auditoria (somente admin)."""
    return render_template('audit_logs.html')

@app.route('/api/audit-logs')
@login_required
@admin_required
def get_audit_logs():
    """API para buscar logs de auditoria."""
    try:
        # Buscar todos os logs ordenados por timestamp decrescente (mais recentes primeiro)
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(1000).all()

        return jsonify({
            'success': True,
            'logs': [log.to_dict() for log in logs]
        }), 200
    except Exception as e:
        logger.error(f"Erro ao buscar audit logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# USERS MANAGEMENT
# ============================================================================

@app.route('/users')
@login_required
@admin_required
def users_page():
    """Página de gerenciamento de usuários."""
    all_users = User.query.order_by(User.username).all()
    return render_template('users.html', users=[u.to_dict() for u in all_users])

@app.route('/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    """Adiciona novo usuário."""
    try:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'viewer')

        # Validar campos obrigatórios
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username e senha são obrigatórios'}), 422

        # Verificar se usuário já existe
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Usuário já existe'}), 409

        # Criar usuário
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        log_audit('create', 'user', new_user.id, {'username': username, 'role': role})
        return jsonify({'success': True, 'user_id': new_user.id}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao criar usuário: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/users/<int:user_id>/get')
@login_required
@admin_required
def get_user_data(user_id):
    """Obtém dados de um usuário."""
    user = User.query.get(user_id)
    if user:
        return jsonify(user.to_dict())
    return jsonify({'error': 'Usuário não encontrado'}), 404

@app.route('/users/<int:user_id>/update', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    """Atualiza um usuário."""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'Usuário não encontrado'}), 404

        data = request.get_json()

        # Atualizar campos
        if 'email' in data:
            user.email = data['email']
        if 'role' in data:
            user.role = data['role']
        if 'password' in data and data['password']:
            user.set_password(data['password'])

        db.session.commit()
        log_audit('update', 'user', user_id, data)
        return jsonify({'success': True}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao atualizar usuário: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
@admin_required
def toggle_user_active(user_id):
    """Ativa/desativa um usuário."""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'Usuário não encontrado'}), 404

        # Não permitir desativar o próprio usuário
        if user.id == current_user.id:
            return jsonify({'success': False, 'error': 'Você não pode desativar sua própria conta'}), 400

        user.active = not user.active
        db.session.commit()

        log_audit('toggle_active', 'user', user_id, {'active': user.active})
        return jsonify({'success': True, 'active': user.active}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao ativar/desativar usuário: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    """Deleta um usuário."""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'Usuário não encontrado'}), 404

        # Não permitir deletar o próprio usuário
        if user.id == current_user.id:
            return jsonify({'success': False, 'error': 'Você não pode deletar sua própria conta'}), 400

        username = user.username
        db.session.delete(user)
        db.session.commit()

        log_audit('delete', 'user', user_id, {'username': username})
        return jsonify({'success': True}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao deletar usuário: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# HEALTH CHECKS - FASE 2
# ============================================================================

@app.route('/health')
def health_liveness():
    """
    Liveness probe - verifica se a aplicação está rodando.

    Usado por Kubernetes/Docker para saber se deve reiniciar o container.
    Não requer autenticação.
    """
    from health import get_health_checker

    checker = get_health_checker()
    if checker is None:
        return jsonify({
            'status': 'healthy',
            'message': 'Health checker not initialized, but app is running'
        }), 200

    result = checker.liveness()
    return jsonify(result), 200


@app.route('/health/ready')
def health_readiness():
    """
    Readiness probe - verifica se a aplicação está pronta para receber tráfego.

    Verifica componentes críticos: banco de dados, scheduler, etc.
    Não requer autenticação.
    """
    from health import get_health_checker

    checker = get_health_checker()
    if checker is None:
        return jsonify({
            'status': 'unhealthy',
            'message': 'Health checker not initialized'
        }), 503

    result = checker.readiness()
    status_code = 200 if result['status'] == 'healthy' else 503
    return jsonify(result), status_code


@app.route('/health/detailed')
@login_required
@admin_required
def health_detailed():
    """
    Health check detalhado - informações completas do sistema.

    Requer autenticação de admin.
    """
    from health import get_health_checker

    checker = get_health_checker()
    if checker is None:
        return jsonify({
            'status': 'unknown',
            'message': 'Health checker not initialized'
        }), 500

    result = checker.detailed()
    log_audit('view', 'health_check', None, {'endpoint': 'detailed'})
    return jsonify(result), 200


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(401)
def unauthorized(e):
    """Handler para 401 Unauthorized."""
    if request.is_json:
        return jsonify({'error': 'Não autorizado'}), 401
    flash('Você precisa fazer login para acessar esta página.', 'warning')
    return redirect(url_for('auth.login', next=request.url))

@app.errorhandler(403)
def forbidden(e):
    """Handler para 403 Forbidden."""
    if request.is_json:
        return jsonify({'error': 'Acesso negado'}), 403
    flash('Você não tem permissão para acessar esta página.', 'danger')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e):
    """Handler para 404 Not Found."""
    if request.is_json:
        return jsonify({'error': 'Não encontrado'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    """Handler para 500 Internal Server Error."""
    logger.error(f"Erro interno: {e}")
    db.session.rollback()
    if request.is_json:
        return jsonify({'error': 'Erro interno do servidor'}), 500
    return render_template('500.html'), 500

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'

    with app.app_context():
        db.create_all()
        logger.info("Banco de dados inicializado")

    logger.info(f"Iniciando aplicação na porta {port} (debug={debug})")
    app.run(host='0.0.0.0', port=port, debug=debug)
