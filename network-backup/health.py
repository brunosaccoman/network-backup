"""
Health Check System - Fase 2: Observabilidade

Fornece endpoints para verificação de saúde do sistema:
- Liveness: Aplicação está rodando?
- Readiness: Aplicação está pronta para receber tráfego?
- Componentes: Status de cada componente (DB, Scheduler, etc)
"""

import logging
from datetime import datetime
from typing import Dict, Any
import psutil
import pytz

logger = logging.getLogger(__name__)


class HealthChecker:
    """Gerencia verificações de saúde do sistema."""

    def __init__(self, app=None, db=None, scheduler=None):
        """
        Inicializa o health checker.

        Args:
            app: Instância Flask
            db: Instância do banco de dados (SQLAlchemy)
            scheduler: Instância do scheduler (APScheduler)
        """
        self.app = app
        self.db = db
        self.scheduler = scheduler
        self.timezone = pytz.timezone('America/Porto_Velho')
        self.start_time = datetime.now(self.timezone)

    def liveness(self) -> Dict[str, Any]:
        """
        Liveness probe - verifica se a aplicação está rodando.

        Usado por Kubernetes/Docker para saber se deve reiniciar o container.

        Returns:
            Dict com status e informações básicas
        """
        return {
            'status': 'healthy',
            'timestamp': datetime.now(self.timezone).isoformat(),
            'uptime_seconds': self._get_uptime_seconds(),
            'service': 'network-backup'
        }

    def readiness(self) -> Dict[str, Any]:
        """
        Readiness probe - verifica se a aplicação está pronta para receber tráfego.

        Verifica componentes críticos: banco de dados, scheduler, etc.

        Returns:
            Dict com status detalhado de cada componente
        """
        checks = {
            'database': self._check_database(),
            'scheduler': self._check_scheduler(),
        }

        # Status geral: healthy se todos os componentes estiverem OK
        all_healthy = all(check['status'] == 'healthy' for check in checks.values())
        overall_status = 'healthy' if all_healthy else 'unhealthy'

        return {
            'status': overall_status,
            'timestamp': datetime.now(self.timezone).isoformat(),
            'checks': checks,
            'uptime_seconds': self._get_uptime_seconds()
        }

    def detailed(self) -> Dict[str, Any]:
        """
        Health check detalhado - informações completas do sistema.

        Inclui métricas de sistema, recursos, etc.

        Returns:
            Dict com informações detalhadas de saúde
        """
        checks = {
            'database': self._check_database(),
            'scheduler': self._check_scheduler(),
            'system': self._check_system_resources(),
            'application': self._check_application()
        }

        all_healthy = all(
            check['status'] == 'healthy'
            for check in checks.values()
            if 'status' in check
        )
        overall_status = 'healthy' if all_healthy else 'unhealthy'

        return {
            'status': overall_status,
            'timestamp': datetime.now(self.timezone).isoformat(),
            'uptime_seconds': self._get_uptime_seconds(),
            'start_time': self.start_time.isoformat(),
            'checks': checks,
            'version': self._get_version()
        }

    def _check_database(self) -> Dict[str, Any]:
        """Verifica conectividade com banco de dados."""
        try:
            if self.db is None:
                return {
                    'status': 'unknown',
                    'message': 'Database instance not configured'
                }

            # Tenta executar uma query simples
            with self.app.app_context():
                result = self.db.session.execute(self.db.text('SELECT 1'))
                result.close()

            # Pega informações de pool de conexões
            pool_info = {}
            if hasattr(self.db.engine.pool, 'size'):
                pool_info = {
                    'pool_size': self.db.engine.pool.size(),
                    'checked_in': self.db.engine.pool.checkedin(),
                    'checked_out': self.db.engine.pool.checkedout(),
                    'overflow': self.db.engine.pool.overflow()
                }

            return {
                'status': 'healthy',
                'message': 'Database connection OK',
                'pool': pool_info
            }

        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
            return {
                'status': 'unhealthy',
                'message': f'Database error: {str(e)}'
            }

    def _check_scheduler(self) -> Dict[str, Any]:
        """Verifica status do scheduler de backups."""
        try:
            if self.scheduler is None:
                return {
                    'status': 'unknown',
                    'message': 'Scheduler instance not configured'
                }

            # Verifica se o scheduler está rodando
            is_running = self.scheduler.scheduler.running

            if not is_running:
                return {
                    'status': 'unhealthy',
                    'message': 'Scheduler is not running'
                }

            # Pega informações sobre jobs agendados
            jobs = self.scheduler.scheduler.get_jobs()
            active_jobs = [j for j in jobs if j.next_run_time is not None]

            return {
                'status': 'healthy',
                'message': 'Scheduler running',
                'total_jobs': len(jobs),
                'active_jobs': len(active_jobs),
                'paused_jobs': len(jobs) - len(active_jobs)
            }

        except Exception as e:
            logger.error(f"Scheduler health check failed: {str(e)}")
            return {
                'status': 'unhealthy',
                'message': f'Scheduler error: {str(e)}'
            }

    def _check_system_resources(self) -> Dict[str, Any]:
        """Verifica recursos do sistema (CPU, memória, disco)."""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()

            # Memória
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available_mb = memory.available / (1024 * 1024)

            # Disco (diretório atual)
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_free_gb = disk.free / (1024 * 1024 * 1024)

            # Determina status baseado em thresholds
            status = 'healthy'
            warnings = []

            if cpu_percent > 90:
                warnings.append('High CPU usage')
                status = 'degraded'

            if memory_percent > 90:
                warnings.append('High memory usage')
                status = 'degraded'

            if disk_percent > 90:
                warnings.append('Low disk space')
                status = 'degraded'

            return {
                'status': status,
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count
                },
                'memory': {
                    'percent': memory_percent,
                    'available_mb': round(memory_available_mb, 2)
                },
                'disk': {
                    'percent': disk_percent,
                    'free_gb': round(disk_free_gb, 2)
                },
                'warnings': warnings if warnings else None
            }

        except Exception as e:
            logger.error(f"System resources check failed: {str(e)}")
            return {
                'status': 'unknown',
                'message': f'Error checking system resources: {str(e)}'
            }

    def _check_application(self) -> Dict[str, Any]:
        """Verifica informações da aplicação."""
        try:
            from models import Device, Backup, Schedule, User

            with self.app.app_context():
                stats = {
                    'devices': {
                        'total': Device.query.count(),
                        'active': Device.query.filter_by(active=True).count()
                    },
                    'backups': {
                        'total': Backup.query.count(),
                        'successful': Backup.query.filter_by(status='success').count(),
                        'failed': Backup.query.filter_by(status='failed').count()
                    },
                    'schedules': {
                        'total': Schedule.query.count(),
                        'active': Schedule.query.filter_by(active=True).count()
                    },
                    'users': {
                        'total': User.query.count(),
                        'active': User.query.filter_by(active=True).count()
                    }
                }

            return {
                'status': 'healthy',
                'statistics': stats
            }

        except Exception as e:
            logger.error(f"Application check failed: {str(e)}")
            return {
                'status': 'degraded',
                'message': f'Error getting application stats: {str(e)}'
            }

    def _get_uptime_seconds(self) -> int:
        """Retorna tempo de uptime em segundos."""
        now = datetime.now(self.timezone)
        delta = now - self.start_time
        return int(delta.total_seconds())

    def _get_version(self) -> str:
        """Retorna versão da aplicação."""
        # Pode ler de um arquivo VERSION ou variável de ambiente
        return "1.0.0-fase2"


# Instância global (será inicializada no app.py)
health_checker = None


def init_health_checker(app, db, scheduler):
    """
    Inicializa o health checker global.

    Args:
        app: Instância Flask
        db: Instância do banco de dados
        scheduler: Instância do scheduler
    """
    global health_checker
    health_checker = HealthChecker(app=app, db=db, scheduler=scheduler)
    logger.info("Health checker initialized")


def get_health_checker():
    """Retorna a instância global do health checker."""
    return health_checker
