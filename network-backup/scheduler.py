"""
Scheduler de backups usando APScheduler com integração Flask/SQLAlchemy.

Este módulo gerencia agendamentos de backups automáticos, integrando
com o contexto da aplicação Flask para acesso ao banco de dados.
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
import logging
from config import get_timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BackupScheduler:
    """
    Gerenciador de agendamentos de backup.

    Integra com Flask app context para acessar modelos SQLAlchemy.
    """

    def __init__(self, app=None, backup_manager=None):
        """
        Inicializa o scheduler.

        Args:
            app: Instância da aplicação Flask (opcional)
            backup_manager: Instância do BackupManager (opcional)
        """
        self.scheduler = BackgroundScheduler()
        self.app = app
        self.backup_manager = backup_manager
        self.scheduler.start()

        # Carrega schedules apenas se app foi fornecido
        if self.app:
            self.load_schedules()

    def set_app(self, app, backup_manager):
        """
        Define a aplicação Flask e backup manager após inicialização.

        Args:
            app: Instância da aplicação Flask
            backup_manager: Instância do BackupManager
        """
        self.app = app
        self.backup_manager = backup_manager
        self.load_schedules()

    def load_schedules(self):
        """Carrega todos os agendamentos ativos do banco de dados."""
        if not self.app:
            logger.warning("App não configurado, não é possível carregar schedules")
            return

        try:
            with self.app.app_context():
                from models import Schedule
                schedules = Schedule.query.filter_by(active=True).all()

                for schedule in schedules:
                    self.add_job(schedule.to_dict())

                logger.info(f"Carregados {len(schedules)} agendamentos")
        except Exception as e:
            logger.error(f"Erro ao carregar schedules: {str(e)}")

    def reload_schedules(self):
        """Recarrega todos os agendamentos (útil após alterações)."""
        try:
            # Remove todos os jobs atuais
            for job in self.scheduler.get_jobs():
                if job.id.startswith('schedule_'):
                    self.scheduler.remove_job(job.id)

            # Recarrega do banco
            self.load_schedules()
            logger.info("Schedules recarregados")
        except Exception as e:
            logger.error(f"Erro ao recarregar schedules: {str(e)}")

    def add_job(self, schedule):
        """
        Adiciona um job de agendamento.

        Args:
            schedule: Dicionário com dados do agendamento
        """
        try:
            job_id = f"schedule_{schedule['id']}"

            # Remove job existente se houver
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)

            # Parse time
            hour, minute = schedule['time'].split(':')

            # Timezone para agendamentos
            tz = get_timezone()

            # Cria trigger baseado na frequência
            if schedule['frequency'] == 'daily':
                trigger = CronTrigger(hour=hour, minute=minute, timezone=tz)
            elif schedule['frequency'] == 'weekly':
                day = schedule.get('day_of_week', 0)
                trigger = CronTrigger(day_of_week=day, hour=hour, minute=minute, timezone=tz)
            elif schedule['frequency'] == 'monthly':
                day = schedule.get('day_of_month', 1)
                trigger = CronTrigger(day=day, hour=hour, minute=minute, timezone=tz)
            else:
                logger.error(f"Frequência desconhecida: {schedule['frequency']}")
                return

            # Determina nome do job
            device_name = 'Todos os dispositivos'
            if schedule.get('device_id'):
                # Busca nome do dispositivo
                try:
                    with self.app.app_context():
                        from models import Device
                        device = Device.query.get(schedule['device_id'])
                        if device:
                            device_name = device.name
                except Exception as e:
                    logger.error(f"Erro ao buscar device: {str(e)}")

            # Adiciona job
            if schedule.get('device_id'):
                self.scheduler.add_job(
                    func=self.run_device_backup,
                    trigger=trigger,
                    id=job_id,
                    args=[schedule['device_id'], schedule['id']],
                    name=f"Backup {device_name}",
                    replace_existing=True
                )
            else:
                self.scheduler.add_job(
                    func=self.run_all_backups,
                    trigger=trigger,
                    id=job_id,
                    args=[schedule['id']],
                    name="Backup de todos os dispositivos",
                    replace_existing=True
                )

            logger.info(f"Job {job_id} adicionado: {device_name}")
        except Exception as e:
            logger.error(f"Erro ao adicionar job: {str(e)}")

    def run_device_backup(self, device_id, schedule_id):
        """
        Executa backup de um dispositivo específico.

        Args:
            device_id: ID do dispositivo
            schedule_id: ID do agendamento
        """
        logger.info(f"Executando backup agendado para dispositivo {device_id}")

        if not self.app or not self.backup_manager:
            logger.error("App ou BackupManager não configurados")
            return

        try:
            with self.app.app_context():
                from models import Schedule

                # Executa backup
                result = self.backup_manager.backup_device(device_id)

                # Atualiza last_run do schedule
                schedule = Schedule.query.get(schedule_id)
                if schedule:
                    schedule.last_run = datetime.now()
                    from models import db
                    db.session.commit()

                logger.info(f"Backup concluído: {result}")
        except Exception as e:
            logger.error(f"Erro ao executar backup: {str(e)}")

    def run_all_backups(self, schedule_id):
        """
        Executa backup paralelo de todos os dispositivos ativos.

        Args:
            schedule_id: ID do agendamento
        """
        logger.info("Executando backup paralelo de todos os dispositivos")

        if not self.app or not self.backup_manager:
            logger.error("App ou BackupManager não configurados")
            return

        try:
            with self.app.app_context():
                from models import Schedule, db

                # Executa backups em paralelo
                results = self.backup_manager.backup_all_devices_parallel()

                # Estatísticas
                total = len(results)
                success = sum(1 for r in results if r['result'].get('success'))
                failed = total - success

                # Atualiza last_run do schedule
                schedule = Schedule.query.get(schedule_id)
                if schedule:
                    schedule.last_run = datetime.now()
                    db.session.commit()

                logger.info(f"Backup agendado concluído: {success}/{total} sucessos, {failed} falhas")
        except Exception as e:
            logger.error(f"Erro ao executar backups agendados: {str(e)}")

    def remove_job(self, schedule_id):
        """
        Remove um job de agendamento.

        Args:
            schedule_id: ID do agendamento
        """
        job_id = f"schedule_{schedule_id}"
        try:
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)
                logger.info(f"Job {job_id} removido")
        except Exception as e:
            logger.error(f"Erro ao remover job: {str(e)}")

    def get_jobs(self):
        """
        Retorna lista de todos os jobs agendados.

        Returns:
            Lista de dicionários com informações dos jobs
        """
        jobs = []
        try:
            for job in self.scheduler.get_jobs():
                next_run = 'N/A'
                if job.next_run_time:
                    next_run = job.next_run_time.strftime('%Y-%m-%d %H:%M:%S')
                jobs.append({
                    'id': job.id,
                    'name': job.name,
                    'next_run': next_run
                })
        except Exception as e:
            logger.error(f"Erro ao listar jobs: {str(e)}")
        return jobs

    def shutdown(self):
        """Desliga o scheduler."""
        self.scheduler.shutdown()
        logger.info("Agendador desligado")
