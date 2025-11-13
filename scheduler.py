from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
from database import Database
from backup_manager import BackupManager
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BackupScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.db = Database()
        self.backup_manager = BackupManager()
        self.scheduler.start()
        self.load_schedules()
    
    def load_schedules(self):
        schedules = self.db.get_schedules(active_only=True)
        for schedule in schedules:
            self.add_job(schedule)
        logger.info(f"Carregados {len(schedules)} agendamentos")
    
    def add_job(self, schedule):
        try:
            job_id = f"schedule_{schedule['id']}"
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)
            
            hour, minute = schedule['time'].split(':')
            
            if schedule['frequency'] == 'daily':
                trigger = CronTrigger(hour=hour, minute=minute)
            elif schedule['frequency'] == 'weekly':
                day = schedule['day_of_week'] if schedule['day_of_week'] is not None else 0
                trigger = CronTrigger(day_of_week=day, hour=hour, minute=minute)
            elif schedule['frequency'] == 'monthly':
                day = schedule['day_of_month'] if schedule['day_of_month'] is not None else 1
                trigger = CronTrigger(day=day, hour=hour, minute=minute)
            else:
                logger.error(f"Frequência desconhecida: {schedule['frequency']}")
                return
            
            # Pegar nome do dispositivo de forma segura
            device_name = 'Todos os dispositivos'
            if schedule['device_id']:
                try:
                    device = self.db.get_device(schedule['device_id'])
                    if device:
                        device_name = device['name']
                except:
                    pass
            
            if schedule['device_id']:
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
            
            logger.info(f"Job {job_id} adicionado")
        except Exception as e:
            logger.error(f"Erro ao adicionar job: {str(e)}")
    
    def run_device_backup(self, device_id, schedule_id):
        logger.info(f"Executando backup agendado para dispositivo {device_id}")
        try:
            result = self.backup_manager.backup_device(device_id)
            self.db.update_schedule_last_run(schedule_id)
            logger.info(f"Backup concluído: {result}")
        except Exception as e:
            logger.error(f"Erro ao executar backup: {str(e)}")
    
    def run_all_backups(self, schedule_id):
        logger.info("Executando backup de todos os dispositivos")
        try:
            results = self.backup_manager.backup_all_devices()
            self.db.update_schedule_last_run(schedule_id)
            logger.info(f"Backups concluídos: {len(results)} dispositivos")
        except Exception as e:
            logger.error(f"Erro ao executar backups: {str(e)}")
    
    def remove_job(self, schedule_id):
        job_id = f"schedule_{schedule_id}"
        try:
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)
                logger.info(f"Job {job_id} removido")
        except Exception as e:
            logger.error(f"Erro ao remover job: {str(e)}")
    
    def get_jobs(self):
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
        self.scheduler.shutdown()
        logger.info("Agendador desligado")
