from datetime import datetime
import pytz
from app import scheduler

tz = pytz.timezone('America/Porto_Velho')
now = datetime.now(tz)
print(f'Hora atual: {now.strftime("%H:%M:%S")}')
print(f'\nScheduler rodando: {scheduler.scheduler.running}')
print(f'\nJobs ativos:')
jobs = scheduler.scheduler.get_jobs()
print(f'Total de jobs: {len(jobs)}')
for j in jobs:
    print(f'  ID: {j.id}')
    print(f'  Nome: {j.name}')
    print(f'  Proxima execucao: {j.next_run_time}')
    print(f'  Trigger: {j.trigger}')
    print()
