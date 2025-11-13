
import os
import sys
import subprocess

def criar_diretorio(path):
    os.makedirs(path, exist_ok=True)
    print(f"✅ Criado: {path}")

def criar_arquivo(path, conteudo):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(conteudo)
    print(f"✅ Criado: {path}")

def main():
    if os.geteuid() != 0:
        print("❌ Execute como root: sudo python3 criar_sistema.py")
        sys.exit(1)
    
    print("╔════════════════════════════════════════╗")
    print("║  Criando Sistema de Backup Completo   ║")
    print("╚════════════════════════════════════════╝\n")
    
    base = "/opt/network-backup"
    
    # Criar diretórios
    print("📁 Criando estrutura de diretórios...")
    for d in ['backups', 'templates', 'static', 'logs', 'db_backups']:
        criar_diretorio(f"{base}/{d}")
    
    os.chdir(base)
    
    # requirements.txt
    print("\n📝 Criando requirements.txt...")
    criar_arquivo(f"{base}/requirements.txt", """Flask==3.1.0
paramiko==3.5.0
APScheduler==3.10.4
python-dotenv==1.0.1
netmiko==4.4.0
gunicorn==23.0.0
""")

    # database.py
    print("📝 Criando database.py...")
    criar_arquivo(f"{base}/database.py", """import sqlite3
from datetime import datetime
import os

class Database:
    def __init__(self, db_path='backups.db'):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip_address TEXT NOT NULL UNIQUE,
                device_type TEXT NOT NULL,
                protocol TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                enable_password TEXT,
                backup_command TEXT,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                status TEXT DEFAULT 'success',
                error_message TEXT,
                backup_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                frequency TEXT NOT NULL,
                time TEXT NOT NULL,
                day_of_week INTEGER,
                day_of_month INTEGER,
                active INTEGER DEFAULT 1,
                last_run TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_device(self, name, ip_address, device_type, protocol, username, password, 
                   port=22, enable_password=None, backup_command=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO devices (name, ip_address, device_type, protocol, port, 
                               username, password, enable_password, backup_command)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, ip_address, device_type, protocol, port, username, 
              password, enable_password, backup_command))
        conn.commit()
        device_id = cursor.lastrowid
        conn.close()
        return device_id
    
    def get_all_devices(self, active_only=True):
        conn = self.get_connection()
        cursor = conn.cursor()
        if active_only:
            cursor.execute('SELECT * FROM devices WHERE active = 1 ORDER BY name')
        else:
            cursor.execute('SELECT * FROM devices ORDER BY name')
        devices = cursor.fetchall()
        conn.close()
        return devices
    
    def get_device(self, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
        device = cursor.fetchone()
        conn.close()
        return device
    
    def update_device(self, device_id, **kwargs):
        conn = self.get_connection()
        cursor = conn.cursor()
        fields = ', '.join([f'{k} = ?' for k in kwargs.keys()])
        values = list(kwargs.values()) + [device_id]
        cursor.execute(f'UPDATE devices SET {fields} WHERE id = ?', values)
        conn.commit()
        conn.close()
    
    def delete_device(self, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE devices SET active = 0 WHERE id = ?', (device_id,))
        conn.commit()
        conn.close()
    
    def add_backup(self, device_id, filename, file_path, file_size, status='success', error_message=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO backups (device_id, filename, file_path, file_size, status, error_message)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (device_id, filename, file_path, file_size, status, error_message))
        conn.commit()
        backup_id = cursor.lastrowid
        conn.close()
        return backup_id
    
    def get_backups(self, device_id=None, limit=100):
        conn = self.get_connection()
        cursor = conn.cursor()
        if device_id:
            cursor.execute('''
                SELECT b.*, d.name as device_name, d.ip_address 
                FROM backups b
                JOIN devices d ON b.device_id = d.id
                WHERE b.device_id = ?
                ORDER BY b.backup_date DESC
                LIMIT ?
            ''', (device_id, limit))
        else:
            cursor.execute('''
                SELECT b.*, d.name as device_name, d.ip_address 
                FROM backups b
                JOIN devices d ON b.device_id = d.id
                ORDER BY b.backup_date DESC
                LIMIT ?
            ''', (limit,))
        backups = cursor.fetchall()
        conn.close()
        return backups
    
    def add_schedule(self, device_id, frequency, time, day_of_week=None, day_of_month=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO schedules (device_id, frequency, time, day_of_week, day_of_month)
            VALUES (?, ?, ?, ?, ?)
        ''', (device_id, frequency, time, day_of_week, day_of_month))
        conn.commit()
        schedule_id = cursor.lastrowid
        conn.close()
        return schedule_id
    
    def get_schedules(self, active_only=True):
        conn = self.get_connection()
        cursor = conn.cursor()
        if active_only:
            cursor.execute('''
                SELECT s.*, d.name as device_name, d.ip_address
                FROM schedules s
                LEFT JOIN devices d ON s.device_id = d.id
                WHERE s.active = 1
                ORDER BY s.id
            ''')
        else:
            cursor.execute('''
                SELECT s.*, d.name as device_name, d.ip_address
                FROM schedules s
                LEFT JOIN devices d ON s.device_id = d.id
                ORDER BY s.id
            ''')
        schedules = cursor.fetchall()
        conn.close()
        return schedules
    
    def update_schedule_last_run(self, schedule_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE schedules SET last_run = CURRENT_TIMESTAMP WHERE id = ?
        ''', (schedule_id,))
        conn.commit()
        conn.close()
    
    def delete_schedule(self, schedule_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE schedules SET active = 0 WHERE id = ?', (schedule_id,))
        conn.commit()
        conn.close()
""")

    # Devido ao limite de tamanho, vou continuar com os outros arquivos...
    # Por favor, me confirme se quer que eu continue ou prefere outro método
    
    print("\n" + "="*50)
    print("✅ Arquivos base criados!")
    print("="*50)
    print("\n📋 PRÓXIMOS PASSOS:")
    print("1. Instale dependências:")
    print("   cd /opt/network-backup")
    print("   python3 -m venv venv")
    print("   source venv/bin/activate")
    print("   pip install -r requirements.txt")
    print("\n2. Execute: python3 app.py")
    print("="*50)

if __name__ == '__main__':
    main()

