import sqlite3
from datetime import datetime
import pytz
import os

class Database:
    def __init__(self, db_path='backups.db'):
        self.db_path = db_path
        self.timezone = pytz.timezone('America/Porto_Velho')
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
                backup_date TIMESTAMP,
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
        # Usar horário de Rondônia
        now = datetime.now(self.timezone)
        backup_date = now.strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            INSERT INTO backups (device_id, filename, file_path, file_size, status, error_message, backup_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (device_id, filename, file_path, file_size, status, error_message, backup_date))
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
    
    def get_schedule(self, schedule_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM schedules WHERE id = ?', (schedule_id,))
        schedule = cursor.fetchone()
        conn.close()
        return schedule
    
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
        cursor.execute('DELETE FROM schedules WHERE id = ?', (schedule_id,))
        conn.commit()
        conn.close()

    def get_provedores(self):
        """Return a list of unique registered provedores (provider/cliente) from devices table."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT provedor FROM devices WHERE provedor IS NOT NULL AND provedor != "" ORDER BY provedor')
        rows = cursor.fetchall()
        conn.close()
        return [row['provedor'] for row in rows if row['provedor']]