import sqlite3
from datetime import datetime
import pytz
import os
import re

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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS provedores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        """Update device fields. Only allows updates to specific safe columns."""
        allowed_columns = {'name', 'ip_address', 'device_type', 'protocol', 'port', 
                          'username', 'password', 'enable_password', 'backup_command', 
                          'provedor', 'active'}
        
        safe_kwargs = {k: v for k, v in kwargs.items() if k in allowed_columns}
        
        if not safe_kwargs:
            return
        
        try:
            device_id = int(device_id)
        except (ValueError, TypeError):
            raise ValueError("ID do dispositivo inválido")
        
        conn = self.get_connection()
        cursor = conn.cursor()
        fields = ', '.join([f'{k} = ?' for k in safe_kwargs.keys()])
        values = list(safe_kwargs.values()) + [device_id]
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
                SELECT b.*, d.name as device_name, d.ip_address, d.provedor
                FROM backups b
                JOIN devices d ON b.device_id = d.id
                WHERE b.device_id = ?
                ORDER BY b.backup_date DESC
                LIMIT ?
            ''', (device_id, limit))
        else:
            cursor.execute('''
                SELECT b.*, d.name as device_name, d.ip_address, d.provedor
                FROM backups b
                JOIN devices d ON b.device_id = d.id
                ORDER BY b.backup_date DESC
                LIMIT ?
            ''', (limit,))

        backups = cursor.fetchall()
        conn.close()
        return backups
    
    def get_all_backups(self, device_id=None, limit=None):
        conn = self.get_connection()
        cursor = conn.cursor()

        if device_id:
            cursor.execute('''
                SELECT b.*, d.name as device_name, d.ip_address, d.provedor
                FROM backups b
                JOIN devices d ON b.device_id = d.id
                WHERE b.device_id = ?
                ORDER BY b.backup_date DESC
                LIMIT ?
            ''', (device_id, limit))
        else:
            cursor.execute('''
                SELECT b.*, d.name as device_name, d.ip_address, d.provedor
                FROM backups b
                JOIN devices d ON b.device_id = d.id
                ORDER BY b.backup_date DESC
                LIMIT ?
            ''', (limit,))
        
        backups = cursor.fetchall()
        conn.close()
        return backups

    def get_backups_with_errors(self, limit=5):
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT b.*, d.name AS device_name, d.ip_address, d.provedor
            FROM backups b
            JOIN devices d ON d.id = b.device_id
            WHERE b.status = 'failed'
            ORDER BY b.backup_date DESC
            LIMIT ?
        ''', (limit,))

        results = cursor.fetchall()
        conn.close()
        return results

    def count_backups(self, device_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()

        if device_id:
            cursor.execute("SELECT COUNT(*) FROM backups WHERE device_id = ?", (device_id,))
        else:
            cursor.execute("SELECT COUNT(*) FROM backups")

        total = cursor.fetchone()[0]
        conn.close()
        return total

    def count_backups_by_status(self, status):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM backups WHERE status = ?", (status,))
        total = cursor.fetchone()[0]
        conn.close()
        return total

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
        """Return a list of registered provedores from provedores table, plus any from devices."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Get from provedores table
        cursor.execute('SELECT name FROM provedores ORDER BY name')
        provedores_table = [row['name'] for row in cursor.fetchall()]
        
        # Get unique from devices table (for backward compatibility)
        cursor.execute('SELECT DISTINCT provedor FROM devices WHERE provedor IS NOT NULL AND provedor != "" AND provedor != "Sem_Provedor" ORDER BY provedor')
        devices_provedores = [row['provedor'] for row in cursor.fetchall() if row['provedor']]
        
        # Combine and remove duplicates
        all_provedores = list(set(provedores_table + devices_provedores))
        all_provedores.sort()
        
        conn.close()
        return all_provedores
    
    def _sanitize_input(self, value, max_length=255, allow_special_chars=False):
        """Sanitize and validate user input to prevent SQL injection."""
        if value is None:
            return None
        
        # Convert to string and strip whitespace
        value = str(value).strip()
        
        # Check for SQL injection patterns
        sql_injection_patterns = [
            r"(\bOR\b|\bAND\b)\s*\d+\s*=\s*\d+",  # OR 1=1, AND 1=1
            r"(\bOR\b|\bAND\b)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",  # OR '1'='1'
            r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b)",  # SQL keywords
            r";\s*--",  # SQL comment injection
            r"(\bEXEC\b|\bEXECUTE\b)",  # Command execution
        ]
        
        for pattern in sql_injection_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"Entrada inválida detectada: caracteres perigosos não permitidos")
        
        # Check length
        if len(value) > max_length:
            raise ValueError(f"Entrada muito longa. Máximo de {max_length} caracteres permitidos.")
        
        # Remove or allow special characters based on flag
        if not allow_special_chars:
            # Allow only alphanumeric, spaces, hyphens, underscores, and basic punctuation
            if not re.match(r'^[a-zA-Z0-9\s\-_\.]+$', value):
                # Remove dangerous characters but keep safe ones
                value = re.sub(r'[^\w\s\-_\.]', '', value)
        
        return value
    
    def add_provedor(self, name, description=None):
        """Add a new provedor to the provedores table."""
        # Sanitize inputs
        name = self._sanitize_input(name, max_length=100)
        description = self._sanitize_input(description, max_length=500, allow_special_chars=True) if description else None
        
        if not name:
            raise ValueError("Nome do provedor não pode estar vazio")
        
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO provedores (name, description) VALUES (?, ?)', (name, description))
            conn.commit()
            provedor_id = cursor.lastrowid
            conn.close()
            return provedor_id
        except sqlite3.IntegrityError:
            conn.close()
            raise ValueError(f"Provedor '{name}' já existe")
    
    def get_all_provedores(self):
        """Get all provedores with their details."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM provedores ORDER BY name')
        provedores = cursor.fetchall()
        conn.close()
        return provedores
    
    def delete_provedor(self, provedor_id):
        """Delete a provedor from the provedores table by ID."""
        # Validate provedor_id is an integer
        try:
            provedor_id = int(provedor_id)
        except (ValueError, TypeError):
            raise ValueError("ID do provedor inválido")
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM provedores WHERE id = ?', (provedor_id,))
        conn.commit()
        deleted = cursor.rowcount
        conn.close()
        
        if deleted == 0:
            raise ValueError("Provedor não encontrado")
        return deleted
    
    def delete_provedor_by_name(self, name):
        """Delete a provedor from the provedores table by name (for cleanup of malicious entries).
        Uses parameterized queries so it's safe even with special characters."""
        if not name or not str(name).strip():
            raise ValueError("Nome do provedor não pode estar vazio")
        
        # Basic validation - just check length, but don't sanitize (parameterized query protects us)
        name = str(name).strip()
        if len(name) > 500:  # Reasonable max length
            raise ValueError("Nome muito longo")
        
        conn = self.get_connection()
        cursor = conn.cursor()
        # Use parameterized query - safe even with SQL injection attempts
        cursor.execute('DELETE FROM provedores WHERE name = ?', (name,))
        conn.commit()
        deleted = cursor.rowcount
        conn.close()
        
        if deleted == 0:
            raise ValueError(f"Provedor não encontrado")
        return deleted