from flask import Flask, render_template, request, jsonify, send_file
from database import Database
from backup_manager import BackupManager
from scheduler import BackupScheduler
import os
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua-chave-secreta-aqui'

db = Database()
backup_manager = BackupManager()
scheduler = BackupScheduler()

@app.route('/')
def index():
    """Dashboard simples e objetiva"""
    
    # Buscar dispositivos
    devices = db.get_all_devices()
    total_devices = len([d for d in devices if d['active']])
    
    # Conectar ao banco
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Contar backups por status (últimos 30 dias)
    cursor.execute('''
        SELECT 
            SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful,
            SUM(CASE WHEN status != 'success' THEN 1 ELSE 0 END) as failed
        FROM backups 
        WHERE backup_date >= datetime('now', '-30 days')
    ''')
    stats = cursor.fetchone()
    successful_backups = stats['successful'] if stats['successful'] else 0
    failed_backups = stats['failed'] if stats['failed'] else 0
    
    # Tamanho total
    cursor.execute('SELECT SUM(file_size) as total FROM backups')
    total_size_result = cursor.fetchone()
    total_size = total_size_result['total'] if total_size_result['total'] else 0
    total_size_gb = round(total_size / (1024**3), 2)
    
    # Backups recentes (últimos 20)
    cursor.execute('''
        SELECT 
            b.id,
            b.backup_date,
            b.status,
            b.file_size,
            d.name as device_name,
            d.ip_address,
            d.provedor
        FROM backups b
        JOIN devices d ON b.device_id = d.id
        ORDER BY b.backup_date DESC
        LIMIT 20
    ''')
    recent_backups = cursor.fetchall()
    
    # Total de backups
    cursor.execute('SELECT COUNT(*) as count FROM backups')
    total_backups_result = cursor.fetchone()
    total_backups = total_backups_result['count'] if total_backups_result else 0
    
    conn.close()
    
    # Get list of unique provedores for filtering
    provedores = db.get_provedores()
    
    return render_template('dashboard.html',
        total_devices=total_devices,
        successful_backups=successful_backups,
        failed_backups=failed_backups,
        total_size_gb=total_size_gb,
        recent_backups=recent_backups,
        total_backups=total_backups,
        devices=devices,
        provedores=provedores
    )

@app.route('/devices')
def devices():
    all_devices = db.get_all_devices(active_only=False)
    return render_template('devices.html', devices=all_devices)

@app.route('/devices/add', methods=['POST'])
def add_device():
    try:
        # Obter e validar provedor do formulário
        provedor = request.form.get('provedor', 'Sem_Provedor')
        if provedor:
            provedor = provedor.strip()
        if not provedor:
            provedor = 'Sem_Provedor'
        
        # Sanitize provedor input (basic validation)
        try:
            # Use the database sanitization method
            provedor = db._sanitize_input(provedor, max_length=100)
        except ValueError as e:
            return jsonify({'success': False, 'error': f'Provedor inválido: {str(e)}'}), 422
        
        # Validate required fields
        required_fields = ['name', 'ip_address', 'device_type', 'protocol', 'username', 'password']
        missing_fields = [field for field in required_fields if not request.form.get(field)]
        if missing_fields:
            return jsonify({'success': False, 'error': f'Campos obrigatórios faltando: {", ".join(missing_fields)}'}), 400
        
        # Adicionar dispositivo COM provedor usando SQL direto
        conn = db.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO devices (
                    name, ip_address, device_type, protocol, 
                    username, password, port, enable_password, 
                    backup_command, provedor, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ''', (
                request.form['name'],
                request.form['ip_address'],
                request.form['device_type'],
                request.form['protocol'],
                request.form['username'],
                request.form['password'],
                int(request.form.get('port', 22)),
                request.form.get('enable_password'),
                request.form.get('backup_command'),
                provedor
            ))
            
            device_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return jsonify({'success': True, 'device_id': device_id}), 201
        except sqlite3.IntegrityError as e:
            conn.close()
            if 'UNIQUE constraint' in str(e):
                return jsonify({'success': False, 'error': 'IP address já cadastrado'}), 409
            return jsonify({'success': False, 'error': 'Erro de integridade: ' + str(e)}), 409
    except (ValueError, TypeError) as e:
        return jsonify({'success': False, 'error': f'Dados inválidos: {str(e)}'}), 422
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/devices/<int:device_id>/get')
def get_device_data(device_id):
    device = db.get_device(device_id)
    if device:
        return jsonify(dict(device))
    return jsonify({'error': 'Not found'}), 404

@app.route('/devices/<int:device_id>/update', methods=['POST'])
def update_device(device_id):
    try:
        data = request.get_json()
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Construir query dinamicamente para incluir provedor
        updates = []
        values = []
        
        if 'name' in data:
            updates.append('name = ?')
            values.append(data['name'])
        
        if 'ip_address' in data:
            updates.append('ip_address = ?')
            values.append(data['ip_address'])
        
        if 'protocol' in data:
            updates.append('protocol = ?')
            values.append(data['protocol'])
        
        if 'port' in data:
            updates.append('port = ?')
            values.append(int(data['port']))
        
        if 'provedor' in data:
            provedor = data['provedor'].strip() if data['provedor'] else 'Sem_Provedor'
            updates.append('provedor = ?')
            values.append(provedor)
        
        if not updates:
            return jsonify({'success': False, 'error': 'Nenhum campo para atualizar'}), 400
        
        values.append(device_id)
        query = f"UPDATE devices SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, values)
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'error': 'Dispositivo não encontrado'}), 404
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except (ValueError, TypeError) as e:
        return jsonify({'success': False, 'error': f'Dados inválidos: {str(e)}'}), 422
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/devices/<int:device_id>/delete', methods=['POST'])
def delete_device_permanent(device_id):
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM devices WHERE id = ?', (device_id,))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'error': 'Dispositivo não encontrado'}), 404
        
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 204
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/backup/<int:device_id>', methods=['POST'])
def backup_device(device_id):
    try:
        # Check if device exists
        device = db.get_device(device_id)
        if not device:
            return jsonify({'success': False, 'error': 'Dispositivo não encontrado'}), 404
        
        result = backup_manager.backup_device(device_id)
        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 422
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/backup/all', methods=['POST'])
def backup_all():
    try:
        results = backup_manager.backup_all_devices()
        return jsonify({'success': True, 'results': results}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/backups')
def backups():
    device_id = request.args.get('device_id', type=int)
    all_backups = db.get_backups(device_id=device_id, limit=100)
    return render_template('backups.html', backups=all_backups)

@app.route('/backups/<int:backup_id>/download')
def download_backup(backup_id):
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT filename, file_path FROM backups WHERE id = ?', (backup_id,))
    result = cursor.fetchone()
    conn.close()
    if result and os.path.exists(result['file_path']):
        return send_file(result['file_path'], as_attachment=True, download_name=result['filename'])
    return jsonify({'error': 'Backup não encontrado'}), 404

@app.route('/backups/<int:backup_id>/view')
def view_backup(backup_id):
    content = backup_manager.get_backup_file(backup_id)
    if content:
        return render_template('view_backup.html', content=content, backup_id=backup_id)
    return jsonify({'error': 'Backup não encontrado'}), 404

@app.route('/schedules')
def schedules_page():
    all_schedules = db.get_schedules(active_only=False)
    all_devices = db.get_all_devices()
    return render_template('schedules.html', schedules=all_schedules, devices=all_devices)

@app.route('/schedules/add', methods=['POST'])
def add_schedule():
    try:
        device_id = request.form.get('device_id')
        if device_id == '':
            device_id = None
        else:
            device_id = int(device_id)
        
        frequency = request.form['frequency']
        time = request.form['time']
        day_of_week = request.form.get('day_of_week')
        day_of_month = request.form.get('day_of_month')
        
        if day_of_week:
            day_of_week = int(day_of_week)
        else:
            day_of_week = None
            
        if day_of_month:
            day_of_month = int(day_of_month)
        else:
            day_of_month = None
        
        schedule_id = db.add_schedule(device_id, frequency, time, day_of_week, day_of_month)
        schedule = db.get_schedule(schedule_id)
        scheduler.add_job(schedule)
        return jsonify({'success': True, 'schedule_id': schedule_id}), 201
    except (ValueError, TypeError) as e:
        return jsonify({'success': False, 'error': f'Dados inválidos: {str(e)}'}), 422
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/schedules/<int:schedule_id>/get')
def get_schedule_data(schedule_id):
    schedule = db.get_schedule(schedule_id)
    if schedule:
        return jsonify(dict(schedule))
    return jsonify({'error': 'Not found'}), 404

@app.route('/schedules/<int:schedule_id>/update', methods=['POST'])
def update_schedule(schedule_id):
    try:
        data = request.get_json()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        device_id = data.get('device_id')
        if device_id == '' or device_id == 'null' or device_id is None:
            device_id = None
        else:
            device_id = int(device_id)
        
        cursor.execute('''
            UPDATE schedules 
            SET device_id = ?, frequency = ?, time = ?, 
                day_of_week = ?, day_of_month = ?
            WHERE id = ?
        ''', (device_id, data['frequency'], data['time'], 
              data.get('day_of_week'), data.get('day_of_month'), schedule_id))
        
        conn.commit()
        conn.close()
        
        schedule = db.get_schedule(schedule_id)
        if not schedule:
            return jsonify({'success': False, 'error': 'Agendamento não encontrado'}), 404
        
        scheduler.remove_job(schedule_id)
        scheduler.add_job(schedule)
        
        return jsonify({'success': True}), 200
    except (ValueError, TypeError) as e:
        return jsonify({'success': False, 'error': f'Dados inválidos: {str(e)}'}), 422
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/schedules/<int:schedule_id>', methods=['DELETE'])
def delete_schedule(schedule_id):
    try:
        # Check if schedule exists
        schedule = db.get_schedule(schedule_id)
        if not schedule:
            return jsonify({'success': False, 'error': 'Agendamento não encontrado'}), 404
        
        db.delete_schedule(schedule_id)
        scheduler.remove_job(schedule_id)
        return jsonify({'success': True}), 204
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    devices = db.get_all_devices()
    backups = db.get_backups(limit=1000)
    schedules = db.get_schedules()
    return jsonify({
        'total_devices': len(devices),
        'active_devices': len([d for d in devices if d['active']]),
        'total_backups': len(backups),
        'successful_backups': len([b for b in backups if b['status'] == 'success']),
        'failed_backups': len([b for b in backups if b['status'] == 'failed']),
        'active_schedules': len([s for s in schedules if s['active']]),
        'next_jobs': scheduler.get_jobs()
    })

@app.route('/api/provedores')
def api_provedores():
    provedores = db.get_provedores()
    return jsonify({"provedores": provedores})

@app.route('/api/provedores/all')
def api_provedores_all():
    """Get all provedores with details."""
    provedores = db.get_all_provedores()
    return jsonify({"provedores": [dict(p) for p in provedores]})

@app.route('/api/provedores/add', methods=['POST'])
def api_provedores_add():
    """Add a new provedor."""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        description = data.get('description')
        
        # Handle description - it can be None, empty string, or have a value
        if description:
            description = str(description).strip() or None
        else:
            description = None
        
        if not name:
            return jsonify({'success': False, 'error': 'Nome do provedor é obrigatório'}), 400
        
        # Input validation is now handled in database.add_provedor()
        provedor_id = db.add_provedor(name, description)
        return jsonify({'success': True, 'provedor_id': provedor_id}), 201
    except ValueError as e:
        error_msg = str(e)
        if 'já existe' in error_msg.lower() or 'already exists' in error_msg.lower():
            return jsonify({'success': False, 'error': error_msg}), 409
        return jsonify({'success': False, 'error': error_msg}), 422
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/provedores/<int:provedor_id>/delete', methods=['POST'])
def api_provedores_delete(provedor_id):
    """Delete a provedor by ID."""
    try:
        db.delete_provedor(provedor_id)
        return jsonify({'success': True}), 200
    except ValueError as e:
        error_msg = str(e)
        if 'não encontrado' in error_msg.lower() or 'not found' in error_msg.lower():
            return jsonify({'success': False, 'error': error_msg}), 404
        return jsonify({'success': False, 'error': error_msg}), 422
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/provedores/delete-by-name', methods=['POST'])
def api_provedores_delete_by_name():
    """Delete a provedor by name (for cleanup of malicious entries)."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Dados não fornecidos'}), 400
        
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'success': False, 'error': 'Nome do provedor é obrigatório'}), 400
        
        db.delete_provedor_by_name(name)
        return jsonify({'success': True}), 200
    except ValueError as e:
        error_msg = str(e)
        if 'não encontrado' in error_msg.lower() or 'not found' in error_msg.lower():
            return jsonify({'success': False, 'error': error_msg}), 404
        return jsonify({'success': False, 'error': error_msg}), 422
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
