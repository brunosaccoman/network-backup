#!/usr/bin/env python3
"""
Script de Limpeza de Backups Antigos
Mantém apenas os 5 backups mais recentes de cada dispositivo
"""

import sqlite3
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def cleanup_old_backups(db_path='backups.db', keep_count=5):
    """Mantém apenas os N backups mais recentes de cada dispositivo"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Buscar todos os dispositivos
    cursor.execute('SELECT DISTINCT device_id FROM backups')
    devices = cursor.fetchall()
    
    total_deleted = 0
    
    for device_row in devices:
        device_id = device_row['device_id']
        
        # Buscar backups do dispositivo, ordenados do mais recente para o mais antigo
        cursor.execute('''
            SELECT id, file_path, backup_date 
            FROM backups 
            WHERE device_id = ? 
            ORDER BY backup_date DESC
        ''', (device_id,))
        
        backups = cursor.fetchall()
        
        # Se tiver mais que o limite, deletar os antigos
        if len(backups) > keep_count:
            backups_to_delete = backups[keep_count:]
            
            for backup in backups_to_delete:
                # Deletar arquivo físico
                if os.path.exists(backup['file_path']):
                    try:
                        os.remove(backup['file_path'])
                        logger.info(f"Arquivo deletado: {backup['file_path']}")
                    except Exception as e:
                        logger.error(f"Erro ao deletar arquivo {backup['file_path']}: {e}")
                
                # Deletar registro do banco
                cursor.execute('DELETE FROM backups WHERE id = ?', (backup['id'],))
                total_deleted += 1
                logger.info(f"Backup ID {backup['id']} removido do banco")
    
    conn.commit()
    conn.close()
    
    logger.info(f"Limpeza concluída: {total_deleted} backups antigos removidos")
    return total_deleted

if __name__ == '__main__':
    cleanup_old_backups(keep_count=5)
