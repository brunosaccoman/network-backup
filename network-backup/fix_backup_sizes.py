#!/usr/bin/env python3
"""
Script para corrigir o file_size dos backups existentes.
Lê o tamanho real dos arquivos e atualiza no banco de dados.

Uso: python fix_backup_sizes.py
"""

import os
import sys

# Adicionar o diretório atual ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import db, Backup
from app import app

def fix_backup_sizes():
    """Corrige o file_size de todos os backups."""

    with app.app_context():
        # Buscar todos os backups
        backups = Backup.query.all()

        updated = 0
        errors = 0
        already_correct = 0

        print(f"Verificando {len(backups)} backups...")
        print("-" * 50)

        for backup in backups:
            if not backup.file_path:
                continue

            # Verificar se o arquivo existe
            if os.path.exists(backup.file_path):
                real_size = os.path.getsize(backup.file_path)

                # Atualizar se diferente
                if backup.file_size != real_size:
                    old_size = backup.file_size
                    backup.file_size = real_size
                    updated += 1
                    print(f"ID {backup.id}: {old_size} -> {real_size} bytes")
                else:
                    already_correct += 1
            else:
                errors += 1
                print(f"ID {backup.id}: Arquivo não encontrado: {backup.file_path}")

        # Salvar alterações
        if updated > 0:
            db.session.commit()
            print("-" * 50)
            print(f"✓ {updated} backups atualizados")

        print(f"✓ {already_correct} já estavam corretos")

        if errors > 0:
            print(f"⚠ {errors} arquivos não encontrados")

        # Calcular total
        total_size = db.session.query(db.func.sum(Backup.file_size)).scalar() or 0
        total_gb = round(total_size / (1024**3), 2)
        total_mb = round(total_size / (1024**2), 2)

        print("-" * 50)
        print(f"Espaço total utilizado: {total_mb} MB ({total_gb} GB)")

if __name__ == '__main__':
    fix_backup_sizes()
