#!/usr/bin/env python3
"""
Script para verificar o conteúdo dos backups de dispositivos Mimosa.
Mostra os últimos backups e seu conteúdo para diagnóstico.

Uso:
    python verificar_backup_mimosa.py
"""

import os
import sys

# Adicionar o diretório ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import Backup, Device

def verificar_backups_mimosa():
    with app.app_context():
        # Buscar dispositivos Mimosa
        mimosa_devices = Device.query.filter(Device.device_type.like('%mimosa%')).all()

        if not mimosa_devices:
            print("Nenhum dispositivo Mimosa encontrado no banco de dados.")
            return

        print(f"Encontrados {len(mimosa_devices)} dispositivos Mimosa:\n")

        for dev in mimosa_devices:
            print(f"{'='*60}")
            print(f"Dispositivo: {dev.name}")
            print(f"IP: {dev.ip_address}")
            print(f"Tipo: {dev.device_type}")
            print(f"Protocolo: {dev.protocol}")
            print(f"Porta: {dev.port}")
            print(f"Ativo: {dev.active}")

            # Buscar último backup
            backup = Backup.query.filter_by(device_id=dev.id).order_by(Backup.backup_date.desc()).first()

            if backup:
                print(f"\nÚltimo backup:")
                print(f"  Data: {backup.backup_date}")
                print(f"  Status: {backup.status}")
                print(f"  Arquivo: {backup.file_path}")
                print(f"  Tamanho: {backup.file_size} bytes ({backup.file_size/1024:.2f} KB)")

                if backup.error_message:
                    print(f"  Erro: {backup.error_message}")

                # Ler conteúdo do arquivo
                if backup.file_path and os.path.exists(backup.file_path):
                    try:
                        with open(backup.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        print(f"\nConteúdo do backup ({len(content)} caracteres):")
                        print("-" * 40)

                        # Mostrar primeiros 1000 caracteres
                        if len(content) > 1000:
                            print(content[:1000])
                            print(f"\n... (mais {len(content) - 1000} caracteres)")
                        else:
                            print(content)

                        print("-" * 40)

                        # Análise do conteúdo
                        print("\nAnálise do conteúdo:")
                        if '<!DOCTYPE' in content or '<html' in content.lower():
                            print("  ⚠️  PROBLEMA: Conteúdo parece ser HTML (página web)")
                            if 'login' in content.lower() or 'password' in content.lower():
                                print("  ⚠️  Provavelmente é página de login - autenticação falhou!")
                        elif 'mimosa' in content.lower() or 'wireless' in content.lower():
                            print("  ✓ Conteúdo parece ser configuração válida")
                        elif len(content) < 200:
                            print("  ⚠️  PROBLEMA: Conteúdo muito pequeno")
                        else:
                            print("  ? Conteúdo não identificado")

                    except Exception as e:
                        print(f"\nErro ao ler arquivo: {e}")
                else:
                    print(f"\n  Arquivo não encontrado: {backup.file_path}")
            else:
                print("\nNenhum backup encontrado para este dispositivo.")

            print()

if __name__ == '__main__':
    verificar_backups_mimosa()
