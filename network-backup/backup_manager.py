import paramiko
import os
import requests
from datetime import datetime
import pytz
from netmiko import ConnectHandler
from database import Database
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class BackupManager:
    def __init__(self, backup_dir='backups', ssl_verify=True, ssl_ca_bundle=None, retention_count=5, max_workers=50, app=None):
        """
        Inicializa o gerenciador de backups.

        Args:
            backup_dir: Diretório onde os backups serão armazenados
            ssl_verify: Se True, verifica certificados SSL/TLS
            ssl_ca_bundle: Caminho para CA bundle customizado (opcional)
            retention_count: Número de backups a manter por dispositivo (padrão: 5)
            max_workers: Número máximo de backups paralelos (padrão: 50, otimizado para 1000+ devices)
            app: Instância Flask app (necessário para app_context em threads)
        """
        self.backup_dir = backup_dir
        self.db = Database()
        self.timezone = pytz.timezone('America/Porto_Velho')
        self.ssl_verify = ssl_verify
        self.ssl_ca_bundle = ssl_ca_bundle if ssl_ca_bundle else ssl_verify
        self.retention_count = retention_count
        self.max_workers = max_workers
        self.app = app

        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        logger.info(f"BackupManager inicializado (SSL verify: {ssl_verify}, retention: {retention_count} backups, max_workers: {max_workers})")
    

    def _sanitize_folder_name(self, name):
        """Sanitiza o nome para ser usado como nome de pasta"""
        sanitized = re.sub(r'[^\w\-_\.]', '_', str(name))
        sanitized = re.sub(r'_+', '_', sanitized)
        sanitized = sanitized.strip('_')
        return sanitized if sanitized else 'Unnamed'
    

    def _get_device_backup_dir(self, device):
        """Retorna o diretório de backup para um dispositivo específico
        Estrutura: backups/Provedor/Dispositivo/
        """
        # Obter provedor
        provedor = 'Sem_Provedor'
        try:
            if 'provedor' in device and device['provedor']:
                provedor = str(device['provedor']).strip()
                if not provedor:
                    provedor = 'Sem_Provedor'
        except:
            pass
        
        provedor_folder = self._sanitize_folder_name(provedor)
        device_folder = self._sanitize_folder_name(device['name'])
        
        # Criar estrutura: backups/Provedor/Dispositivo/
        device_dir = os.path.join(self.backup_dir, provedor_folder, device_folder)
        
        # Criar as pastas se não existirem
        if not os.path.exists(device_dir):
            os.makedirs(device_dir)
        
        return device_dir
    

    def _backup_device_with_context(self, device_id):
        """Wrapper que garante app_context para threads paralelas."""
        if self.app:
            with self.app.app_context():
                return self.backup_device(device_id)
        else:
            return self.backup_device(device_id)

    def backup_device(self, device_id):
        device = self.db.get_device(device_id)
        if not device:
            return {'success': False, 'error': 'Dispositivo não encontrado'}
        
        try:
            if device['protocol'].lower() in ['http', 'https']:
                result = self._backup_http(device)
            elif device['protocol'].lower() == 'ssh':
                result = self._backup_ssh(device)
            elif device['protocol'].lower() == 'telnet':
                result = self._backup_telnet(device)
            else:
                return {'success': False, 'error': 'Protocolo não suportado'}
            
            # Executar limpeza após backup bem-sucedido
            if result.get('success'):
                self._cleanup_old_backups(device_id)
            
            return result
        except Exception as e:
            error_msg = str(e)
            self.db.add_backup(device_id, '', '', 0, 'failed', error_msg)
            return {'success': False, 'error': error_msg}
    
    def _cleanup_old_backups(self, device_id, keep_count=None):
        """Mantém apenas os N backups mais recentes de um dispositivo"""
        from models import Backup, db

        # Usar o retention_count da configuração se keep_count não for especificado
        if keep_count is None:
            keep_count = self.retention_count

        try:
            # Buscar backups do dispositivo, ordenados do mais recente para o mais antigo
            backups = Backup.query.filter_by(
                device_id=device_id
            ).order_by(Backup.backup_date.desc()).all()

            # Se tiver mais que o limite, deletar os antigos
            if len(backups) > keep_count:
                backups_to_delete = backups[keep_count:]

                for backup in backups_to_delete:
                    # Deletar arquivo físico
                    if backup.file_path and os.path.exists(backup.file_path):
                        try:
                            os.remove(backup.file_path)
                            logger.info(f"Arquivo de backup antigo removido: {backup.file_path}")
                        except Exception as e:
                            logger.error(f"Erro ao deletar arquivo: {e}")

                    # Deletar registro do banco
                    db.session.delete(backup)

                db.session.commit()
                logger.info(f"Limpeza concluída: {len(backups_to_delete)} backups antigos removidos")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro na limpeza: {e}")
    
    def _backup_http(self, device):
        try:
            if device['device_type'] == 'mimosa':
                return self._backup_mimosa_http(device)
            elif device['device_type'] == 'intelbras_radio':
                return self._backup_intelbras_http(device)
            else:
                return {'success': False, 'error': f"Tipo {device['device_type']} não suporta HTTP/HTTPS"}
        except Exception as e:
            raise Exception(f"Erro HTTP: {str(e)}")
    
    def _backup_mimosa_http(self, device):
        protocol = device['protocol'].lower()
        port = device['port']
        base_url = f"{protocol}://{device['ip_address']}:{port}"
        session = requests.Session()

        try:
            login_url = f"{base_url}/login"
            login_data = {'password': device['password']}
            response = session.post(login_url, data=login_data, verify=self.ssl_ca_bundle, timeout=30)

            if response.status_code == 200 or 'Set-Cookie' in response.headers:
                config_endpoints = ['/api/v1/config', '/cgi-bin/export_config', '/api/config/export', '/backup.cgi', '/cgi-bin/config/export']

                for endpoint in config_endpoints:
                    try:
                        config_url = f"{base_url}{endpoint}"
                        config_response = session.get(config_url, verify=self.ssl_ca_bundle, timeout=30)
                        if config_response.status_code == 200 and len(config_response.content) > 100:
                            return self._save_backup(device, config_response.text)
                    except Exception as e:
                        logger.debug(f"Endpoint {endpoint} falhou: {e}")
                        continue

                config_response = session.get(f"{base_url}/config", verify=self.ssl_ca_bundle, timeout=30)
                if config_response.status_code == 200:
                    return self._save_backup(device, config_response.text)

                raise Exception("Não foi possível baixar a configuração após login")
            else:
                raise Exception(f"Falha no login: HTTP {response.status_code}")
        except Exception as e:
            raise Exception(f"Erro Mimosa: {str(e)}")
        finally:
            session.close()
    
    def _backup_intelbras_http(self, device):
        protocol = device['protocol'].lower()
        port = device['port']
        base_url = f"{protocol}://{device['ip_address']}:{port}"
        session = requests.Session()

        try:
            auth = (device['username'], device['password'])
            backup_urls = [
                f"{base_url}/cgi-bin/luci/admin/config/backup",
                f"{base_url}/backup.cgi",
                f"{base_url}/cgi-bin/backup",
                f"{base_url}/backup",
                f"{base_url}/api/backup",
                f"{base_url}/cgi-bin/export"
            ]

            for url in backup_urls:
                try:
                    response = session.get(url, auth=auth, verify=self.ssl_ca_bundle, timeout=30)
                    if response.status_code == 200 and len(response.content) > 100:
                        return self._save_backup(device, response.text)
                except Exception as e:
                    logger.debug(f"URL {url} falhou: {e}")
                    continue

            raise Exception("Nenhum endpoint de backup funcionou.")
        except Exception as e:
            raise Exception(f"Erro Intelbras: {str(e)}")
        finally:
            session.close()
    
    def _backup_ssh(self, device):
        device_type_map = {
            'ubiquiti_airos': 'ubiquiti_edgerouter',
            'intelbras_radio': 'linux',
            'mimosa': 'linux',
            'datacom': 'cisco_ios',
            'datacom_dmos': 'cisco_ios'
        }

        netmiko_type = device_type_map.get(device['device_type'], device['device_type'])

        device_config = {
            'device_type': netmiko_type,
            'host': device['ip_address'],
            'username': device['username'],
            'password': device['password'],
            'port': device['port'],
            'timeout': 30,
        }

        if device['enable_password']:
            device_config['secret'] = device['enable_password']

        try:
            logger.info(f"Iniciando backup SSH para {device['name']} ({device['ip_address']})")
            connection = ConnectHandler(**device_config)
            logger.info(f"Conexão estabelecida com sucesso")

            if device['enable_password'] and netmiko_type not in ['linux', 'ubiquiti_edgerouter']:
                connection.enable()

            backup_command = device['backup_command'] if device['backup_command'] else self._get_default_command(device['device_type'])
            logger.info(f"Executando comando: {backup_command}")

            # Mikrotik /export needs timing-based approach instead of expect-based
            if device['device_type'] == 'mikrotik_routeros' and 'export' in backup_command.lower():
                output = connection.send_command_timing(backup_command, delay_factor=4, max_loops=500)
                logger.info(f"Usou send_command_timing para Mikrotik")
            else:
                output = connection.send_command(backup_command, read_timeout=60)
            logger.info(f"Comando executado. Output recebido: {len(output)} caracteres, {len(output.splitlines())} linhas")

            if len(output) > 0:
                logger.info(f"Primeiras 100 caracteres do output: {output[:100]}")
            else:
                logger.warning(f"OUTPUT VAZIO recebido do comando {backup_command}")

            connection.disconnect()
            logger.info(f"Conexão SSH encerrada")

            return self._save_backup(device, output)
        except Exception as e:
            logger.error(f"Erro no backup SSH: {str(e)}")
            raise Exception(f"Erro SSH: {str(e)}")
    
    def _backup_telnet(self, device):
        device_type_map = {
            'ubiquiti_airos': 'ubiquiti_edgerouter',
            'intelbras_radio': 'linux',
            'mimosa': 'linux',
            'datacom': 'cisco_ios',
            'datacom_dmos': 'cisco_ios'
        }

        netmiko_type = device_type_map.get(device['device_type'], device['device_type'])
        
        device_config = {
            'device_type': netmiko_type + '_telnet',
            'host': device['ip_address'],
            'username': device['username'],
            'password': device['password'],
            'port': device['port'],
            'timeout': 30,
        }
        
        if device['enable_password']:
            device_config['secret'] = device['enable_password']
        
        try:
            connection = ConnectHandler(**device_config)
            if device['enable_password']:
                connection.enable()
            
            backup_command = device['backup_command'] if device['backup_command'] else self._get_default_command(device['device_type'])
            output = connection.send_command(backup_command, read_timeout=60)
            connection.disconnect()
            
            return self._save_backup(device, output)
        except Exception as e:
            raise Exception(f"Erro Telnet: {str(e)}")
    
    def _get_default_command(self, device_type):
        commands = {
            'cisco_ios': 'show running-config',
            'cisco_nxos': 'show running-config',
            'cisco_asa': 'show running-config',
            'cisco_xr': 'show running-config',
            'datacom': 'show running-config',
            'datacom_dmos': 'show running-config',
            'juniper_junos': 'show configuration',
            'arista_eos': 'show running-config',
            'hp_comware': 'display current-configuration',
            'huawei': 'display current-configuration',
            'huawei_vrpv8': 'display current-configuration',
            'mikrotik_routeros': '/export compact',
            'paloalto_panos': 'show config running',
            'ubiquiti_airos': 'cat /tmp/system.cfg',
            'ubiquiti_edge': 'show configuration',
            'intelbras_radio': 'cat /etc/config/*',
            'mimosa': 'cat /etc/persistent/mimosa.cfg',
        }
        return commands.get(device_type, 'show running-config')
    
    def _save_backup(self, device, config_data):
        logger.info(f"_save_backup chamado para {device['name']}")
        logger.info(f"Tamanho dos dados recebidos: {len(config_data)} caracteres")

        now = datetime.now(self.timezone)
        timestamp = now.strftime('%Y%m%d_%H%M%S')

        # Usar nova estrutura com provedor
        device_dir = self._get_device_backup_dir(device)
        logger.info(f"Diretório de backup: {device_dir}")

        # Nome do arquivo mais simples (sem nome do dispositivo, só IP e timestamp)
        filename = f"{device['ip_address']}_{timestamp}.txt"
        file_path = os.path.join(device_dir, filename)
        logger.info(f"Caminho completo do arquivo: {file_path}")

        logger.info(f"Escrevendo {len(config_data)} caracteres no arquivo...")
        with open(file_path, 'w', encoding='utf-8') as f:
            bytes_written = f.write(config_data)
            logger.info(f"Bytes escritos no arquivo: {bytes_written}")

        file_size = os.path.getsize(file_path)
        logger.info(f"Tamanho do arquivo após salvar: {file_size} bytes")

        if file_size == 0:
            logger.error(f"ERRO: Arquivo salvo com 0 bytes! config_data tinha {len(config_data)} caracteres")
        elif file_size != len(config_data):
            logger.warning(f"AVISO: Tamanho do arquivo ({file_size}) diferente do tamanho dos dados ({len(config_data)})")

        self.db.add_backup(device['id'], filename, file_path, file_size, 'success')
        logger.info(f"Backup registrado no banco de dados")

        return {'success': True, 'filename': filename, 'size': file_size, 'path': file_path}
    
    def backup_all_devices(self):
        """Executa backup sequencial de todos os dispositivos ativos (modo legado)."""
        devices = self.db.get_all_devices(active_only=True)
        results = []
        for device in devices:
            result = self.backup_device(device['id'])
            results.append({'device': device['name'], 'ip': device['ip_address'], 'result': result})
        return results

    def backup_all_devices_parallel(self):
        """Executa backup paralelo de todos os dispositivos ativos."""
        devices = self.db.get_all_devices(active_only=True)

        if not devices:
            logger.info("Nenhum dispositivo ativo encontrado")
            return []

        total_devices = len(devices)
        logger.info(f"Iniciando backup paralelo de {total_devices} dispositivos (workers: {self.max_workers})")

        results = []

        # Usar ThreadPoolExecutor para executar backups em paralelo
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submeter todos os jobs (usa wrapper com app_context)
            future_to_device = {
                executor.submit(self._backup_device_with_context, device['id']): device
                for device in devices
            }

            # Processar resultados conforme completam
            completed = 0
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                completed += 1

                try:
                    result = future.result()
                    results.append({
                        'device': device['name'],
                        'ip': device['ip_address'],
                        'result': result
                    })

                    status = "✓ sucesso" if result.get('success') else f"✗ falha: {result.get('error', 'erro desconhecido')}"
                    logger.info(f"[{completed}/{total_devices}] {device['name']} ({device['ip_address']}): {status}")

                except Exception as e:
                    error_msg = str(e)
                    logger.error(f"[{completed}/{total_devices}] {device['name']} ({device['ip_address']}): Exceção - {error_msg}")
                    results.append({
                        'device': device['name'],
                        'ip': device['ip_address'],
                        'result': {'success': False, 'error': error_msg}
                    })

        # Estatísticas finais
        success_count = sum(1 for r in results if r['result'].get('success'))
        failed_count = total_devices - success_count
        logger.info(f"Backup paralelo concluído: {success_count} sucessos, {failed_count} falhas de {total_devices} dispositivos")

        return results
    
    def get_backup_file(self, backup_id):
        """Retorna o conteúdo de um arquivo de backup pelo ID."""
        from models import Backup

        backup = Backup.query.get(backup_id)

        if backup and backup.file_path and os.path.exists(backup.file_path):
            with open(backup.file_path, 'r', encoding='utf-8') as f:
                return f.read()
        return None
