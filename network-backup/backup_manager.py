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
            if device['device_type'] in ['mimosa', 'mimosa_c5c', 'mimosa_b5c', 'mimosa_b5', 'mimosa_a5c']:
                return self._backup_mimosa_http(device)
            elif device['device_type'] == 'intelbras_radio':
                return self._backup_intelbras_http(device)
            else:
                return {'success': False, 'error': f"Tipo {device['device_type']} não suporta HTTP/HTTPS"}
        except Exception as e:
            raise Exception(f"Erro HTTP: {str(e)}")
    
    def _backup_mimosa_http(self, device):
        """
        Backup de dispositivos Mimosa (C5c, B5c, B5, A5c, etc.) via HTTP/HTTPS.

        Os equipamentos Mimosa usam uma interface web com API REST em /core/api/calls/.
        O arquivo de configuração é o mimosa.conf.

        Fluxo:
        1. Autenticação via API ou formulário de login
        2. Download do arquivo de configuração mimosa.conf
        """
        protocol = device['protocol'].lower()
        port = device['port']
        base_url = f"{protocol}://{device['ip_address']}:{port}"
        session = requests.Session()

        # Configurar retries automáticos para dispositivos lentos
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        retry_strategy = Retry(
            total=3,  # Número total de tentativas
            backoff_factor=2,  # Espera 2s, 4s, 8s entre tentativas
            status_forcelist=[500, 502, 503, 504],  # Retry em erros de servidor
            allowed_methods=["GET", "POST"]  # Permitir retry em GET e POST
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Desabilitar avisos de SSL para certificados auto-assinados
        if not self.ssl_verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            logger.info(f"Iniciando backup Mimosa para {device['name']} ({device['ip_address']})")

            # Método 1: Autenticação via API REST com credenciais na URL
            # Formato: https://user:pass@ip/endpoint
            auth = (device['username'], device['password'])

            logged_in = False

            # Método 2: Tentar login via formulário web
            # IMPORTANTE: /login.php é o endpoint correto para Mimosa C5c e deve ser testado primeiro
            login_attempts = [
                # Formato correto para Mimosa C5c (retorna JSON com role quando sucesso)
                ('/login.php', {'username': device['username'], 'password': device['password']}),
                ('/login.php', {'password': device['password']}),
                # Formatos alternativos para outros modelos
                ('/?q=index.login', {'username': device['username'], 'password': device['password']}),
                ('/?q=index.login', {'password': device['password']}),
                ('/api/login', {'username': device['username'], 'password': device['password']}),
                ('/login', {'username': device['username'], 'password': device['password']}),
            ]

            # Headers para simular navegador (alguns firmwares Mimosa exigem)
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Origin': base_url,
                'Referer': f'{base_url}/',
            })

            for login_endpoint, login_data in login_attempts:
                try:
                    login_url = f"{base_url}{login_endpoint}"
                    logger.info(f"Tentando login em: {login_url}")

                    response = session.post(
                        login_url,
                        data=login_data,
                        verify=self.ssl_ca_bundle,
                        timeout=(30, 60),  # 30s conectar, 60s ler (para Mimosas lentas)
                        allow_redirects=True
                    )

                    content_type = response.headers.get('Content-Type', '').lower()
                    logger.info(f"Resposta login {login_endpoint}: HTTP {response.status_code}, Content-Type: {content_type}, Cookies: {len(session.cookies)}")

                    # Verificar se login funcionou
                    # Para /login.php, sucesso retorna JSON com "role" (não HTML)
                    if response.status_code == 200:
                        if 'application/json' in content_type:
                            # Login bem-sucedido retorna JSON com dados da sessão
                            try:
                                json_response = response.json()
                                if 'role' in json_response or 'version' in json_response or 'success' in json_response:
                                    logged_in = True
                                    logger.info(f"Login bem-sucedido via {login_endpoint} (JSON response: {list(json_response.keys())})")
                                    break
                            except:
                                pass
                        elif len(response.content) < 1000 and 'html' not in content_type:
                            # Resposta pequena não-HTML pode indicar sucesso
                            logged_in = True
                            logger.info(f"Login possivelmente bem-sucedido via {login_endpoint}")
                            break

                        # Verificar se tem cookies de sessão (indica login bem-sucedido)
                        # Para /?q=index.login que retorna HTML
                        if session.cookies and len(session.cookies) > 0:
                            # Verificar se não é página de erro
                            response_text = response.text.lower() if response.text else ''
                            error_indicators = ['invalid', 'failed', 'error', 'incorrect', 'denied']
                            has_error = any(err in response_text for err in error_indicators)

                            if not has_error:
                                logged_in = True
                                logger.info(f"Login bem-sucedido via {login_endpoint} (cookie de sessão: {list(session.cookies.keys())})")
                                break
                            else:
                                logger.debug(f"Login {login_endpoint} retornou página com erro")

                except Exception as e:
                    logger.debug(f"Login endpoint {login_endpoint} falhou: {e}")
                    continue

            # Se não conseguiu fazer login via formulário, continua mesmo assim
            if not logged_in:
                logger.info("Login não confirmado, tentando download com Basic Auth...")

            # Endpoint principal de backup Mimosa (DESCOBERTO!)
            # Este endpoint faz download direto do arquivo mimosa.conf
            primary_endpoint = '/?q=preferences.configure&mimosa_action=download'

            try:
                config_url = f"{base_url}{primary_endpoint}"
                logger.info(f"Tentando download de backup: {config_url}")

                # Tenta com a sessão autenticada
                # Timeout: (connect, read) - aumentado para Mimosas lentas
                config_response = session.get(
                    config_url,
                    verify=self.ssl_ca_bundle,
                    timeout=(30, 180),  # 30s para conectar, 180s para ler (3 min)
                    stream=False  # Garante download completo
                )

                content_type = config_response.headers.get('Content-Type', '')
                content_disposition = config_response.headers.get('Content-Disposition', '')

                logger.info(f"Resposta: HTTP {config_response.status_code}, Content-Type: {content_type}, Disposition: {content_disposition}, Size: {len(config_response.content)} bytes")

                if config_response.status_code == 200 and len(config_response.content) > 50:
                    content = config_response.content.decode('utf-8', errors='ignore')

                    # Verificar se é HTML (página de erro) ou configuração
                    is_html_page = '<!DOCTYPE' in content[:100] or '<html' in content[:100].lower()

                    # Se tem Content-Disposition com attachment, é o arquivo de backup
                    is_attachment = 'attachment' in content_disposition or 'mimosa' in content_disposition.lower()

                    if is_attachment:
                        logger.info(f"Configuração obtida via download direto ({len(content)} bytes)")
                        return self._save_backup(device, content)
                    elif not is_html_page:
                        # Não é HTML, provavelmente é o arquivo de configuração
                        logger.info(f"Configuração obtida (não-HTML) ({len(content)} bytes)")
                        return self._save_backup(device, content)
                    else:
                        logger.warning(f"Endpoint retornou HTML em vez do arquivo de backup")

            except Exception as e:
                logger.error(f"Erro no endpoint principal: {e}")

            # Endpoints alternativos caso o principal falhe
            config_endpoints = [
                '/?q=backup.download',
                '/backup/download',
                '/config/backup',
                '/api/backup',
                '/core/api/config/backup',
                '/core/api/calls/Backup.php',
                '/cgi-bin/backup.cgi',
                '/backup.cgi',
                '/download/mimosa.conf',
            ]

            for endpoint in config_endpoints:
                try:
                    config_url = f"{base_url}{endpoint}"
                    logger.debug(f"Tentando endpoint alternativo: {config_url}")

                    config_response = session.get(
                        config_url,
                        verify=self.ssl_ca_bundle,
                        timeout=(30, 180),  # 30s para conectar, 180s para ler
                        auth=auth if not logged_in else None
                    )

                    if config_response.status_code == 200 and len(config_response.content) > 100:
                        content = config_response.content.decode('utf-8', errors='ignore')
                        content_disposition = config_response.headers.get('Content-Disposition', '')

                        is_html = '<!DOCTYPE' in content[:100] or '<html' in content[:100].lower()
                        is_attachment = 'attachment' in content_disposition

                        if is_attachment or not is_html:
                            logger.info(f"Configuração obtida via {endpoint} ({len(content)} bytes)")
                            return self._save_backup(device, content)

                except Exception as e:
                    logger.debug(f"Endpoint {endpoint} falhou: {e}")
                    continue

            # Método 3: Tentar via API REST com parâmetros de autenticação na URL
            # Formato documentado: https://ip/core/api/service/endpoint?username=X&password=Y
            api_endpoints = [
                f"/core/api/service/backup?username={device['username']}&password={device['password']}",
                f"/core/api/service/config?username={device['username']}&password={device['password']}",
            ]

            for endpoint in api_endpoints:
                try:
                    api_url = f"{base_url}{endpoint}"
                    response = session.get(api_url, verify=self.ssl_ca_bundle, timeout=(30, 180))

                    if response.status_code == 200 and len(response.content) > 100:
                        content = response.text if response.text else response.content.decode('utf-8', errors='ignore')
                        logger.info(f"Configuração obtida via API REST ({len(content)} bytes)")
                        return self._save_backup(device, content)

                except Exception as e:
                    logger.debug(f"API endpoint falhou: {e}")
                    continue

            raise Exception("Não foi possível baixar a configuração. Verifique se HTTPS está habilitado no dispositivo e se as credenciais estão corretas.")

        except Exception as e:
            raise Exception(f"Erro Mimosa: {str(e)}")
        finally:
            session.close()
    
    def _backup_intelbras_http(self, device):
        """
        Backup de rádios Intelbras (WOM 5A, APC 5A, WOM 5A MiMo, etc) via HTTP.

        Suporta múltiplos métodos de autenticação:
        - Modelos novos: Basic Auth + endpoints /System/configBackup ou /cgi-bin/
        - Modelos antigos: Login via formNumber=201 + formNumber=100
        """
        protocol = device['protocol'].lower()
        port = device['port']
        base_url = f"{protocol}://{device['ip_address']}:{port}"
        session = requests.Session()

        # Desabilitar avisos de SSL
        if not self.ssl_verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            logger.info(f"Iniciando backup Intelbras HTTP para {device['name']} ({device['ip_address']})")

            # ================================================================
            # MÉTODO 1: LuCI POST (APC 5A-90 v2.0, modelos novos com OpenWrt/LuCI)
            # ================================================================
            logger.info("Tentando método LuCI POST (APC 5A-90 v2.0 e similares)...")

            basic_auth = (device['username'], device['password'])

            # Headers para LuCI
            luci_headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/octet-stream, */*',
            }

            # Endpoints LuCI que precisam de POST
            luci_post_endpoints = [
                ('/cgi-bin/luci/admin/system/flashops/backup', {}),
                ('/cgi-bin/luci/admin/system/backup', {'backup': '1'}),
                ('/cgi-bin/luci/admin/system/flashops', {'backup': 'backup'}),
                ('/cgi-bin/luci/;stok=/admin/system/flashops/backup', {}),
            ]

            for endpoint, post_data in luci_post_endpoints:
                try:
                    url = f"{base_url}{endpoint}"
                    logger.debug(f"Tentando POST em {url}")

                    response = session.post(
                        url,
                        auth=basic_auth,
                        data=post_data,
                        headers=luci_headers,
                        verify=self.ssl_ca_bundle,
                        timeout=(30, 120),
                        allow_redirects=True
                    )

                    content_disposition = response.headers.get('Content-Disposition', '')
                    content_type = response.headers.get('Content-Type', '')

                    logger.debug(f"POST {endpoint}: status={response.status_code}, "
                               f"type={content_type}, size={len(response.content)}")

                    if response.status_code == 200 and len(response.content) > 100:
                        # Verificar se é arquivo de backup
                        if ('attachment' in content_disposition or
                            'octet-stream' in content_type or
                            'application/x-tar' in content_type or
                            'application/gzip' in content_type):

                            # Determinar extensão
                            if '.tar.gz' in content_disposition or 'gzip' in content_type:
                                ext = '.tar.gz'
                            elif '.fmw' in content_disposition:
                                ext = '.fmw'
                            else:
                                ext = '.cfg'

                            logger.info(f"Backup Intelbras (LuCI POST) obtido via {endpoint}: {len(response.content)} bytes")
                            return self._save_backup_binary(device, response.content, ext)

                except Exception as e:
                    logger.debug(f"LuCI POST endpoint {endpoint} falhou: {e}")
                    continue

            # ================================================================
            # MÉTODO 2: Basic Auth GET (outros modelos novos)
            # ================================================================
            logger.info("Tentando método Basic Auth GET...")

            # Endpoints para GET
            get_endpoints = [
                '/System/configBackup',
                '/cgi-bin/luci/admin/system/backup',
                '/cgi-bin/backup',
                '/backup',
                '/cgi-bin/luci/admin/system/flashops/backup',
            ]

            for endpoint in get_endpoints:
                try:
                    url = f"{base_url}{endpoint}"
                    logger.debug(f"Tentando GET em {url}")

                    response = session.get(
                        url,
                        auth=basic_auth,
                        verify=self.ssl_ca_bundle,
                        timeout=(30, 120),
                        allow_redirects=True
                    )

                    content_disposition = response.headers.get('Content-Disposition', '')
                    content_type = response.headers.get('Content-Type', '')

                    logger.debug(f"GET {endpoint}: status={response.status_code}, "
                               f"type={content_type}, size={len(response.content)}")

                    if response.status_code == 200 and len(response.content) > 100:
                        # Verificar se é arquivo de backup
                        if ('attachment' in content_disposition or
                            'octet-stream' in content_type or
                            'application/x-tar' in content_type or
                            'application/gzip' in content_type):

                            # Determinar extensão
                            if '.tar.gz' in content_disposition or 'gzip' in content_type:
                                ext = '.tar.gz'
                            elif '.fmw' in content_disposition:
                                ext = '.fmw'
                            else:
                                ext = '.cfg'

                            logger.info(f"Backup Intelbras (Basic Auth GET) obtido via {endpoint}: {len(response.content)} bytes")
                            return self._save_backup_binary(device, response.content, ext)

                        # Pode ser texto/config
                        content = response.content.decode('utf-8', errors='ignore')
                        if 'password' not in content.lower()[:500] and len(content) > 100:
                            logger.info(f"Backup Intelbras (Basic Auth GET) obtido via {endpoint}: {len(content)} chars")
                            return self._save_backup(device, content)

                except Exception as e:
                    logger.debug(f"GET endpoint {endpoint} falhou: {e}")
                    continue

            # ================================================================
            # MÉTODO 2: Form Login (modelos antigos - WOM 5A original)
            # ================================================================
            logger.info("Tentando método Form Login (modelos antigos)...")

            # Passo 1: Login via formulário
            login_url = f"{base_url}/cgi-bin/firmware.cgi"
            login_data = {
                'formNumber': '201',
                'user': device['username'],
                'password': device['password'],
            }

            logger.debug(f"Fazendo login em {login_url}")
            login_response = session.post(
                login_url,
                data=login_data,
                verify=self.ssl_ca_bundle,
                timeout=(30, 60)
            )

            logger.debug(f"Login response: {login_response.status_code}, Cookies: {len(session.cookies)}")

            # Passo 2: Download do backup via formNumber=100
            backup_url = f"{base_url}/cgi-bin/firmware.cgi?formNumber=100"
            logger.debug(f"Baixando backup de {backup_url}")

            backup_response = session.get(
                backup_url,
                verify=self.ssl_ca_bundle,
                timeout=(30, 120)
            )

            content_disposition = backup_response.headers.get('Content-Disposition', '')
            content_type = backup_response.headers.get('Content-Type', '')

            logger.debug(f"Backup response: {backup_response.status_code}, "
                       f"Content-Type: {content_type}, "
                       f"Disposition: {content_disposition}, "
                       f"Size: {len(backup_response.content)} bytes")

            # Verificar se é o arquivo de backup
            if backup_response.status_code == 200:
                if 'attachment' in content_disposition or 'octet-stream' in content_type:
                    logger.info(f"Backup Intelbras (Form) obtido: {len(backup_response.content)} bytes")
                    return self._save_backup_binary(device, backup_response.content, '.fmw')
                elif len(backup_response.content) > 100:
                    content = backup_response.content.decode('utf-8', errors='ignore')
                    if 'password' not in content.lower()[:500]:
                        return self._save_backup(device, content)

            # ================================================================
            # MÉTODO 3: Endpoints alternativos com sessão
            # ================================================================
            logger.info("Tentando endpoints alternativos com sessão...")

            alternative_endpoints = [
                '/cgi-bin/backup.cgi',
                '/backup.cgi',
                '/cgi-bin/export',
                '/cgi-bin/config.cgi?action=backup',
            ]

            for endpoint in alternative_endpoints:
                try:
                    url = f"{base_url}{endpoint}"
                    response = session.get(url, verify=self.ssl_ca_bundle, timeout=30)
                    if response.status_code == 200 and len(response.content) > 100:
                        content_disp = response.headers.get('Content-Disposition', '')
                        if 'attachment' in content_disp or 'octet-stream' in response.headers.get('Content-Type', ''):
                            return self._save_backup_binary(device, response.content, '.fmw')
                        else:
                            content = response.content.decode('utf-8', errors='ignore')
                            if 'password' not in content.lower()[:500]:
                                return self._save_backup(device, content)
                except Exception as e:
                    logger.debug(f"Endpoint {endpoint} falhou: {e}")
                    continue

            raise Exception("Não foi possível baixar o backup. Verifique as credenciais e se HTTP está habilitado. "
                          "Para modelos novos, certifique-se que o usuário tem permissão de backup.")

        except Exception as e:
            raise Exception(f"Erro Intelbras HTTP: {str(e)}")
        finally:
            session.close()
    
    def _backup_ssh(self, device):
        device_type_map = {
            'ubiquiti_airos': 'ubiquiti_edgerouter',
            'intelbras_radio': 'linux',
            'mimosa': 'linux',
            'mimosa_c5c': 'linux',
            'mimosa_b5c': 'linux',
            'mimosa_b5': 'linux',
            'mimosa_a5c': 'linux',
            'datacom': 'cisco_ios',
            'datacom_dmos': 'cisco_ios'
        }

        netmiko_type = device_type_map.get(device['device_type'], device['device_type'])

        # Timeout maior para Intelbras (radios podem ser lentos)
        connect_timeout = 60 if device['device_type'] == 'intelbras_radio' else 30

        device_config = {
            'device_type': netmiko_type,
            'host': device['ip_address'],
            'username': device['username'],
            'password': device['password'],
            'port': device['port'],
            'timeout': connect_timeout,
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

            # Intelbras radio needs multiple commands to collect full info
            if device['device_type'] == 'intelbras_radio':
                logger.info("Coletando backup Intelbras com múltiplos comandos")
                output = "=== INTELBRAS RADIO BACKUP ===\n\n"

                intelbras_commands = [
                    ('SYSTEM INFO', 'uname -a'),
                    ('NETWORK INTERFACES', 'ifconfig -a'),
                    ('ROUTING TABLE', 'route -n'),
                    ('WIRELESS INFO', 'iwinfo wlan0 info'),
                    ('CONNECTED CLIENTS', 'iwinfo wlan0 assoclist'),
                    ('ARP TABLE', 'cat /proc/net/arp'),
                    ('DNS CONFIG', 'cat /var/etc/resolv.conf'),
                ]

                for section, cmd in intelbras_commands:
                    try:
                        result = connection.send_command(cmd, read_timeout=30)
                        output += f"=== {section} ===\n{result}\n\n"
                    except Exception as e:
                        output += f"=== {section} ===\nErro: {e}\n\n"

                output += "=== BACKUP END ==="
                logger.info(f"Backup Intelbras coletado: {len(output)} bytes")
            # Mikrotik /export needs timing-based approach instead of expect-based
            elif device['device_type'] == 'mikrotik_routeros' and 'export' in backup_command.lower():
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
            'mimosa_c5c': 'linux',
            'mimosa_b5c': 'linux',
            'mimosa_b5': 'linux',
            'mimosa_a5c': 'linux',
            'datacom': 'cisco_ios',
            'datacom_dmos': 'cisco_ios'
        }

        netmiko_type = device_type_map.get(device['device_type'], device['device_type'])

        # Timeout maior para Intelbras (radios podem ser lentos)
        connect_timeout = 60 if device['device_type'] == 'intelbras_radio' else 30

        device_config = {
            'device_type': netmiko_type + '_telnet',
            'host': device['ip_address'],
            'username': device['username'],
            'password': device['password'],
            'port': device['port'],
            'timeout': connect_timeout,
        }

        if device['enable_password']:
            device_config['secret'] = device['enable_password']

        try:
            connection = ConnectHandler(**device_config)
            if device['enable_password']:
                connection.enable()

            backup_command = device['backup_command'] if device['backup_command'] else self._get_default_command(device['device_type'])

            # Intelbras radio needs multiple commands to collect full info
            if device['device_type'] == 'intelbras_radio':
                output = "=== INTELBRAS RADIO BACKUP ===\n\n"

                intelbras_commands = [
                    ('SYSTEM INFO', 'uname -a'),
                    ('NETWORK INTERFACES', 'ifconfig -a'),
                    ('ROUTING TABLE', 'route -n'),
                    ('WIRELESS INFO', 'iwinfo wlan0 info'),
                    ('CONNECTED CLIENTS', 'iwinfo wlan0 assoclist'),
                    ('ARP TABLE', 'cat /proc/net/arp'),
                    ('DNS CONFIG', 'cat /var/etc/resolv.conf'),
                ]

                for section, cmd in intelbras_commands:
                    try:
                        result = connection.send_command(cmd, read_timeout=30)
                        output += f"=== {section} ===\n{result}\n\n"
                    except Exception as e:
                        output += f"=== {section} ===\nErro: {e}\n\n"

                output += "=== BACKUP END ==="
            else:
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
            # Mimosa - comando SSH (caso tenha acesso SSH)
            'mimosa': 'cat /etc/persistent/mimosa.cfg',
            'mimosa_c5c': 'cat /etc/persistent/mimosa.cfg',
            'mimosa_b5c': 'cat /etc/persistent/mimosa.cfg',
            'mimosa_b5': 'cat /etc/persistent/mimosa.cfg',
            'mimosa_a5c': 'cat /etc/persistent/mimosa.cfg',
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

    def _save_backup_binary(self, device, binary_data, extension='.bin'):
        """Salva backup em formato binário (para arquivos compactados como Intelbras .fmw)"""
        logger.info(f"_save_backup_binary chamado para {device['name']}")
        logger.info(f"Tamanho dos dados binários: {len(binary_data)} bytes")

        now = datetime.now(self.timezone)
        timestamp = now.strftime('%Y%m%d_%H%M%S')

        # Usar nova estrutura com provedor
        device_dir = self._get_device_backup_dir(device)
        logger.info(f"Diretório de backup: {device_dir}")

        # Nome do arquivo com extensão customizada
        filename = f"{device['ip_address']}_{timestamp}{extension}"
        file_path = os.path.join(device_dir, filename)
        logger.info(f"Caminho completo do arquivo: {file_path}")

        logger.info(f"Escrevendo {len(binary_data)} bytes no arquivo binário...")
        with open(file_path, 'wb') as f:
            f.write(binary_data)

        file_size = os.path.getsize(file_path)
        logger.info(f"Tamanho do arquivo após salvar: {file_size} bytes")

        if file_size == 0:
            logger.error(f"ERRO: Arquivo salvo com 0 bytes!")
        elif file_size != len(binary_data):
            logger.warning(f"AVISO: Tamanho do arquivo ({file_size}) diferente dos dados ({len(binary_data)})")

        self.db.add_backup(device['id'], filename, file_path, file_size, 'success')
        logger.info(f"Backup binário registrado no banco de dados")

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
