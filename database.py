"""
Database Manager usando SQLAlchemy

Nova versão que usa SQLAlchemy ORM ao invés de SQL direto.
Mantém compatibilidade com a interface antiga para facilitar migração.
"""

from models import db, Device, Backup, Schedule, Provedor, User
from crypto_manager import CredentialManager
from validators import InputValidator, ValidationError
from datetime import datetime
import pytz
import logging

logger = logging.getLogger(__name__)


class Database:
    """
    Gerenciador de banco de dados usando SQLAlchemy.

    Esta classe mantém compatibilidade com a interface antiga
    mas usa SQLAlchemy internamente.
    """

    def __init__(self):
        """Inicializa o gerenciador de banco de dados."""
        self.timezone = pytz.timezone('America/Porto_Velho')
        self.crypto_manager = CredentialManager()
        self.validator = InputValidator()
        logger.info("Database manager inicializado")

    def get_connection(self):
        """
        DEPRECATED: Retorna sessão do SQLAlchemy.

        Mantido para compatibilidade. Use db.session diretamente.
        """
        logger.warning("get_connection() está deprecated. Use db.session diretamente.")
        return db.session

    def init_db(self):
        """
        Inicializa o banco de dados.

        Cria todas as tabelas se não existirem.
        """
        db.create_all()
        logger.info("Banco de dados inicializado")

    # ========================================================================
    # DEVICES
    # ========================================================================

    def add_device(self, name, ip_address, device_type, protocol, username, password,
                   port=22, enable_password=None, backup_command=None, provedor='Sem_Provedor'):
        """
        Adiciona um novo dispositivo.

        Args:
            name: Nome do dispositivo
            ip_address: Endereço IP
            device_type: Tipo do dispositivo (cisco_ios, etc)
            protocol: Protocolo (ssh, telnet, http, https)
            username: Nome de usuário
            password: Senha (será criptografada)
            port: Porta de conexão
            enable_password: Senha de enable (será criptografada)
            backup_command: Comando de backup personalizado
            provedor: Nome do provedor

        Returns:
            ID do dispositivo criado

        Raises:
            ValidationError: Se algum campo for inválido
        """
        try:
            # Validar inputs
            name = self.validator.validate_device_name(name)
            ip_address = self.validator.validate_ip_address(ip_address)
            device_type = self.validator.validate_device_type(device_type)
            protocol = self.validator.validate_protocol(protocol)
            port = self.validator.validate_port(port)
            username = self.validator.validate_username(username)
            provedor = self.validator.validate_provedor(provedor)

            if backup_command:
                backup_command = self.validator.validate_backup_command(backup_command, device_type)

            # Criptografar senhas
            encrypted_password = self.crypto_manager.encrypt(password)
            encrypted_enable_password = None
            if enable_password:
                encrypted_enable_password = self.crypto_manager.encrypt(enable_password)

            # Criar device
            device = Device(
                name=name,
                ip_address=ip_address,
                device_type=device_type,
                protocol=protocol,
                port=port,
                username=username,
                password=encrypted_password,
                enable_password=encrypted_enable_password,
                backup_command=backup_command,
                provedor=provedor
            )

            db.session.add(device)
            db.session.commit()

            logger.info(f"Device criado: {name} ({ip_address})")
            return device.id

        except ValidationError:
            raise
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao adicionar device: {e}")
            raise

    def get_all_devices(self, active_only=True):
        """
        Retorna todos os dispositivos.

        Args:
            active_only: Se True, retorna apenas dispositivos ativos

        Returns:
            Lista de dispositivos como dicionários (para compatibilidade)
        """
        try:
            query = Device.query
            if active_only:
                query = query.filter_by(active=True)

            devices = query.order_by(Device.name).all()

            # Converter para dicts e descriptografar senhas
            result = []
            for device in devices:
                device_dict = dict(device.to_dict(include_credentials=True))

                # Descriptografar senhas
                try:
                    device_dict['password'] = self.crypto_manager.decrypt(device_dict['password'])
                    if device_dict.get('enable_password'):
                        device_dict['enable_password'] = self.crypto_manager.decrypt(device_dict['enable_password'])
                except Exception as e:
                    logger.error(f"Erro ao descriptografar senhas do device {device.id}: {e}")
                    # Manter criptografado se falhar

                result.append(device_dict)

            return result

        except Exception as e:
            logger.error(f"Erro ao buscar devices: {e}")
            return []

    def get_device(self, device_id):
        """
        Retorna um dispositivo pelo ID.

        Args:
            device_id: ID do dispositivo

        Returns:
            Dicionário com dados do dispositivo ou None
        """
        try:
            device = Device.query.get(device_id)
            if not device:
                return None

            device_dict = dict(device.to_dict(include_credentials=True))

            # Descriptografar senhas
            try:
                device_dict['password'] = self.crypto_manager.decrypt(device_dict['password'])
                if device_dict.get('enable_password'):
                    device_dict['enable_password'] = self.crypto_manager.decrypt(device_dict['enable_password'])
            except Exception as e:
                logger.error(f"Erro ao descriptografar senhas do device {device_id}: {e}")

            return device_dict

        except Exception as e:
            logger.error(f"Erro ao buscar device {device_id}: {e}")
            return None

    def update_device(self, device_id, **kwargs):
        """
        Atualiza um dispositivo.

        Args:
            device_id: ID do dispositivo
            **kwargs: Campos a atualizar

        Raises:
            ValidationError: Se algum campo for inválido
        """
        try:
            device = Device.query.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} não encontrado")

            # Validar e atualizar campos
            if 'name' in kwargs:
                device.name = self.validator.validate_device_name(kwargs['name'])

            if 'ip_address' in kwargs:
                device.ip_address = self.validator.validate_ip_address(kwargs['ip_address'])

            if 'device_type' in kwargs:
                device.device_type = self.validator.validate_device_type(kwargs['device_type'])

            if 'protocol' in kwargs:
                device.protocol = self.validator.validate_protocol(kwargs['protocol'])

            if 'port' in kwargs:
                device.port = self.validator.validate_port(kwargs['port'])

            if 'username' in kwargs:
                device.username = self.validator.validate_username(kwargs['username'])

            if 'password' in kwargs:
                device.password = self.crypto_manager.encrypt(kwargs['password'])

            if 'enable_password' in kwargs:
                if kwargs['enable_password']:
                    device.enable_password = self.crypto_manager.encrypt(kwargs['enable_password'])
                else:
                    device.enable_password = None

            if 'backup_command' in kwargs:
                if kwargs['backup_command']:
                    device.backup_command = self.validator.validate_backup_command(
                        kwargs['backup_command'],
                        device.device_type
                    )
                else:
                    device.backup_command = None

            if 'provedor' in kwargs:
                device.provedor = self.validator.validate_provedor(kwargs['provedor'])

            if 'active' in kwargs:
                device.active = bool(kwargs['active'])

            device.updated_at = datetime.utcnow()
            db.session.commit()

            logger.info(f"Device {device_id} atualizado")

        except ValidationError:
            db.session.rollback()
            raise
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao atualizar device {device_id}: {e}")
            raise

    def delete_device(self, device_id):
        """
        Desativa um dispositivo (soft delete).

        Args:
            device_id: ID do dispositivo
        """
        try:
            device = Device.query.get(device_id)
            if device:
                device.active = False
                db.session.commit()
                logger.info(f"Device {device_id} desativado")

        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao deletar device {device_id}: {e}")
            raise

    # ========================================================================
    # BACKUPS
    # ========================================================================

    def add_backup(self, device_id, filename, file_path, file_size, status='success', error_message=None):
        """
        Adiciona um registro de backup.

        Args:
            device_id: ID do dispositivo
            filename: Nome do arquivo
            file_path: Caminho completo do arquivo
            file_size: Tamanho em bytes
            status: Status (success, failed)
            error_message: Mensagem de erro se falhou

        Returns:
            ID do backup criado
        """
        try:
            now = datetime.now(self.timezone)

            backup = Backup(
                device_id=device_id,
                filename=filename,
                file_path=file_path,
                file_size=file_size,
                status=status,
                error_message=error_message,
                backup_date=now
            )

            db.session.add(backup)
            db.session.commit()

            logger.info(f"Backup registrado: {filename} ({status})")
            return backup.id

        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao adicionar backup: {e}")
            raise

    def get_backups(self, device_id=None, limit=100):
        """
        Retorna backups.

        Args:
            device_id: Filtrar por device (opcional)
            limit: Número máximo de resultados

        Returns:
            Lista de backups como dicionários
        """
        try:
            query = Backup.query

            if device_id:
                query = query.filter_by(device_id=device_id)

            backups = query.order_by(Backup.backup_date.desc()).limit(limit).all()

            return [backup.to_dict() for backup in backups]

        except Exception as e:
            logger.error(f"Erro ao buscar backups: {e}")
            return []

    def get_backups_with_errors(self, limit=5):
        """Retorna backups com erro."""
        try:
            backups = Backup.query.filter_by(status='failed').order_by(
                Backup.backup_date.desc()
            ).limit(limit).all()

            return [backup.to_dict() for backup in backups]

        except Exception as e:
            logger.error(f"Erro ao buscar backups com erro: {e}")
            return []

    def count_backups(self, device_id=None):
        """Conta total de backups."""
        try:
            query = Backup.query
            if device_id:
                query = query.filter_by(device_id=device_id)
            return query.count()

        except Exception as e:
            logger.error(f"Erro ao contar backups: {e}")
            return 0

    # ========================================================================
    # SCHEDULES
    # ========================================================================

    def add_schedule(self, device_id, frequency, time, day_of_week=None, day_of_month=None):
        """Adiciona um agendamento."""
        try:
            schedule = Schedule(
                device_id=device_id,
                frequency=frequency,
                time=time,
                day_of_week=day_of_week,
                day_of_month=day_of_month
            )

            db.session.add(schedule)
            db.session.commit()

            logger.info(f"Schedule criado: {frequency} @ {time}")
            return schedule.id

        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao adicionar schedule: {e}")
            raise

    def get_schedules(self, active_only=True):
        """Retorna agendamentos."""
        try:
            query = Schedule.query
            if active_only:
                query = query.filter_by(active=True)

            schedules = query.order_by(Schedule.id).all()
            return [schedule.to_dict() for schedule in schedules]

        except Exception as e:
            logger.error(f"Erro ao buscar schedules: {e}")
            return []

    def get_schedule(self, schedule_id):
        """Retorna um schedule pelo ID."""
        try:
            schedule = Schedule.query.get(schedule_id)
            return schedule.to_dict() if schedule else None

        except Exception as e:
            logger.error(f"Erro ao buscar schedule {schedule_id}: {e}")
            return None

    def update_schedule_last_run(self, schedule_id):
        """Atualiza data da última execução."""
        try:
            schedule = Schedule.query.get(schedule_id)
            if schedule:
                schedule.last_run = datetime.utcnow()
                db.session.commit()

        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao atualizar last_run: {e}")

    def delete_schedule(self, schedule_id):
        """Deleta um schedule."""
        try:
            schedule = Schedule.query.get(schedule_id)
            if schedule:
                db.session.delete(schedule)
                db.session.commit()
                logger.info(f"Schedule {schedule_id} deletado")

        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao deletar schedule: {e}")
            raise

    # ========================================================================
    # PROVEDORES
    # ========================================================================

    def get_provedores(self):
        """Retorna lista de nomes de provedores."""
        try:
            # Provedores da tabela
            table_provedores = [p.name for p in Provedor.query.order_by(Provedor.name).all()]

            # Provedores dos devices (para compatibilidade)
            device_provedores = db.session.query(Device.provedor).filter(
                Device.provedor.isnot(None),
                Device.provedor != '',
                Device.provedor != 'Sem_Provedor'
            ).distinct().all()
            device_provedores = [p[0] for p in device_provedores if p[0]]

            # Combinar e remover duplicatas
            all_provedores = list(set(table_provedores + device_provedores))
            all_provedores.sort()

            return all_provedores

        except Exception as e:
            logger.error(f"Erro ao buscar provedores: {e}")
            return []

    def get_all_provedores(self):
        """Retorna todos os provedores com detalhes."""
        try:
            provedores = Provedor.query.order_by(Provedor.name).all()
            return [p.to_dict() for p in provedores]

        except Exception as e:
            logger.error(f"Erro ao buscar provedores detalhados: {e}")
            return []

    def add_provedor(self, name, description=None):
        """Adiciona um provedor."""
        try:
            # Validar
            name = self.validator.validate_provedor(name)

            # Verificar duplicata
            existing = Provedor.query.filter_by(name=name).first()
            if existing:
                raise ValueError(f"Provedor '{name}' já existe")

            provedor = Provedor(name=name, description=description)
            db.session.add(provedor)
            db.session.commit()

            logger.info(f"Provedor criado: {name}")
            return provedor.id

        except ValueError:
            db.session.rollback()
            raise
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao adicionar provedor: {e}")
            raise

    def delete_provedor(self, provedor_id):
        """Deleta um provedor pelo ID."""
        try:
            provedor = Provedor.query.get(provedor_id)
            if not provedor:
                raise ValueError("Provedor não encontrado")

            db.session.delete(provedor)
            db.session.commit()

            logger.info(f"Provedor {provedor_id} deletado")
            return 1

        except ValueError:
            db.session.rollback()
            raise
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao deletar provedor: {e}")
            raise

    def delete_provedor_by_name(self, name):
        """Deleta um provedor pelo nome."""
        try:
            provedor = Provedor.query.filter_by(name=name).first()
            if not provedor:
                raise ValueError(f"Provedor '{name}' não encontrado")

            db.session.delete(provedor)
            db.session.commit()

            logger.info(f"Provedor '{name}' deletado")
            return 1

        except ValueError:
            db.session.rollback()
            raise
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro ao deletar provedor: {e}")
            raise
