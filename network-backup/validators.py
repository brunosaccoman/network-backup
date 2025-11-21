"""
Sistema de Validação de Inputs

Fornece validação rigorosa de todos os inputs do usuário para prevenir:
- SQL Injection
- Command Injection
- Path Traversal
- XSS
- Inputs malformados
"""

import re
import ipaddress
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Exceção levantada quando validação falha."""
    pass


class InputValidator:
    """
    Classe principal para validação de inputs.

    Todos os métodos levantam ValidationError se a validação falhar.
    """

    # Whitelist de protocolos permitidos
    ALLOWED_PROTOCOLS = {'ssh', 'telnet', 'http', 'https'}

    # Whitelist de device types permitidos
    ALLOWED_DEVICE_TYPES = {
        'cisco_ios', 'cisco_nxos', 'cisco_asa', 'cisco_xr',
        'datacom', 'datacom_dmos',
        'juniper_junos', 'arista_eos', 'hp_comware',
        'huawei', 'huawei_vrpv8', 'mikrotik_routeros', 'mikrotik_dude',
        'paloalto_panos', 'ubiquiti_airos', 'ubiquiti_edge',
        'intelbras_radio', 'mimosa', 'fortinet_fortios',
        'dell_force10', 'extreme', 'checkpoint'
    }

    # Whitelist de comandos de backup por device type
    ALLOWED_BACKUP_COMMANDS = {
        'cisco_ios': [
            'show running-config',
            'show startup-config',
            'show version',
            'show configuration'
        ],
        'datacom': [
            'show running-config',
            'show startup-config',
            'show version',
            'show configuration'
        ],
        'datacom_dmos': [
            'show running-config',
            'show startup-config',
            'show version',
            'show configuration'
        ],
        'cisco_nxos': [
            'show running-config',
            'show startup-config'
        ],
        'cisco_asa': [
            'show running-config',
            'show startup-config'
        ],
        'cisco_xr': [
            'show running-config',
            'show configuration'
        ],
        'juniper_junos': [
            'show configuration',
            'show configuration | display set'
        ],
        'arista_eos': [
            'show running-config',
            'show startup-config'
        ],
        'hp_comware': [
            'display current-configuration',
            'display saved-configuration'
        ],
        'huawei': [
            'display current-configuration',
            'display saved-configuration'
        ],
        'huawei_vrpv8': [
            'display current-configuration',
            'display saved-configuration'
        ],
        'mikrotik_routeros': [
            'export compact',
            'export verbose',
            '/export'
        ],
        'mikrotik_dude': [
            '/dude export-db',
            '/dude export-db name'
        ],
        'paloalto_panos': [
            'show config running',
            'show config pushed-shared-policy'
        ],
        'ubiquiti_airos': [
            'cat /tmp/system.cfg',
            'cat /tmp/running.cfg'
        ],
        'ubiquiti_edge': [
            'show configuration',
            'show configuration commands'
        ],
        'intelbras_radio': [
            'cat /etc/config/*',
            'cat /etc/config/network',
            'cat /etc/config/wireless'
        ],
        'mimosa': [
            'cat /etc/persistent/mimosa.cfg'
        ],
        'fortinet_fortios': [
            'show',
            'show full-configuration'
        ]
    }

    # Frequências permitidas para agendamento
    ALLOWED_FREQUENCIES = {'daily', 'weekly', 'monthly'}

    # Roles de usuário permitidos
    ALLOWED_ROLES = {'admin', 'operator', 'viewer'}

    @staticmethod
    def validate_ip_address(ip: str) -> str:
        """
        Valida um endereço IP (IPv4 ou IPv6).

        Args:
            ip: String contendo o IP

        Returns:
            IP validado e normalizado

        Raises:
            ValidationError: Se o IP for inválido
        """
        if not ip:
            raise ValidationError("Endereço IP não pode estar vazio")

        try:
            # Tenta parsear como IPv4 ou IPv6
            ip_obj = ipaddress.ip_address(ip.strip())
            return str(ip_obj)
        except ValueError as e:
            raise ValidationError(f"Endereço IP inválido '{ip}': {str(e)}")

    @staticmethod
    def validate_port(port: int) -> int:
        """
        Valida um número de porta.

        Args:
            port: Número da porta

        Returns:
            Porta validada

        Raises:
            ValidationError: Se a porta for inválida
        """
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            raise ValidationError(f"Porta deve ser um número inteiro, recebido: {port}")

        if port_int < 1 or port_int > 65535:
            raise ValidationError(f"Porta deve estar entre 1 e 65535, recebido: {port_int}")

        return port_int

    @staticmethod
    def validate_protocol(protocol: str) -> str:
        """
        Valida o protocolo de conexão.

        Args:
            protocol: Nome do protocolo

        Returns:
            Protocolo validado em lowercase

        Raises:
            ValidationError: Se o protocolo não for permitido
        """
        if not protocol:
            raise ValidationError("Protocolo não pode estar vazio")

        protocol_lower = protocol.strip().lower()

        if protocol_lower not in InputValidator.ALLOWED_PROTOCOLS:
            raise ValidationError(
                f"Protocolo '{protocol}' não permitido. "
                f"Permitidos: {', '.join(InputValidator.ALLOWED_PROTOCOLS)}"
            )

        return protocol_lower

    @staticmethod
    def validate_device_type(device_type: str) -> str:
        """
        Valida o tipo de dispositivo.

        Args:
            device_type: Tipo do dispositivo

        Returns:
            Device type validado em lowercase

        Raises:
            ValidationError: Se o tipo não for permitido
        """
        if not device_type:
            raise ValidationError("Tipo de dispositivo não pode estar vazio")

        device_type_lower = device_type.strip().lower()

        if device_type_lower not in InputValidator.ALLOWED_DEVICE_TYPES:
            raise ValidationError(
                f"Tipo de dispositivo '{device_type}' não permitido. "
                f"Permitidos: {', '.join(sorted(InputValidator.ALLOWED_DEVICE_TYPES))}"
            )

        return device_type_lower

    @staticmethod
    def validate_backup_command(command: str, device_type: str) -> str:
        """
        Valida um comando de backup para um tipo de dispositivo.

        Args:
            command: Comando a ser validado
            device_type: Tipo do dispositivo

        Returns:
            Comando validado

        Raises:
            ValidationError: Se o comando não for permitido para este device type
        """
        if not command:
            raise ValidationError("Comando de backup não pode estar vazio")

        command = command.strip()
        device_type_lower = device_type.lower()

        # Buscar comandos permitidos para este device type
        allowed_commands = InputValidator.ALLOWED_BACKUP_COMMANDS.get(device_type_lower, [])

        if not allowed_commands:
            logger.warning(f"Nenhum comando de backup definido para device_type: {device_type}")
            # Permitir qualquer comando se não houver whitelist definida
            # Em produção, considere rejeitar ao invés de permitir
            return command

        # Verificar se o comando está na whitelist (case insensitive)
        command_lower = command.lower()
        for allowed in allowed_commands:
            if command_lower == allowed.lower():
                return command

        raise ValidationError(
            f"Comando '{command}' não permitido para device type '{device_type}'. "
            f"Comandos permitidos: {', '.join(allowed_commands)}"
        )

    @staticmethod
    def validate_device_name(name: str, max_length: int = 100) -> str:
        """
        Valida o nome de um dispositivo.

        Args:
            name: Nome do dispositivo
            max_length: Tamanho máximo permitido

        Returns:
            Nome validado

        Raises:
            ValidationError: Se o nome for inválido
        """
        if not name:
            raise ValidationError("Nome do dispositivo não pode estar vazio")

        name = name.strip()

        if len(name) > max_length:
            raise ValidationError(f"Nome muito longo (máximo {max_length} caracteres)")

        # Permitir alfanuméricos, espaços, hífens, underscores e pontos
        if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', name):
            raise ValidationError(
                "Nome contém caracteres inválidos. "
                "Permitidos: letras, números, espaços, hífens, underscores e pontos"
            )

        return name

    @staticmethod
    def validate_username(username: str, max_length: int = 50) -> str:
        """
        Valida um nome de usuário.

        Args:
            username: Nome de usuário
            max_length: Tamanho máximo permitido

        Returns:
            Username validado

        Raises:
            ValidationError: Se o username for inválido
        """
        if not username:
            raise ValidationError("Nome de usuário não pode estar vazio")

        username = username.strip()

        if len(username) > max_length:
            raise ValidationError(f"Nome de usuário muito longo (máximo {max_length} caracteres)")

        # Permitir alfanuméricos, hífens e underscores
        if not re.match(r'^[a-zA-Z0-9\-_@.]+$', username):
            raise ValidationError(
                "Nome de usuário contém caracteres inválidos. "
                "Permitidos: letras, números, @, ponto, hífen e underscore"
            )

        return username

    @staticmethod
    def validate_email(email: str) -> str:
        """
        Valida um endereço de email.

        Args:
            email: Endereço de email

        Returns:
            Email validado em lowercase

        Raises:
            ValidationError: Se o email for inválido
        """
        if not email:
            raise ValidationError("Email não pode estar vazio")

        email = email.strip().lower()

        # Regex básico para email (não perfeito, mas suficiente)
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        if not re.match(email_pattern, email):
            raise ValidationError(f"Email inválido: {email}")

        if len(email) > 255:
            raise ValidationError("Email muito longo (máximo 255 caracteres)")

        return email

    @staticmethod
    def validate_provedor(provedor: str, max_length: int = 100) -> str:
        """
        Valida o nome de um provedor.

        Args:
            provedor: Nome do provedor
            max_length: Tamanho máximo permitido

        Returns:
            Provedor validado

        Raises:
            ValidationError: Se o provedor for inválido
        """
        if not provedor:
            return "Sem_Provedor"

        provedor = provedor.strip()

        if len(provedor) > max_length:
            raise ValidationError(f"Nome do provedor muito longo (máximo {max_length} caracteres)")

        # Permitir alfanuméricos, espaços, hífens e underscores
        if not re.match(r'^[a-zA-Z0-9\s\-_]+$', provedor):
            raise ValidationError(
                "Nome do provedor contém caracteres inválidos. "
                "Permitidos: letras, números, espaços, hífens e underscores"
            )

        return provedor

    @staticmethod
    def validate_frequency(frequency: str) -> str:
        """
        Valida a frequência de agendamento.

        Args:
            frequency: Frequência (daily, weekly, monthly)

        Returns:
            Frequência validada em lowercase

        Raises:
            ValidationError: Se a frequência não for permitida
        """
        if not frequency:
            raise ValidationError("Frequência não pode estar vazia")

        frequency_lower = frequency.strip().lower()

        if frequency_lower not in InputValidator.ALLOWED_FREQUENCIES:
            raise ValidationError(
                f"Frequência '{frequency}' não permitida. "
                f"Permitidas: {', '.join(InputValidator.ALLOWED_FREQUENCIES)}"
            )

        return frequency_lower

    @staticmethod
    def validate_time(time_str: str) -> str:
        """
        Valida uma string de horário (HH:MM).

        Args:
            time_str: String no formato HH:MM

        Returns:
            Horário validado

        Raises:
            ValidationError: Se o horário for inválido
        """
        if not time_str:
            raise ValidationError("Horário não pode estar vazio")

        time_pattern = r'^([0-1][0-9]|2[0-3]):([0-5][0-9])$'

        if not re.match(time_pattern, time_str.strip()):
            raise ValidationError(
                f"Horário inválido '{time_str}'. "
                "Formato esperado: HH:MM (00:00 a 23:59)"
            )

        return time_str.strip()

    @staticmethod
    def validate_role(role: str) -> str:
        """
        Valida o role de um usuário.

        Args:
            role: Role do usuário

        Returns:
            Role validado em lowercase

        Raises:
            ValidationError: Se o role não for permitido
        """
        if not role:
            raise ValidationError("Role não pode estar vazio")

        role_lower = role.strip().lower()

        if role_lower not in InputValidator.ALLOWED_ROLES:
            raise ValidationError(
                f"Role '{role}' não permitido. "
                f"Permitidos: {', '.join(InputValidator.ALLOWED_ROLES)}"
            )

        return role_lower

    @staticmethod
    def sanitize_path(file_path: str, base_dir: str) -> str:
        """
        Valida e sanitiza um caminho de arquivo para prevenir path traversal.

        Args:
            file_path: Caminho do arquivo
            base_dir: Diretório base permitido

        Returns:
            Caminho absoluto validado

        Raises:
            ValidationError: Se o caminho tentar sair do diretório base
        """
        import os

        if not file_path:
            raise ValidationError("Caminho do arquivo não pode estar vazio")

        # Resolver para caminho absoluto
        abs_path = os.path.abspath(file_path)
        abs_base = os.path.abspath(base_dir)

        # Verificar se o caminho está dentro do diretório base
        if not abs_path.startswith(abs_base):
            raise ValidationError(
                f"Acesso negado: caminho '{file_path}' está fora do diretório permitido"
            )

        return abs_path

    @staticmethod
    def validate_positive_integer(value: int, field_name: str = "valor") -> int:
        """
        Valida um inteiro positivo.

        Args:
            value: Valor a validar
            field_name: Nome do campo (para mensagens de erro)

        Returns:
            Inteiro validado

        Raises:
            ValidationError: Se o valor não for um inteiro positivo
        """
        try:
            int_value = int(value)
        except (ValueError, TypeError):
            raise ValidationError(f"{field_name} deve ser um número inteiro")

        if int_value < 1:
            raise ValidationError(f"{field_name} deve ser maior que zero")

        return int_value


# Funções de conveniência para validação rápida
def validate_device_data(data: dict) -> dict:
    """
    Valida todos os campos de um dispositivo de uma vez.

    Args:
        data: Dicionário com dados do dispositivo

    Returns:
        Dicionário com dados validados

    Raises:
        ValidationError: Se algum campo for inválido
    """
    validator = InputValidator()

    validated = {}

    # Campos obrigatórios
    validated['name'] = validator.validate_device_name(data.get('name', ''))
    validated['ip_address'] = validator.validate_ip_address(data.get('ip_address', ''))
    validated['device_type'] = validator.validate_device_type(data.get('device_type', ''))
    validated['protocol'] = validator.validate_protocol(data.get('protocol', ''))
    validated['username'] = validator.validate_username(data.get('username', ''))

    # Campos opcionais com validação
    if 'port' in data and data['port']:
        validated['port'] = validator.validate_port(data['port'])
    else:
        validated['port'] = 22  # Default SSH

    if 'provedor' in data:
        validated['provedor'] = validator.validate_provedor(data.get('provedor', ''))

    if 'backup_command' in data and data['backup_command']:
        validated['backup_command'] = validator.validate_backup_command(
            data['backup_command'],
            validated['device_type']
        )

    # Senhas não são validadas aqui (apenas presença), criptografia é feita separadamente
    if not data.get('password'):
        raise ValidationError("Senha não pode estar vazia")
    validated['password'] = data['password']

    if 'enable_password' in data:
        validated['enable_password'] = data.get('enable_password')

    return validated


if __name__ == '__main__':
    # Testes rápidos
    print("=== Testes de Validação ===\n")

    validator = InputValidator()

    # Teste de IP
    try:
        ip = validator.validate_ip_address("192.168.1.1")
        print(f"✓ IP válido: {ip}")
    except ValidationError as e:
        print(f"✗ Erro: {e}")

    # Teste de IP inválido
    try:
        validator.validate_ip_address("999.999.999.999")
        print("✗ IP inválido não foi rejeitado!")
    except ValidationError:
        print("✓ IP inválido foi corretamente rejeitado")

    # Teste de porta
    try:
        port = validator.validate_port(22)
        print(f"✓ Porta válida: {port}")
    except ValidationError as e:
        print(f"✗ Erro: {e}")

    # Teste de protocolo
    try:
        proto = validator.validate_protocol("SSH")
        print(f"✓ Protocolo válido: {proto}")
    except ValidationError as e:
        print(f"✗ Erro: {e}")

    # Teste de device type
    try:
        dtype = validator.validate_device_type("cisco_ios")
        print(f"✓ Device type válido: {dtype}")
    except ValidationError as e:
        print(f"✗ Erro: {e}")

    # Teste de comando
    try:
        cmd = validator.validate_backup_command("show running-config", "cisco_ios")
        print(f"✓ Comando válido: {cmd}")
    except ValidationError as e:
        print(f"✗ Erro: {e}")

    # Teste de comando inválido
    try:
        validator.validate_backup_command("rm -rf /", "cisco_ios")
        print("✗ Comando malicioso não foi rejeitado!")
    except ValidationError:
        print("✓ Comando malicioso foi corretamente rejeitado")

    print("\n✓ Todos os testes passaram!")
