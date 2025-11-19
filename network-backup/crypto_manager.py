"""
Gerenciador de Criptografia de Credenciais

Este módulo fornece criptografia segura AES-256 para senhas e credenciais
armazenadas no banco de dados, utilizando key derivation com PBKDF2.
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import secrets
import logging

logger = logging.getLogger(__name__)


class CredentialManager:
    """
    Gerencia criptografia e descriptografia de credenciais.

    Utiliza:
    - AES-256 via Fernet (symmetric encryption)
    - PBKDF2 para key derivation
    - Salt fixo (deve ser armazenado com segurança)
    - 100.000 iterações para proteção contra brute force
    """

    # Salt fixo - Em produção, considere armazenar em Vault/KMS
    # IMPORTANTE: Mudar este valor invalidará todas as senhas criptografadas existentes
    _SALT = b'network_backup_salt_v1_secure_2025'

    def __init__(self, encryption_key: str = None):
        """
        Inicializa o gerenciador de credenciais.

        Args:
            encryption_key: Chave de criptografia. Se None, tenta obter de ENCRYPTION_KEY env var.

        Raises:
            ValueError: Se ENCRYPTION_KEY não estiver configurada
        """
        if encryption_key is None:
            encryption_key = os.environ.get('ENCRYPTION_KEY')

        if not encryption_key:
            raise ValueError(
                "ENCRYPTION_KEY não configurada! "
                "Configure a variável de ambiente ENCRYPTION_KEY com uma chave de 32+ caracteres.\n"
                "Para gerar uma chave segura, use: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )

        self.key = self._derive_key(encryption_key)
        self.fernet = Fernet(self.key)
        logger.info("CredentialManager inicializado com sucesso")

    def _derive_key(self, password: str) -> bytes:
        """
        Deriva uma chave criptográfica a partir de uma senha usando PBKDF2.

        Args:
            password: Senha mestre para derivar a chave

        Returns:
            Chave de 32 bytes adequada para Fernet
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._SALT,
            iterations=100000,  # OWASP recomenda 100k+ para PBKDF2-SHA256
        )
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)

    def encrypt(self, plaintext: str) -> str:
        """
        Criptografa um texto plano.

        Args:
            plaintext: Texto a ser criptografado (ex: senha)

        Returns:
            Texto criptografado em base64

        Raises:
            ValueError: Se plaintext estiver vazio
        """
        if not plaintext:
            raise ValueError("Não é possível criptografar texto vazio")

        try:
            encrypted = self.fernet.encrypt(plaintext.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Erro ao criptografar: {e}")
            raise

    def decrypt(self, ciphertext: str) -> str:
        """
        Descriptografa um texto criptografado.

        Args:
            ciphertext: Texto criptografado em base64

        Returns:
            Texto plano original

        Raises:
            ValueError: Se ciphertext estiver vazio ou inválido
            cryptography.fernet.InvalidToken: Se o token for inválido ou a chave estiver errada
        """
        if not ciphertext:
            raise ValueError("Não é possível descriptografar texto vazio")

        try:
            decrypted = self.fernet.decrypt(ciphertext.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Erro ao descriptografar (chave incorreta ou dados corrompidos): {e}")
            raise

    def encrypt_dict(self, data: dict, fields: list) -> dict:
        """
        Criptografa campos específicos de um dicionário.

        Args:
            data: Dicionário com dados
            fields: Lista de campos a criptografar

        Returns:
            Dicionário com campos especificados criptografados
        """
        encrypted_data = data.copy()
        for field in fields:
            if field in encrypted_data and encrypted_data[field]:
                encrypted_data[field] = self.encrypt(encrypted_data[field])
        return encrypted_data

    def decrypt_dict(self, data: dict, fields: list) -> dict:
        """
        Descriptografa campos específicos de um dicionário.

        Args:
            data: Dicionário com dados criptografados
            fields: Lista de campos a descriptografar

        Returns:
            Dicionário com campos especificados descriptografados
        """
        decrypted_data = data.copy()
        for field in fields:
            if field in decrypted_data and decrypted_data[field]:
                try:
                    decrypted_data[field] = self.decrypt(decrypted_data[field])
                except Exception as e:
                    logger.warning(f"Não foi possível descriptografar campo '{field}': {e}")
                    # Manter valor criptografado se falhar
        return decrypted_data


def generate_encryption_key() -> str:
    """
    Gera uma chave de criptografia segura.

    Returns:
        Chave aleatória de 32 bytes em formato URL-safe base64
    """
    return secrets.token_urlsafe(32)


def test_encryption():
    """
    Testa o sistema de criptografia.
    Útil para validar a configuração.
    """
    print("=== Teste de Criptografia ===\n")

    # Gerar chave de teste
    test_key = generate_encryption_key()
    print(f"1. Chave gerada: {test_key[:20]}...\n")

    # Criar manager
    cm = CredentialManager(encryption_key=test_key)

    # Testar criptografia de senha
    senha_original = "minha_senha_super_secreta_123!"
    print(f"2. Senha original: {senha_original}")

    senha_criptografada = cm.encrypt(senha_original)
    print(f"3. Senha criptografada: {senha_criptografada[:50]}...\n")

    senha_descriptografada = cm.decrypt(senha_criptografada)
    print(f"4. Senha descriptografada: {senha_descriptografada}")

    # Validar
    if senha_original == senha_descriptografada:
        print("\n✓ Teste PASSOU! Criptografia funcionando corretamente.")
    else:
        print("\n✗ Teste FALHOU! Verificar implementação.")

    # Testar com dicionário
    device = {
        'name': 'Router-01',
        'ip_address': '10.0.0.1',
        'username': 'admin',
        'password': 'senha123',
        'enable_password': 'enable456'
    }

    print(f"\n5. Device original: {device}")

    encrypted_device = cm.encrypt_dict(device, ['password', 'enable_password'])
    print(f"\n6. Device criptografado:")
    print(f"   password: {encrypted_device['password'][:50]}...")
    print(f"   enable_password: {encrypted_device['enable_password'][:50]}...")

    decrypted_device = cm.decrypt_dict(encrypted_device, ['password', 'enable_password'])
    print(f"\n7. Device descriptografado: {decrypted_device}")

    if device == decrypted_device:
        print("\n✓ Teste de dicionário PASSOU!")
    else:
        print("\n✗ Teste de dicionário FALHOU!")


if __name__ == '__main__':
    # Gerar nova chave
    print("Para gerar uma nova ENCRYPTION_KEY, copie a linha abaixo:\n")
    print(f"export ENCRYPTION_KEY='{generate_encryption_key()}'")
    print("\n" + "="*60 + "\n")

    # Rodar testes se ENCRYPTION_KEY estiver configurada
    if os.environ.get('ENCRYPTION_KEY'):
        test_encryption()
    else:
        print("Para testar a criptografia, configure ENCRYPTION_KEY primeiro:")
        print(f"\nexport ENCRYPTION_KEY='{generate_encryption_key()}'")
        print("python crypto_manager.py")
