import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class CryptoUtils:
    def __init__(self):
        self.salt = b'CypherVault_Salt'  # In production, this should be unique per user
        self.key = None
        self.fernet = None

    def derive_key(self, master_password: str) -> None:
        """Derive encryption key from master password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.key = key
        self.fernet = Fernet(key)

    def encrypt_data(self, data: str) -> bytes:
        """Encrypt string data."""
        if not self.fernet:
            raise ValueError("Key not derived. Call derive_key first.")
        return self.fernet.encrypt(data.encode())

    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt encrypted data back to string."""
        if not self.fernet:
            raise ValueError("Key not derived. Call derive_key first.")
        return self.fernet.decrypt(encrypted_data).decode()

    def encrypt_file(self, input_file: str, output_file: str) -> None:
        """Encrypt a file."""
        if not self.fernet:
            raise ValueError("Key not derived. Call derive_key first.")
        
        with open(input_file, 'rb') as f:
            data = f.read()
        
        encrypted_data = self.fernet.encrypt(data)
        
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

    def decrypt_file(self, input_file: str, output_file: str) -> None:
        """Decrypt a file."""
        if not self.fernet:
            raise ValueError("Key not derived. Call derive_key first.")
        
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = self.fernet.decrypt(encrypted_data)
        
        with open(output_file, 'wb') as f:
            f.write(decrypted_data) 