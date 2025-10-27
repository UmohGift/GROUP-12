import json
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

class PasswordVault:
    def __init__(self, master_password, storage_file="storage.json"):
        self.storage_file = storage_file
        self.key = self._derive_key(master_password)
        self.fernet = Fernet(self.key)
        self.data = self._load_storage()

    def _derive_key(self, password):
        salt = b"static_salt_value"  # for demo; use random in real app
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _load_storage(self):
        if not os.path.exists(self.storage_file):
            return {}
        with open(self.storage_file, "rb") as f:
            encrypted_data = f.read()
        if not encrypted_data:
            return {}
        try:
            decrypted = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted.decode())
        except Exception:
            raise ValueError("Invalid master password")

    def _save_storage(self):
        encrypted_data = self.fernet.encrypt(json.dumps(self.data).encode())
        with open(self.storage_file, "wb") as f:
            f.write(encrypted_data)

    def add_entry(self, name, username, password):
        self.data[name] = {"username": username, "password": password}
        self._save_storage()

    def list_entries(self):
        return list(self.data.keys())

    def get_entry(self, name):
        return self.data.get(name, {})
