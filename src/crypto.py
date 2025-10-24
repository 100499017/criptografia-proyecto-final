# src/crypto.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

class CryptoManager:
    def __init__(self):
        self.key_size = 32    # AES-256-GCM
        self.nonce_size = 12  # 96 bits
    
    def generate_key(self):
        """Genera una clave simétrica aleatoria para AES-GCM"""
        return AESGCM.generate_key(self.key_size * 8)

    def encrypt_data(self, data: bytes, key: bytes) -> dict:
        """Cifra los datos usando AES-256-GCM"""
        # Generar nonce aleatorio
        nonce = os.urandom(self.nonce_size)

        # Crear instancia de AES-GCM
        aesgcm = AESGCM(key)

        # Cifrar los datos (GCM incluye autenticación automáticamente)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
        }
    
    def decrypt_data(self, encrypted_data: dict, key: bytes) -> bytes:
        """Descifra los datos usando AES-256-GCM"""
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])

        # Crear instancia de AES-GCM
        aesgcm = AESGCM(key)

        # Descifrar y verificar autenticación
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"Error de autenticación: {e}")
