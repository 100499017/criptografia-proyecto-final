# src/crypto.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

class CryptoManager:
    def __init__(self):
        self.key_size = 32   # AES-256
        self.nonce_size = 12 # 96 bits recomendado para GCM
    
    def generate_symmetric_key(self):
        """Genera una clave simétrica aleatoria para AES-GCM"""
        return AESGCM.generate_key(bit_length=self.key_size*8)

    def encrypt_aes_gcm(self, data: bytes, key: bytes) -> dict:
        """Cifra los datos usando AES-256-GCM (cifrado autenticado)"""
        # Generar nonce aleatorio
        nonce = os.urandom(self.nonce_size)

        # Crear instancia de AES-GCM
        aesgcm = AESGCM(key)

        # Cifrar datos (GCM incluye autenticación automáticamente)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'algorithm': 'AES-256-GCM'
        }
    
    def decrypt_aes_gcm(self, encrypted_data: dict, key: bytes) -> bytes:
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
            print(f"Error de autenticación GCM: {e}")
            return None
