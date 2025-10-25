# src/crypto.py
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
import base64

class CryptoManager:
    def __init__(self):
        self.key_size = 32    # AES-256
    
    def generate_symmetric_key(self):
        """Genera una clave simétrica aleatoria para AES-GCM"""
        return os.urandom(self.key_size)

    def encrypt_aes(self, data: bytes, key: bytes) -> dict:
        """Cifra los datos usando AES-256-CBC con padding PKCS7"""
        # Generar IV aleatorio
        iv = os.urandom(16)

        # Configurar cifrador
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Aplicar padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Cifrar
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'iv': base64.b64encode(iv).decode(),
            'algorithm': 'AES-256-CBC'
        }
    
    def decrypt_aes(self, encrypted_data: dict, key: bytes) -> bytes:
        """Descifra los datos usando AES-256-CBC"""
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])

        # Configurar descifrador
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        # Descifrar
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Quitar padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

    def generate_hmac(self, data: bytes, key: bytes) -> str:
        """Genera un HMAC-SHA256 para autenticar los datos"""
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        return base64.b64encode(h.finalize()).decode()
    
    def verify_hmac(self, data: bytes, key: bytes, hmac_tag: str) -> bool:
        """Verifica un HMAC para autenticar los datos"""
        try:
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(data)
            h.verify(base64.b64decode(hmac_tag))
            return True
        except Exception:
            return False
