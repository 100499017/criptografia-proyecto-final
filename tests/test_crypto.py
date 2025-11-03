# tests/test_crypto.py
import unittest
import os
import sys

# Añadir la carpeta raíz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.crypto import CryptoManager

class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.crypto = CryptoManager()
    
    def test_generate_key(self):
        """Generar clave simétrica"""
        key = self.crypto.generate_symmetric_key()
        self.assertEqual(len(key), 32)
    
    def test_encrypt_descrypt(self):
        """Cifrar y descifrar datos"""
        original_data = b"Datos para cifrar y descifrar"
        key = self.crypto.generate_symmetric_key()

        # Cifrar
        encrypted = self.crypto.encrypt_aes_gcm(original_data, key)

        # Verificar que tiene la estructura correcta
        self.assertIn('ciphertext', encrypted)
        self.assertIn('nonce', encrypted)

        # Descifrar
        decrypted = self.crypto.decrypt_aes_gcm(encrypted, key)

        # Verificar que son iguales
        self.assertEqual(original_data, decrypted)

if __name__ == "__main__":
    unittest.main()
