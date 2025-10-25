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
        encrypted = self.crypto.encrypt_aes(original_data, key)

        # Verificar que tiene la estructura correcta
        self.assertIn('ciphertext', encrypted)
        self.assertIn('iv', encrypted)

        # Descifrar
        decrypted = self.crypto.decrypt_aes(encrypted, key)

        # Verificar que son iguales
        self.assertEqual(original_data, decrypted)
    
    def test_hmac_generation(self):
        """Generar y verificar HMAC"""
        data = b"Datos para autenticar"
        key = self.crypto.generate_symmetric_key()

        # Generar HMAC
        hmac_tag = self.crypto.generate_hmac(data, key)

        # Verificar correcto
        result = self.crypto.verify_hmac(data, key, hmac_tag)
        self.assertTrue(result)
    
    def test_hmac_verification_fails(self):
        """Verificar que HMAC falla con datos modificados"""
        original_data = b"Datos originales"
        modified_data = b"Datos modificados"
        key = self.crypto.generate_symmetric_key()

        hmac_tag = self.crypto.generate_hmac(original_data, key)

        # Verificar con datos modificados
        result = self.crypto.verify_hmac(modified_data, key, hmac_tag)
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
