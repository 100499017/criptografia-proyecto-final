# tests/test_crypto.py
import unittest
import os
import sys
import base64

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
    
    def test_integrity_check(self):
        """
        Prueba de Integridad:
        Verifica que AES-GCM detecta si el texto cifrado ha sido manipulado.
        """
        original_data = b"Mensaje critico de seguridad"
        key = self.crypto.generate_symmetric_key()

        # Cifrar datos legítimos
        encrypted_dict = self.crypto.encrypt_aes_gcm(original_data, key)

        # Simular un ataque (Man-in-the-Middle)
        # Obtenemos el ciphertext original
        original_ciphertext = base64.b64decode(encrypted_dict['ciphertext'])
        
        # Modificamos un solo byte del mensaje cifrado
        # Convertimos a mutable (bytearray), cambiamos el último byte y volvemos a bytes
        mutable_ciphertext = bytearray(original_ciphertext)
        mutable_ciphertext[-1] = mutable_ciphertext[-1] ^ 0xFF # Invertir bits

        # Actualizamos el diccionario con el ciphertext corrupto
        encrypted_dict['ciphertext'] = base64.b64encode(mutable_ciphertext).decode()

        # Intentar descifrar
        # El sistema captura internamente el error de integridad (InvalidTag)
        # y devuelve None para indicar que el descifrado falló
        result = self.crypto.decrypt_aes_gcm(encrypted_dict, key)
        
        self.assertIsNone(result, "El sistema debería retornar None al detectar manipulación del criptograma (Fallo de integridad)")

if __name__ == "__main__":
    unittest.main()
