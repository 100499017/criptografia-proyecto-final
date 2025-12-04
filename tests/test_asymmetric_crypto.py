# tests/test_asymmetric_crypto.py
import unittest
import os
import sys
import base64

# Añadir la carpeta raíz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.asymmetric_crypto import AsymmetricCrypto

class TestAsymmetricCrypto(unittest.TestCase):
    
    def setUp(self):
        self.crypto = AsymmetricCrypto()
    
    def test_generate_keypair(self):
        """Generar par de claves RSA"""
        private_pem, public_pem = self.crypto.generate_keypair("password123")

        # Verificar que son bytes
        self.assertIsInstance(private_pem, bytes)
        self.assertIsInstance(public_pem, bytes)
    
    def test_load_keys(self):
        """Cargar claves desde PEM"""
        private_pem, public_pem = self.crypto.generate_keypair("password123")

        # Cargar claves
        private_key = self.crypto.load_private_key(private_pem, "password123")
        public_key = self.crypto.load_public_key(public_pem)

        # Verificar que se cargaron correctamente
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
    
    def test_encrypt_decrypt(self):
        """Cifrar y descifrar con RSA"""
        test_data = b"Datos para cifrar y descifrar con RSA"

        # Generar claves
        private_pem, public_pem = self.crypto.generate_keypair("password123")
        private_key = self.crypto.load_private_key(private_pem, "password123")
        public_key = self.crypto.load_public_key(public_pem)

        # Cifrar
        encrypted = self.crypto.encrypt_with_public_key(test_data, public_key)

        # Descifrar
        decrypted = self.crypto.decrypt_with_private_key(encrypted, private_key)

        # Verificar igualdad
        self.assertEqual(test_data, decrypted)
    
    def test_load_private_key_wrong_password(self):
        """Con una contraseña incorrecta se rechaza la carga de la clave privada."""
        private_pem, public_pem = self.crypto.generate_keypair("password123")
    
        wrong_password = "incorrecta"
    
        # Debe lanzar una excepción al usar la contraseña incorrecta
        with self.assertRaises((ValueError)):
            self.crypto.load_private_key(private_pem, wrong_password)
    
    def test_decrypt_tampered_ciphertext(self):
        """Verifica que el descifrado falla si el texto cifrado (ciphertext) ha sido manipulado."""
        test_data = b"Datos que seran manipulados"

        # Generar claves
        private_pem, public_pem = self.crypto.generate_keypair("password123")
        private_key = self.crypto.load_private_key(private_pem, "password123")
        public_key = self.crypto.load_public_key(public_pem)

        # Cifrar
        encrypted = self.crypto.encrypt_with_public_key(test_data, public_key)
        
        # Simular manipulación (Alterar un byte)
        ciphertext = base64.b64decode(encrypted)
        
        # Cambiamos el último byte
        mutable_ciphertext = bytearray(ciphertext)
        mutable_ciphertext[-1] = mutable_ciphertext[-1] ^ 0x01 
        
        tampered_encrypted = base64.b64encode(mutable_ciphertext).decode()

        # Intentar descifrar (debe saltar una excepción)
        with self.assertRaises((ValueError)):
            self.crypto.decrypt_with_private_key(tampered_encrypted, private_key)

if __name__ == "__main__":
    unittest.main()
