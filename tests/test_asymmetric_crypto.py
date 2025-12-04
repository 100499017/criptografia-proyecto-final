# tests/test_asymmetric_crypto.py
import unittest
import os
import sys
import base64

# Añadir la carpeta raíz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.asymmetric_crypto import AsymmetricCrypto
from src.asymmetric_crypto import KeyLoadError, DecryptionError, EncryptionError

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
        """Con una contraseña incorrecta se rechaza la carga de la clave privada (excepción manejada KeyLoadError)"""
        private_pem, public_pem = self.crypto.generate_keypair("password123")
    
        wrong_password = "incorrecta"
    
        # Debe lanzar una excepción por error al cargar la clave (contraseña incorrecta)
        with self.assertRaises((KeyLoadError)):
            self.crypto.load_private_key(private_pem, wrong_password)
    
    def test_load_public_key_corrupt(self):
        """Verifica que la carga de clave pública falla si el PEM está corrupto (excepción manejada KeyLoadError)"""
        # Generar claves
        private_pem, public_pem = self.crypto.generate_keypair("any_password")
        
        # Simular corrupción (quitar algunos bytes)
        corrupt_public_pem = public_pem[:-10]
        
        # Debe lanzar una excepción por error al cargar la clave (clave corrupta)
        with self.assertRaises(KeyLoadError):
            self.crypto.load_public_key(corrupt_public_pem)
    
    def test_decrypt_tampered_ciphertext(self):
        """Verifica que el descifrado falla si el texto cifrado (ciphertext) ha sido manipulado (excepción manejada DecryptionError)"""
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

        # # Debe lanzar una excepción por error al descifrar (ciphertext manipulado)
        with self.assertRaises((DecryptionError)):
            self.crypto.decrypt_with_private_key(tampered_encrypted, private_key)
    
    def test_encrypt_data_too_large(self):
        """Verifica que el cifrado falla con datos grandes que exceden el límite de RSA (excepción manejada EncryptionError)"""
        
        # Datos que superan el límite de 214 bytes
        large_data = b'A' * 300
        
        # Generar claves
        _, public_pem = self.crypto.generate_keypair("any_password")
        public_key = self.crypto.load_public_key(public_pem)
        
        # Debe lanzar una excepción por error al cifrar (datos demasiado grandes)
        with self.assertRaises(EncryptionError):
            self.crypto.encrypt_with_public_key(large_data, public_key)

if __name__ == "__main__":
    unittest.main()
