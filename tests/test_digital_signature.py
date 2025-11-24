# tests/test_digital_signature.py
import unittest
import os
import sys

# Añadir la carpeta raíz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.digital_signature import DigitalSignature
from src.asymmetric_crypto import AsymmetricCrypto

class TestDigitalSignature(unittest.TestCase):
    
    def setUp(self):
        self.digital_signature = DigitalSignature()
        self.crypto = AsymmetricCrypto()
        
        # Generar par de claves para testing
        self.private_pem, self.public_pem = self.crypto.generate_keypair("testpassword")
        self.private_key = self.crypto.load_private_key(self.private_pem, "testpassword")
        self.public_key = self.crypto.load_public_key(self.public_pem)
    
    def test_sign_verify_data(self):
        """Test firma y verificación de datos"""
        test_data = b"Test data for digital signature"
        
        # Firmar
        signature = self.digital_signature.sign_data(test_data, self.private_key)
        
        # Verificar
        result = self.digital_signature.verify_signature(test_data, signature, self.public_key)
        self.assertTrue(result)
    
    def test_verify_tampered_data(self):
        """Test verificación con datos modificados"""
        original_data = b"Original data"
        tampered_data = b"Tampered data"
        
        signature = self.digital_signature.sign_data(original_data, self.private_key)
        result = self.digital_signature.verify_signature(tampered_data, signature, self.public_key)
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
