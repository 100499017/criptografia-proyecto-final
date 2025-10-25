# tests/test_integration.py
import unittest
import os
import tempfile
import shutil
import sys

# Añadir la carpeta raíz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.auth import register_user, login_user
from src.crypto import CryptoManager
from src.asymmetric_crypto import AsymmetricCrypto

class TestIntegration(unittest.TestCase):
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        
        # Configurar archivo de usuarios de prueba
        self.test_users_file = os.path.join(self.test_dir, "test_users.json")
        with open(self.test_users_file, 'w') as f:
            f.write('{}')
        
        # Guardar y reemplazar archivo original
        self.original_users_file = register_user.__globals__['USERS_FILE']
        register_user.__globals__['USERS_FILE'] = self.test_users_file
        login_user.__globals__['USERS_FILE'] = self.test_users_file
    
    def tearDown(self):
        # Restaurar archivo original
        register_user.__globals__['USERS_FILE'] = self.original_users_file
        login_user.__globals__['USERS_FILE'] = self.original_users_file
        
        shutil.rmtree(self.test_dir)
    
    def test_complete_workflow(self):
        """Flujo completo: registro -> cifrado -> descifrado"""
        
        # 1. Registrar usuario
        result = register_user("test_user", "test_password")
        self.assertTrue(result)
        
        # 2. Iniciar sesión
        user = login_user("test_user", "test_password")
        self.assertEqual(user, "test_user")
        
        # 3. Probar cifrado simétrico
        crypto = CryptoManager()
        test_data = b"Esto es una prueba de integracion"
        key = crypto.generate_symmetric_key()
        
        encrypted = crypto.encrypt_aes(test_data, key)
        decrypted = crypto.decrypt_aes(encrypted, key)
        
        self.assertEqual(test_data, decrypted)
        
        # 4. Probar HMAC
        hmac_tag = crypto.generate_hmac(test_data, key)
        verification = crypto.verify_hmac(test_data, key, hmac_tag)
        self.assertTrue(verification)
        
        # 5. Probar RSA
        rsa_crypto = AsymmetricCrypto()
        private_pem, public_pem = rsa_crypto.generate_keypair("test_password")
        
        private_key = rsa_crypto.load_private_key(private_pem, "test_password")
        public_key = rsa_crypto.load_public_key(public_pem)
        
        # Cifrar clave AES con RSA
        encrypted_key = rsa_crypto.encrypt_with_public_key(key, public_key)
        decrypted_key = rsa_crypto.decrypt_with_private_key(encrypted_key, private_key)
        
        self.assertEqual(key, decrypted_key)

if __name__ == '__main__':
    unittest.main()
