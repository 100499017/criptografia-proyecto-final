# tests/test_user_manager.py
import unittest
import os
import json
import tempfile
import shutil
import sys

# Añadir la carpeta raíz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.user_manager import UserManager

class TestUserManager(unittest.TestCase):
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.test_users_file = os.path.join(self.test_dir, "test_users.json")
        
        # Crear datos de prueba
        test_users = {
            "usuario1": {"salt": "salt1", "password_hash": "hash1"},
            "usuario2": {"salt": "salt2", "password_hash": "hash2"}
        }
        
        with open(self.test_users_file, 'w') as f:
            json.dump(test_users, f)
        
        self.user_manager = UserManager()
        self.user_manager.users_file = self.test_users_file
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_user_exists(self):
        """Verificar existencia de usuarios"""
        self.assertTrue(self.user_manager.user_exists("usuario1"))
        self.assertTrue(self.user_manager.user_exists("usuario2"))
        self.assertFalse(self.user_manager.user_exists("usuario3"))
    
    def test_list_users(self):
        """Listar usuarios"""
        users = self.user_manager.list_users()
        
        self.assertEqual(len(users), 2)
        self.assertIn("usuario1", users)
        self.assertIn("usuario2", users)

if __name__ == '__main__':
    unittest.main()
