# tests/test_auth.py
import sys
import unittest
import os
import json
import tempfile
import shutil

# Añadir la carpeta raíz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.auth import register_user, login_user

class TestAuth(unittest.TestCase):

    def setUp(self):
        """Preparar entorno de prueba"""
        self.test_dir = tempfile.mkdtemp()
        self.test_users_file = os.path.join(self.test_dir, "test_users.json")

        # Crear archivo vacío
        with open(self.test_users_file, 'w') as f:
            json.dump({}, f)
        
        # Guardar archivo original y usar el de prueba
        self.original_users_file = register_user.__globals__['USERS_FILE']
        register_user.__globals__['USERS_FILE'] = self.test_users_file
        login_user.__globals__['USERS_FILE'] = self.test_users_file

    def tearDown(self):
        """Limpiar después de la prueba"""
        # Restaurar archivo original
        register_user.__globals__['USERS_FILE'] = self.original_users_file
        login_user.__globals__['USERS_FILE'] = self.original_users_file

        # Eliminar directorio temporal
        shutil.rmtree(self.test_dir)
    
    def test_register_user_success(self):
        """Registrar usuario exitosamente"""
        result = register_user("usuario1", "contraseña123")
        self.assertTrue(result)
    
    def test_register_duplicate_user(self):
        """No permitir usuario duplicado"""
        register_user("usuario1", "contraseña123")
        result = register_user("usuario1", "contraseña456")
        self.assertFalse(result)
    
    def test_login_success(self):
        """Inicio de sesión exitoso"""
        register_user("usuario1", "contraseña123")
        user = login_user("usuario1", "contraseña123")
        self.assertEqual(user, "usuario1")
    
    def test_login_wrong_password(self):
        """Inicio de sesión con contraseña incorrecta"""
        register_user("usuario1", "contraseña123")
        user = login_user("usuario1", "contraseña456")
        self.assertIsNone(user)
    
    def test_login_unknown_user(self):
        """Inicio de sesión con usuario que no existe"""
        user = login_user("usuario", "contraseña")
        self.assertIsNone(user)

if __name__ == "__main__":
    unittest.main()
