# tests/test_pki.py
import unittest
import os
import tempfile
import shutil
import sys

# Añadir la carpeta raíz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pki_manager import PKIManager

class TestPKI(unittest.TestCase):
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.pki = PKIManager(self.test_dir)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_create_ca(self):
        """Test creación de CA raíz"""
        self.pki.create_ca("TestCA", "testpassword")
        
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "TestCA")))
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "TestCA", "private_key.pem")))
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "TestCA", "certificate.pem")))
    
    def test_create_subca(self):
        """Test creación de subCA"""
        # Primero crear CA raíz
        root_private_key, root_cert = self.pki.create_ca("RootCA", "rootpassword")
        
        # Luego crear subCA
        _, subca_cert = self.pki.create_subca(
            "SubCA", "RootCA", root_private_key, root_cert, "subcapassword"
        )
        
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "SubCA")))
        self.assertEqual(subca_cert.issuer, root_cert.subject)

if __name__ == '__main__':
    unittest.main()
