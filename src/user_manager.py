# src/user_manager.py
import os
import json
from cryptography.hazmat.primitives import serialization
from cryptography import x509

class UserManager:
    def __init__(self):
        self.users_file = 'data/users.json'
        self.certificates_dir = 'data/certificates'
        os.makedirs(self.certificates_dir, exist_ok=True)
    
    def user_exists(self, username: str) -> bool:
        """Verifica si un usuario existe"""
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
            return username in users
        except:
            return False
    
    def list_users(self):
        """Lista todos los usuarios registrados"""
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
            return [user for user in users.keys()]
        except:
            return []
    
    def save_user_certificate(self, username, certificate):
        """Guarda el certificado de un usuario"""
        cert_path = os.path.join(self.certificates_dir, f'{username}_certificate.pem')
        with open(cert_path, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
    def load_user_certificate(self, username):
        """Carga el certificado de un usuario"""
        cert_path = os.path.join(self.certificates_dir, f'{username}_certificate.pem')
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"Certificado no encontrado para el usuario: {username}")

        try:
            with open(cert_path, 'rb') as f:
                cert_pem = f.read()
            return x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            raise Exception(f"Error cargando certificado de {username}: {e}")
    
    def get_public_key_from_certificate(self, username):
        """Obtiene la clave pública desde el certificado del usuario"""
        try:
            cert = self.load_user_certificate(username)
            #TODO Cargar los certificados de RootCA y SubCA y verificar
            return cert.public_key()
        except Exception as e:
            raise Exception(f"Error obteniendo clave pública desde certificado de {username}: {e}")
