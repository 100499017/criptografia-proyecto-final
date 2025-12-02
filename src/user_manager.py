# src/user_manager.py
import os
import json
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

class UserManager:
    def __init__(self):
        self.users_file = 'data/users.json'
        self.certificates_dir = 'data/certificates'
        self.pki_dir = 'data/pki'
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
        """
        Carga el certificado del usuario, verifica toda la cadena de confianza
        (User -> SubCA -> RootCA) y si es válido, retorna su clave pública.
        """
        print(f"Validando certificado X.509 para '{username}'...")

        # Cargar el certificado del usuario
        user_cert = self.load_user_certificate(username)

        # Cargar los certificados de las Autoridades de Certificación
        try:
            sub_ca_cert = self._load_ca_certificate("SubCA")
            root_ca_cert = self._load_ca_certificate("RootCA")
        except FileNotFoundError:
            print("Error: No se encuentran los certificados de la CA (Root/Sub) para validar.")
            raise ValueError("Infraestructura PKI incompleta o no inicializada.")
        
        # Validar fechas
        now = datetime.now(timezone.utc)
        not_before = user_cert.not_valid_before_utc
        not_after = user_cert.not_valid_after_utc

        if not (not_before <= now <= not_after):
            raise ValueError(f"El certificado de {username} ha expirado o aún no es válido.")
        
        # Validar firmas criptográficas
        try:
            # Verificar que la Root CA es auténtica (autofirmada)
            self._verify_signature(root_ca_cert, root_ca_cert.public_key())

            # Verificar que la Sub CA fue firmada por la Root CA
            self._verify_signature(sub_ca_cert, root_ca_cert.public_key())

            # Verificar que el certificado del Usuario fue firmado por la Sub CA
            self._verify_signature(user_cert, sub_ca_cert.public_key())

            print(f"Certificado de {username} verificado correctamente. " \
                  "Cadena de confianza válida.")
            return user_cert.public_key()
        
        except Exception as e:
            print(f"Fallo en la verificación de la cadena de certificados: {e}")
            return None
    
    def _load_ca_certificate(self, ca_name):
        """Carga certificado de CA"""
        path = os.path.join(self.pki_dir, ca_name, 'certificate.pem')
        if not os.path.exists(path):
            raise FileNotFoundError(f"No existe el certificado para {ca_name}")
        with open(path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read())
    
    def _verify_signature(self, cert, issuer_public_key):
        """Verifica la firma de un certificado usando la clave pública del emisor"""
        try:
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except Exception as e:
            raise ValueError(f"Firma inválida en la cadena de confianza: {e}")
