# src/pki_manager.py
import os
from datetime import datetime,timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class PKIManager:
    def __init__(self, base_dir='data/pki'):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
    
    def create_ca(self, ca_name, private_key_password=None):
        """Crea una Autoridad Certificadora Raíz (Autofirmada)"""
        # Generar clave privada para la CA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Crear el certificado autofirmado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bóveda Segura"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES")
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=3650) # 10 años
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).sign(private_key, hashes.SHA256())

        # Guardar clave privada y certificado
        ca_dir = os.path.join(self.base_dir, ca_name)
        os.makedirs(ca_dir, exist_ok=True)

        # Guardar la clave privada
        with open(os.path.join(ca_dir, 'private_key.pem'), 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(private_key_password.encode()) if private_key_password else serialization.NoEncryption()
            ))
        
        # Guardar certificado
        with open(os.path.join(ca_dir, 'certificate.pem'), 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        return private_key, cert

    def create_subca(self, subca_name, parent_ca_name, parent_private_key, parent_cert, private_key_password=None):
        """Crea una Autoridad Certificada Subordinada"""
        # Generar clave privada paa la subCA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subca_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bóveda Segura"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES")
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            parent_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=1825) # 5 años
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        ).sign(parent_private_key, hashes.SHA256())

        # Guardar clave privada y certificado
        subca_dir = os.path.join(self.base_dir, subca_name)
        os.makedirs(subca_dir, exist_ok=True)

        # Guardar clave privada
        with open(os.path.join(subca_dir, 'private_key.pem'), 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(private_key_password.encode()) if private_key_password else serialization.NoEncryption()
            ))
        
        # Guardar certificado
        with open(os.path.join(subca_dir, 'certificate.pem'), 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        return private_key, cert
    
    def generate_user_csr(self, private_key, username):
        """
        Genera una Solicitud de Firma de Certificado (CSR).
        Esto debe ejecutarse en el lado del usuario usando su propia clave privada.
        """
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, username),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bóveda Segura"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES")
            ])
        ).sign(private_key, hashes.SHA256())

        return csr
    
    def issue_certificate(self, csr, ca_name, ca_password):
        """Emite un certificado final a partir de un CSR."""
        # Cargar credenciales de la CA firmante (SubCA)
        ca_cert = self.load_ca_certificate(ca_name)
        ca_private_key = self.load_private_key(ca_name, ca_password)

        # Validar que la firma del CSR es válida
        if not csr.is_signature_valid:
            raise ValueError("Firma del CSR inválida: el usuario no posee la clave privada correspondiente.")
        
        # Construir el certificado final
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365) # 1 año
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).sign(ca_private_key, hashes.SHA256())

        return cert
    
    def load_ca_certificate(self, ca_name):
        """Carga el certificado de una CA"""
        cert_path = os.path.join(self.base_dir, ca_name, 'certificate.pem')
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"No se encontró el certificado para {ca_name}")
        with open(cert_path, 'rb') as f:
            cert_pem = f.read()
        return x509.load_pem_x509_certificate(cert_pem)
    
    def load_private_key(self, ca_name, password=None):
        """Carga la clave privada de una CA"""
        key_path = os.path.join(self.base_dir, ca_name, 'private_key.pem')
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"No se encontró la clave privada para {ca_name}")

        with open(key_path, 'rb') as f:
            private_pem = f.read()
        return serialization.load_pem_private_key(private_pem, password=password.encode() if password else None)
