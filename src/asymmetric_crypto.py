# src/asymmetric_crypto.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

class AsymmetricCrypto:
    def __init__(self):
        self.key_size = 2048 # RSA-2048
    
    def generate_keypair(self, password: str):
        """Genera un par de claves RSA y las protege con contraseña"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )

        # Proteger clave privada con contraseña
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem
    
    def load_private_key(self, private_pem: bytes, password: str):
        """Carga una clave privada desde PEM"""
        return serialization.load_pem_private_key(
            private_pem,
            password=password.encode() if password else None
        )
    
    def load_public_key(self, public_pem: bytes):
        """Carga una clave pública desde PEM"""
        return serialization.load_pem_public_key(public_pem)
    
    def encrypt_with_public_key(self, data: bytes, public_key):
        """Cifra datos con una clave pública RSA"""
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
    
    def decrypt_with_private_key(self, encrypted_data, private_key):
        """Descifra datos con una clave privada RSA"""
        ciphertext = base64.b64decode(encrypted_data)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
