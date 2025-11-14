# src/sign.py
from src.asymmetric_crypto import AsymmetricCrypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
import base64

class Signer:
    def __init__(self):
        self.asymmetric_crypto = AsymmetricCrypto()
    
    def sign_data(self, data: bytes, private_key) -> bytes:
        """Firma datos con clave privada RSA"""
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(data)
        digest = hasher.finalize()
        
        signature = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verifica la firma de los datos con clave pública RSA"""
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(data)
        digest = hasher.finalize()
        
        try:
            public_key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(hashes.SHA256())
            )
            return True
        except Exception:
            return False
