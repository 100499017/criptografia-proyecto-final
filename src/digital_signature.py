# src/digital_signature.py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
import base64

class DigitalSignature:
    def __init__(self):
        self.signature_algorithm = 'RSA-PSS-SHA256'
    
    def sign_data(self, data: bytes, private_key) -> str:
        """Firma el hash de los datos con la clave privada usando RSA-PSS"""
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(data)
        digest = hasher.finalize()
        signature = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosen_hash)
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, data: bytes, signature: str, public_key) -> bool:
        """Verifica una firma con la clave pública"""
        try:
            signature_bytes = base64.b64decode(signature)
            chosen_hash = hashes.SHA256()
            hasher = hashes.Hash(chosen_hash)
            hasher.update(data)
            digest = hasher.finalize()
            public_key.verify(
                signature,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                utils.Prehashed(chosen_hash)
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Error verificando firma: {e}")
            return False
    
    def sign_file(self, file_path: str, private_key) -> str:
        """Firma un archivo completo"""
        with open(file_path, 'rb') as f:
            file_data = f.read()
        return self.sign_data(file_data, private_key)

    def verify_file_signature(self, file_path: str, signature: str, public_key) -> bool:
        """Verifica la firma de un archivo"""
        with open(file_path, 'rb') as f:
            file_data = f.read()
        return self.verify_signature(file_data, signature, public_key)
