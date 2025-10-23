# Fichero: seguridad.py
import os, base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# (Definiciones de N_SCRYPT, R_SCRYPT, P_SCRYPT, LONGITUD_CLAVE...)
N_SCRYPT = 2**14
R_SCRYPT = 8
P_SCRYPT = 1
LONGITUD_CLAVE = 32

def _derivar_clave(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=LONGITUD_CLAVE, n=N_SCRYPT, r=R_SCRYPT, p=P_SCRYPT, backend=default_backend())
    return kdf.derive(password)

def cifrar_archivo(password_str: str, datos_en_claro: bytes) -> dict:
    password = password_str.encode('utf-8')
    salt = os.urandom(16)
    clave = _derivar_clave(password, salt)
    aesgcm = AESGCM(clave)
    nonce = os.urandom(12) 
    datos_cifrados = aesgcm.encrypt(nonce, datos_en_claro, None)
    return {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(datos_cifrados).decode('utf-8')
    }

def descifrar_archivo(password_str: str, paquete_cifrado: dict) -> bytes | None:
    try:
        salt = base64.b64decode(paquete_cifrado['salt'])
        nonce = base64.b64decode(paquete_cifrado['nonce'])
        datos_cifrados = base64.b64decode(paquete_cifrado['ciphertext'])
        password = password_str.encode('utf-8')
        clave = _derivar_clave(password, salt)
        aesgcm = AESGCM(clave)
        datos_descifrados = aesgcm.decrypt(nonce, datos_cifrados, None)
        return datos_descifrados
    except InvalidTag:
        print("\n*** ERROR: ¡Contraseña incorrecta o archivo corrupto! (MAC Invalido) ***")
        return None
    except Exception as e:
        print(f"\nHa ocurrido un error inesperado: {e}")
        return None