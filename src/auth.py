# src/auth.py
import json
import os, base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

USERS_FILE = 'data/users.json'

def register_user(username: str, password: str) -> bool:
    """Registra un nuevo usuario guardando el hash de su contraseña con un salt."""
    if not username or not password:
        print("Error: El nombre de usuario y la contraseña no pueden estar vacíos.")
        return False
    
    try:
        with open(USERS_FILE, 'r+') as f:
            users = json.load(f)
    except:
        users = {}
        
    if username in users:
        print("Error: El nombre de usuario ya existe.")
        return False
        
    # Genera un salt aleatorio de 16 bytes
    salt = os.urandom(16)

    # Crea el hash de la contraseña con el salt
    # Usamos PBKDF2, un estándar para derivar claves de contraseña
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)

    password_hash = kdf.derive(password.encode())

    # Guarda el usuario, el salt (en hexadecimal) y el hash (en hexadecimal)
    users[username] = {
        'salt': base64.b64encode(salt).decode(),
        'password_hash': base64.b64encode(password_hash).decode('utf-8')
    }

    # Sobreescribe el archivo
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)
    
    # Mensaje para el usuario
    print(f"Usuario '{username}' registrado con éxito.")

    # Mostrar el resultado en un log
    print(f"--- Log de Registro de Usuario ---")
    print(f"Hashing Utilizado: Algoritmo Scrypt")
    print(f"Parámetros Scrypt: N={2**14}, r=8, p=1 longitud=32 bytes")
    print(f"----------------------------------")

    return True

def login_user(username: str, password: str) -> str:
    """Autentica a un usuario comparando el hash de la contraseña proporcionada"""
    try:
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
    except:
        print("Error: No hay usuarios registrados o el archivo está dañado.")
        return None
    
    if username not in users:
        print("Error: Usuario o contraseña incorrectos.")
        return None
    
    user_data = users[username]
    salt = base64.b64decode(user_data['salt'])
    password_hash_stored = base64.b64decode(user_data['password_hash'])

    # Calcula el hash de la contraseña introducida con el salt guardado
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    
    try:
        # Compara los hashes de la contraseña guardada y la introducida
        kdf.verify(password.encode(), password_hash_stored)
        print("Inicio de sesión exitoso.")
        return username
    
    except Exception:
        print("Error: Usuario o contraseña incorrectos.")
        return None

def set_users_file_for_testing(new_path):
    """Función auxiliar para pruebas - cambia la ruta del archivo de usuarios"""
    global USERS_FILE
    USERS_FILE = new_path
