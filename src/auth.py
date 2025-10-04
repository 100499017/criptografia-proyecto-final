# src/auth.py
import json
import os, base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

USERS_FILE = 'data/users.json'

def register_user(username, password):
    """Registra un nuevo usuario guardando el hash de su contraseña con un salt."""
    if not username or not password:
        print("Error: El nombre de usuario y la contraseña no pueden estar vacíos.")
        return
    
    with open(USERS_FILE, 'r+') as f:
        try:
            users = json.load(f)
        except json.JSONDecodeError:
            users = {}
        
        if username in users:
            print("Error: El nombre de usuario ya existe.")
            return
        
        # Genera un salt aleatorio de 16 bytes
        salt = os.urandom(16)

        # Crea el hash de la contraseña con el salt
        # Usamos PBKDF2, un estándar para derivar claves de contraseña
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1
        )

        password_hash = kdf.derive(password.encode('utf-8'))

        # Guarda el usuario, el salt (en hexadecimal) y el hash (en hexadecimal)
        users[username] = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'password_hash': base64.b64encode(password_hash).decode('utf-8')
        }

        # Vuelve al inicio del archivo para sobreescribirlo
        f.seek(0)
        json.dump(users, f, indent=4)
        print(f"Usuario '{username}' registrado con éxito.")
        return True

def login_user(username, password):
    """Autentica a un usuario comparando el hash de la contraseña proporcionada"""
    try:
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print("Error: No hay usuarios registrados o el archivo está dañado.")
        return
    
    if username not in users:
        print("Error: Usuario o contraseña incorrectos.")
        return
    
    user_data = users[username]
    salt = base64.b64decode(user_data['salt'])
    password_hash_stored = base64.b64decode(user_data['password_hash'])

    # Calcula el hash de la contraseña introducida con el salt guardado
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    password_hash_attempt = kdf.derive(password.encode('utf-8'))

    # Compara los hashes de la contraseña guardada y la introducida
    if password_hash_attempt == password_hash_stored:
        print("Inicio de sesión exitoso.")
        return username
    else:
        print("Error: Usuario o contraseña incorrectos.")
        return
