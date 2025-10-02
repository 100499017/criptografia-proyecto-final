# src/auth.py
import json
import hashlib
import hmac
import os

USERS_FILE = 'data/users.json'

def register_user(username, password):
    """Registra un nuevo usuario guardando el hash de su contraseña con un salt."""
    if not username or not password:
        print("El nombre de usuario y la contraseña no pueden estar vacíos.")
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
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'), # Convertimos la contraseña en una secuencia de bytes
            salt,
            100000 # Número de iteraciones
        )

        # Guarda el usuario, el salt (en hexadecimal) y el hash (en hexadecimal)
        users[username] = {
            'salt': salt.hex(),
            'password_hash': password_hash.hex()
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
    salt = bytes.fromhex(user_data['salt'])
    password_hash_stored = bytes.fromhex(user_data['password_hash'])

    # Calcula el hash de la contraseña introducida con el salt guardado
    password_hash_attempt = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )

    # Compara los hashes de la contraseña guardada y la introducida
    if password_hash_attempt == password_hash_stored:
        print("Inicio de sesión exitoso.")
        return username
    else:
        print("Error: Usuario o contraseña incorrectos.")
        return
