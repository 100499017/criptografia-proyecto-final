# main.py
import os
from src.cli import main_menu

def main():
    print("====================================")
    print("    SISTEMA DE MENSAJERÍA SEGURA    ")
    print("====================================")

    # Prepara el entorno
    setup_directories()

    # Inicia el menú principal
    main_menu()

def setup_directories():
    """Crea los directorios necesarios si no existen."""
    directories = [
        'data/keys',
        'data/public_keys',
        'data/vault',
        'data/messages'
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Crear archivo de usuarios si no existe
    if not os.path.exists('data/users.json'):
        with open('data/users.json', 'w') as f:
            f.write('{}')

if __name__ == "__main__":
    main()
