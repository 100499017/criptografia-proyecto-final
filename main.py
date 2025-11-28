# main.py
import os
import sys
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
        'data/messages',
        'downloads'
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Crear archivo de usuarios si no existe
    if not os.path.exists('data/users.json'):
        with open('data/users.json', 'w') as f:
            f.write('{}')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSaliendo de la aplicación...")
        sys.exit(0)
    except Exception as e:
        print(f"\nOcurrió un error inesperado: {e}")
        sys.exit(1)
