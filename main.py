# main.py
import os
from src import main_menu

def setup_directories():
    """Crea los directorios necesarios si no existen."""
    if not os.path.exists('data'):
        os.makedirs('data/vault')
        os.makedirs('data/pki')
        # Crea el archivo de usuarios vacío
        with open('data/users.json', 'w') as f:
            f.write('{}')

if __name__ == "__main__":
    print("===========================")
    print("    Bóveda Local Segura    ")
    print("===========================")

    # Prepara el entorno
    setup_directories()

    # Inicia el menú principal
    main_menu()
