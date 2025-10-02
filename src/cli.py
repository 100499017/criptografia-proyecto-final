# src/cli.py
from getpass import getpass
from src.auth import register_user, login_user

def main_menu():
    """Muestra el menú principal y gestiona la entrada del usuario."""
    while True:
        print("\n--- Menú Principal ---")
        print("1. Registrar un nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Salir")

        choice = input("Seleccione una opción: ")

        if choice == '1':
            username = input("Ingrese nombre de usuario: ")
            password = getpass("Ingrese contraseña: ")
            register_user(username, password)
        elif choice == '2':
            username = input("Ingrese nombre de usuario: ")
            password = getpass("Ingrese contraseña: ")
            user = login_user(username, password)
            if user:
                # Si el login es exitoso, pasamos al menú del usuario
                user_menu(user)
        elif choice == '3':
            print("Saliendo de la aplicación. ¡Hasta luego!")
            break
        else:
            print("Opción no válida. Inténtelo de nuevo.")

def user_menu(username):
    """Muestra el menú para un usuario autenticado."""
    print(f"¡Bienvenido, {username}!")
    while True:
        print("\n--- Menú de Usuario ---")
        print("1. Subir un archivo a la bóveda")
        print("2. Descargar un archivo de la bóveda")
        print("3. Compartir un archivo")
        print("4. Cerrar sesión")

        choice = input("Seleccione una opción: ")

        if choice == '1':
            #TODO
            ...
        elif choice == '2':
            #TODO
            ...
        elif choice == '3':
            #TODO
            ...
        elif choice == '4':
            print("Cerrando sesión.")
            break
        else:
            print("Opción no válida. Inténtelo de nuevo.")
