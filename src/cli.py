# src/cli.py
import os
import shutil
from getpass import getpass
from src.auth import register_user, login_user
from src.user_manager import UserManager
from src.personal_vault import PersonalVault
from src.messaging import MessagingSystem
from src.asymmetric_crypto import AsymmetricCrypto

def main_menu():
    """Muestra el menú principal y gestiona la entrada del usuario."""
    while True:
        print("\n--- Menú Principal ---")
        print("1. Registrar usuario")
        print("2. Iniciar sesión")
        print("3. Salir")
        print("4. Borrar todos los datos y salir")

        choice = input("Seleccione una opción: ")

        if choice == '1':
            username = input("Ingrese nombre de usuario: ")
            password = getpass("Ingrese contraseña: ")

            if register_user(username, password):
                # Generar claves RSA
                crypto = AsymmetricCrypto()
                private_pem, public_pem = crypto.generate_keypair(password)

                # Guardar claves
                os.makedirs(f'data/keys/{username}', exist_ok=True)
                with open(f'data/keys/{username}/private_key.pem', 'wb') as f:
                    f.write(private_pem)
                with open(f'data/public_keys/{username}_public.pem', 'wb') as f:
                    f.write(public_pem)

                print("Usuario registrado con claves RSA.")

            else:
                print("El registro falló. Inténtelo de nuevo.")

        elif choice == '2':
            username = input("Ingrese nombre de usuario: ")
            password = getpass("Ingrese contraseña: ")
            user = login_user(username, password)
            if user:
                # Si el login es exitoso, pasamos al menú del usuario
                user_menu(user, password)
        elif choice == '3':
            print("Saliendo del sistema. ¡Hasta luego!")
            break
        elif choice == '4':
            shutil.rmtree('data')
            print("Todos los datos han sido borrados. ¡Hasta luego!")
            break
        else:
            print("Opción no válida. Inténtelo de nuevo.")

def user_menu(username, password):
    """Muestra el menú para un usuario autenticado."""
    vault = PersonalVault(username)
    messaging = MessagingSystem()
    user_manager = UserManager()

    while True:
        print("\n--- Menú de {username} ---")
        print("1. Guardar archivo en mi bóveda")
        print("2. Recuperar archivo de mi bóveda")
        print("3. Listar mis archivos")
        print("4. Enviar archivo a otro usuario")
        print("5. Ver archivos recibidos")
        print("6. Listar usuarios")
        print("7. Cerrar sesión")

        choice = input("Seleccione una opción: ")

        if choice == '1':
            file_path = input("Ruta del archivo: ")
            password = getpass("Su contraseña: ")
            vault.store_file(file_path, password)

        elif choice == '2':
            files = vault.list_files()
            if files:
                filename = input("Nombre del archivo: ")
                output_path = input("Ruta donde guardar: ")
                password = getpass("Su contraseña: ")
                vault.download_file(filename, password, output_path)

        elif choice == '3':
            vault.list_files()

        elif choice == '4':
            receiver = input("Usuario destino: ")
            file_path = input("Ruta del archivo: ")
            message = input("Mensaje (opcional): ")
            password = getpass("Su contraseña: ")
            messaging.send_file(username, receiver, file_path, password, message)

        elif choice == '5':
            password = getpass("Su contraseña: ")
            messages = messaging.get_messages(username, password)

            for i, msg in enumerate(messages, 1):
                print(f"\n--- Mensaje {i} ---")
                print(f"De: {msg['sender']}")
                print(f"Archivo: {msg['filename']}")
                print(f"Mensaje: {msg['message']}")
                print(f"Firma válida: {'Sí' if msg['signature_valid'] else 'No'}")

                save = input("¿Descargar archivo? (s/n)")
                if save.lower() == 's':
                    messaging.save_received_file(msg)

        elif choice == '6':
            users = user_manager.list_users()
            print("\nUsuarios registrados:")
            for user in users:
                print(f"\t- {user}")
        
        elif choice == '7':
            print("Cerrando sesión...")
            break
        
        else:
            print("Opción inválida. Inténtelo de nuevo.")
