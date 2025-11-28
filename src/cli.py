# src/cli.py
import os
import shutil
import time
from getpass import getpass
from src.auth import register_user, login_user
from src.user_manager import UserManager
from src.personal_vault import PersonalVault
from src.messaging import MessagingSystem
from src.asymmetric_crypto import AsymmetricCrypto
from src.digital_signature import DigitalSignature
from src.pki_manager import PKIManager

def setup_pki():
    """Configura la infraestructura PKI si no existe"""
    pki = PKIManager()

    # Crear CA raíz si no existe
    if not os.path.exists('data/pki/RootCA'):
        print("Configurando PKI...")
        pki.create_ca("RootCA", "root_password")
        print("Autoridad Certificadora Raíz creada.")

        # Crear subCA
        root_private_key = pki.load_private_key("RootCA", "root_password")
        root_cert = pki.load_ca_certificate("RootCA")
        pki.create_subca("SubCA", "RootCA", root_private_key, root_cert, "subca_password")
        print("Autoridad Certificadora Subordinada creada.")

def main_menu():
    """Muestra el menú principal y gestiona la entrada del usuario."""

    # Configura PKI al inicio
    setup_pki()

    while True:
        print("\n--- Menú Principal ---")
        print("1. Registrar usuario")
        print("2. Iniciar sesión")
        print("3. Gestionar PKI")
        print("4. Salir")
        print("5. Borrar todos los datos y salir")

        choice = input("Seleccione una opción: ")

        if choice == '1':
            username = input("Ingrese nombre de usuario: ")
            password = getpass("Ingrese contraseña: ")

            if register_user(username, password):
                print("\n[1/4] Usuario registrado en base de datos.")
                
                try:
                    # Generar par de claves RSA para el usuario
                    print("[2/4] Generando claves criptográficas RSA-2048...")
                    crypto = AsymmetricCrypto()
                    private_pem, public_pem = crypto.generate_keypair(password)

                    # Crear directorio de claves del usuario
                    os.makedirs(f'data/keys/{username}', exist_ok=True)

                    # Guardar claves
                    with open(f'data/keys/{username}/private_key.pem', 'wb') as f:
                        f.write(private_pem)
                    with open(f'data/public_keys/{username}_public.pem', 'wb') as f:
                        f.write(public_pem)
                    
                    # Generar CSR
                    print("[3/4] Generando Solicitud de Firma de Certificado (CSR)...")
                    pki = PKIManager()
                    private_key = crypto.load_private_key(private_pem, password)

                    csr = pki.generate_user_csr(private_key, username)

                    # Enviar CSR a la CA para que emita el certificado
                    print("[4/4] Enviando CSR a la SubCA para emisión de certificado...")
                    cert = pki.issue_certificate(csr, "SubCA", "subca_password")

                    # Guardar el certificado público resultante
                    user_manager = UserManager()
                    user_manager.save_user_certificate(username, cert)

                    print(f"\n¡Registro completado! Bienvenido, {username}.")

                except Exception as e:
                    print(f"\nError durante la generación de claves/certificados: {e}")
            else:
                print(f"\nEl registro falló (el usuario ya existe o datos inválidos).")

        elif choice == '2':
            username = input("Ingrese nombre de usuario: ")
            password = getpass("Ingrese contraseña: ")
            user = login_user(username, password)
            if user:
                # Si el login es exitoso, pasamos al menú del usuario
                user_menu(user, password)
        
        elif choice == '3':
            pki_menu()

        elif choice == '4':
            print("Saliendo del sistema. ¡Hasta luego!")
            break

        elif choice == '5':
            shutil.rmtree('data')
            shutil.rmtree('downloads')
            print("Todos los datos han sido borrados. ¡Hasta luego!")
            break

        else:
            print("Opción no válida. Inténtelo de nuevo.")

def pki_menu():
    """Menú de gestión de PKI"""
    pki = PKIManager()
    
    while True:
        print("\n--- Gestión PKI ---")
        print("1. Ver certificados de CA")
        print("2. Ver certificado de usuario")
        print("3. Volver al menú principal")
        
        choice = input("Seleccione opción: ")
        
        if choice == '1':
            print("\n--- Certificados de Autoridad ---")
            if os.path.exists('data/pki/RootCA/certificate.pem'):
                root_cert = pki.load_ca_certificate("RootCA")
                print("RootCA:")
                print(f"  Emisor: {root_cert.issuer}")
                print(f"  Válido hasta: {root_cert.not_valid_after_utc}")
            
            if os.path.exists('data/pki/SubCA/certificate.pem'):
                subca_cert = pki.load_ca_certificate("SubCA")
                print("SubCA:")
                print(f"  Emisor: {subca_cert.issuer}")
                print(f"  Válido hasta: {subca_cert.not_valid_after_utc}")
                
        elif choice == '2':
            username = input("Usuario: ")
            user_manager = UserManager()
            if user_manager.user_exists(username):
                try:
                    user_cert = user_manager.load_user_certificate(username)
                    print(f"\nCertificado de {username}:")
                    print(f"  Emisor: {user_cert.issuer}")
                    print(f"  Sujeto: {user_cert.subject}")
                    print(f"  Válido hasta: {user_cert.not_valid_after_utc}")
                except:
                    print("El usuario no tiene certificado.")
            else:
                print("Usuario no encontrado.")
                
        elif choice == '3':
            break
        else:
            print("Opción inválida")

def user_menu(username, password):
    """Muestra el menú para un usuario autenticado."""
    vault = PersonalVault(username)
    messaging = MessagingSystem()
    user_manager = UserManager()
    digital_signature = DigitalSignature()

    while True:
        print(f"\n--- Menú de {username} ---")
        print("1. Guardar archivo en mi bóveda")
        print("2. Recuperar archivo de mi bóveda")
        print("3. Eliminar archivo de mi bóveda")
        print("4. Listar mis archivos")
        print("5. Firmar archivo digitalmente")
        print("6. Verificar firma de archivo")
        print("7. Enviar archivo a otro usuario")
        print("8. Ver archivos recibidos")
        print("9. Listar usuarios")
        print("10. Cerrar sesión")

        choice = input("Seleccione una opción: ")

        if choice == '1':
            file_path = input("Ruta del archivo: ")
            vault_password = getpass("Su contraseña: ")
            if os.path.exists(file_path):
                vault.store_file(file_path, vault_password)
            else:
                print("El archivo no existe.")

        elif choice == '2':
            files = vault.list_files()
            if files:
                filename = input("Nombre del archivo: ")
                output_path = input("Ruta donde guardar: ")
                vault_password = getpass("Su contraseña: ")
                vault.retrieve_file(filename, vault_password, output_path)
        
        elif choice == '3':
            files = vault.list_files()
            if files:
                filename = input("Nombre del archivo: ")
                confirm = input(f"¿Está seguro de eliminar '{filename}'? (s/n): ")
                if confirm.lower() == 's':
                    vault.delete_file(filename)
                    print(f"Archivo '{filename}' eliminado con éxito.")
                else:
                    print("Eliminación cancelada.")
        
        elif choice == '4':
            vault.list_files()
        
        elif choice == '5':
            # Firmar archivo digitalmente
            file_path = input("Ruta del archivo a firmar: ")
            password = getpass("Su contraseña: ")
            
            if os.path.exists(file_path):
                # Cargar clave privada
                crypto = AsymmetricCrypto()
                key_path = f'data/keys/{username}/private_key.pem'
                with open(key_path, 'rb') as f:
                    private_pem = f.read()
                private_key = crypto.load_private_key(private_pem, password)
                
                # Firmar archivo
                signature = digital_signature.sign_file(file_path, private_key)
                
                # Guardar firma
                signature_path = file_path + '.sig'
                with open(signature_path, 'w') as f:
                    f.write(signature)
                
                print(f"Archivo firmado. Firma guardada en: {signature_path}")
            else:
                print("El archivo no existe.")
        
        elif choice == '6':
            # Verificar firma digital
            file_path = input("Ruta del archivo: ")
            signature_path = input("Ruta de la firma: ")
            target_user = input("Usuario que firmó: ")
            
            if os.path.exists(file_path) and os.path.exists(signature_path):
                # Cargar firma
                with open(signature_path, 'r') as f:
                    signature = f.read().strip()
                
                try:
                    # Obtener clave pública desde certificado
                    public_key = user_manager.get_public_key_from_certificate(target_user)
                    
                    # Verificar firma
                    if digital_signature.verify_file_signature(file_path, signature, public_key):
                        print("Firma digital verificada.")
                    else:
                        print("Firma digital no válida.")
                
                except Exception as e:
                    print(f"Error al verificar firma: {e}")
            else:
                print("Archivo o firma no encontrados.")

        elif choice == '7':
            receiver = input("Usuario destino: ")
            file_path = input("Ruta del archivo: ")
            message = input("Mensaje (opcional): ")
            password = getpass("Su contraseña: ")
            if os.path.exists(file_path):
                messaging.send_file(username, receiver, file_path, password, message)
            else:
                print("El archivo no existe")

        elif choice == '8':
            password = getpass("Su contraseña: ")
            messages = messaging.get_messages(username, password)

            for i, msg in enumerate(messages, 1):
                print(f"\n--- Mensaje {i} ---")
                print(f"De: {msg['sender']}")
                print(f"Archivo: {msg['filename']}")
                print(f"Mensaje: {msg['message']}")
                print(f"HMAC válido: {'Sí' if msg['auth_success'] else 'No'}")

                if msg['auth_success']:
                    save = input("¿Descargar archivo? (s/n)")
                    if save.lower() == 's':
                        messaging.save_received_file(username, msg)
                else:
                    print("No se puede descargar - Autenticación inválida")
                
                delete_msg = input("¿Eliminar este mensaje? (s/n): ")
                if delete_msg.lower() == 's':
                    if messaging.delete_message_file(username, msg['message_file']):
                        print("Mensaje eliminado.")
                    else:
                        print("Error al eliminar el mensaje.")
                else:
                    print("Mensaje conservado.")

        elif choice == '9':
            users = user_manager.list_users()
            print("\nUsuarios registrados:")
            for user in users:
                print(f"\t- {user}")
        
        elif choice == '10':
            print("Cerrando sesión...")
            break
        
        else:
            print("Opción inválida. Inténtelo de nuevo.")
