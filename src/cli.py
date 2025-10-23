# src/cli.py
import shutil
from getpass import getpass
from src.auth import register_user, login_user
import os
import json
from src.cifrado import cifrar_archivo, descifrar_archivo

def main_menu():
    """Muestra el menú principal y gestiona la entrada del usuario."""
    while True:
        print("\n--- Menú Principal ---")
        print("1. Registrar un nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Salir")
        print("4. Borrar carpeta /data y salir")

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
                user_menu(user, password)
        elif choice == '3':
            print("Saliendo de la aplicación. ¡Hasta luego!")
            break
        elif choice == '4':
            shutil.rmtree('data')
            print("Carpeta 'data' borrada. Saliendo de la aplicación. ¡Hasta luego!")
            break
        else:
            print("Opción no válida. Inténtelo de nuevo.")


def menu_subir_archivo(username, password):
    print("\n--- Subir archivo a la Bóveda ---")
    ruta_original = input("Ruta del archivo a subir: ")
    if not os.path.exists(ruta_original):
        print(f"Error: El archivo '{ruta_original}' no existe.")
        return

    nombre_guardado = input("Nombre para guardar en la bóveda: ")
    
    # Creamos la carpeta del usuario si no existe
    user_vault_path = os.path.join('data', 'vault', username)
    os.makedirs(user_vault_path, exist_ok=True)
    
    # Ruta final del archivo cifrado
    ruta_cifrada = os.path.join(user_vault_path, f"{nombre_guardado}.vault")

    try:
        # 1. Leer archivo original como bytes
        with open(ruta_original, 'rb') as f:
            datos_en_claro = f.read()

        # 2. Llamar a la función de cifrado. Usamos la contraseña del login como clave maestra
        print("Cifrando archivo...")
        paquete_cifrado = cifrar_archivo(password, datos_en_claro)

        # 3. Guardar el paquete (dict) como un archivo JSON
        with open(ruta_cifrada, 'w') as f:
            json.dump(paquete_cifrado, f, indent=4)
            
        print(f"¡Éxito! Archivo cifrado y guardado en '{ruta_cifrada}'")

    except Exception as e:
        print(f"Ha ocurrido un error durante el cifrado: {e}")

def menu_descargar_archivo(username, password):
    print("\n--- Descargar Archivo de la Bóveda ---")
    
    # Listamos los archivos en la bóveda del usuario
    user_vault_path = os.path.join('data', username)
    if not os.path.exists(user_vault_path) or not os.listdir(user_vault_path):
        print("Tu bóveda está vacía.")
        return
        
    print("Archivos en tu bóveda:")
    archivos = [f for f in os.listdir(user_vault_path) if f.endswith('.vault')]
    for i, f in enumerate(archivos):
        print(f"  {i+1}. {f}")
        
    try:
        choice = int(input("Selecciona el número del archivo a descargar: "))
        nombre_archivo_vault = archivos[choice-1]
    except (ValueError, IndexError):
        print("Selección no válida.")
        return

    ruta_cifrada = os.path.join(user_vault_path, nombre_archivo_vault)
    ruta_descifrada = input("Guardar archivo descifrado como (ej: 'mi_secreto.txt'): ")

    try:
        # 1. Leer el paquete JSON (texto)
        with open(ruta_cifrada, 'r') as f:
            paquete_cifrado = json.load(f)

        # 2. Llamar a la función de descifrado 
        print("Descifrando y verificando archivo...")
        datos_recuperados = descifrar_archivo(password, paquete_cifrado)

        # 3. Comprobar si el descifrado falló (Contraseña/MAC incorrecto)
        if datos_recuperados is None:
            # La función 'descifrar_archivo' ya imprimió el error
            return

        # 4. Guardar los datos recuperados (bytes)
        with open(ruta_descifrada, 'wb') as f:
            f.write(datos_recuperados)
            
        print(f"¡Éxito! Archivo descifrado y guardado en '{ruta_descifrada}'")

    except Exception as e:
        print(f"Ha ocurrido un error durante el descifrado: {e}")


def user_menu(username, password):
    """Muestra el menú para un usuario autenticado."""
    print(f"¡Bienvenido, {username}!")
    while True:
        print("\n--- Menú de Usuario ---")
        print("1. Subir un archivo a la bóveda")
        print("2. Eliminar un archivo de la bóveda")
        print("3. Descargar un archivo de la bóveda")
        print("4. Compartir un archivo")
        print("5. Cerrar sesión")

        choice = input("Seleccione una opción: ")

        if choice == '1':
            menu_subir_archivo(username, password)
        elif choice == '2':
            print("\n--- Eliminar Archivo de la Bóveda ---")
            nombre_archivo = input("Nombre del archivo a eliminar (con extensión .vault): ")
            ruta_archivo = os.path.join('data', 'vault', username, nombre_archivo)
            if os.path.exists(ruta_archivo):
                os.remove(ruta_archivo)
                print(f"Archivo '{nombre_archivo}' eliminado exitosamente.")
            else:
                print(f"Error: El archivo '{nombre_archivo}' no existe en tu bóveda, comprueba que lo hayas escrito correctamente y con la extensión (.vault).")
        elif choice == '3':
            menu_descargar_archivo(username, password)
        elif choice == '4':
            #menu_compartir_archivo(username, password)
            print("Funcionalidad de compartir archivo no implementada aún.")
        elif choice == '5':
            print("Cerrando sesión.")
            break
        else:
            print("Opción no válida. Inténtelo de nuevo.")
