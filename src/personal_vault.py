# src/personal_vault.py
import os
import json
from src.crypto import CryptoManager
from src.asymmetric_crypto import AsymmetricCrypto

class PersonalVault:
    def __init__(self, username: str):
        self.username = username
        self.crypto = CryptoManager()
        self.asymmetric_crypto = AsymmetricCrypto()
        self.vault_dir = f'data/vault/{username}'

        os.makedirs(self.vault_dir, exist_ok=True)
    
    def _get_private_key(self, password: str):
        """Obtiene clave privada RSA del usuario"""
        key_path = f'data/keys/{self.username}/private_key.pem'
        with open(key_path, 'rb') as f:
            private_pem = f.read()
        return self.asymmetric_crypto.load_private_key(private_pem, password)
    
    def store_file(self, file_path: str, password: str):
        """Almacena un archivo en la bóveda personal"""
        try:
            # Leer archivo
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Cargar claves del usuario
            private_key = self._get_private_key(password)
            public_key = private_key.public_key()

            # Generar clave AES única para este archivo
            aes_key = self.crypto.generate_symmetric_key()

            # Cifrar archivo con AES-GCM (incluye autenticación integrada)
            encrypted_file = self.crypto.encrypt_aes_gcm(file_data, aes_key)

            # Cifrar la clave AES con RSA
            encrypted_aes_key = self.asymmetric_crypto.encrypt_with_public_key(aes_key, public_key)

            # Guardar archivo cifrado
            filename = os.path.basename(file_path)
            file_info = {
                'filename': filename,
                'encrypted_key': encrypted_aes_key,
                'encrypted_data': encrypted_file
            }

            with open(f'{self.vault_dir}/{filename}.enc', 'w') as f:
                json.dump(file_info, f, indent=4)
            
            print(f"Archivo {filename} guardado en la bóveda.")
            print("\tCifrado: AES-256-GCM (cifrado autenticado)")

            # Eliminamos el archivo original para que solo quede el cifrado
            os.remove(file_path)

            return True
        
        except Exception as e:
            print(f"Error al guardar archivo: {e}")
            return False
    
    def retrieve_file(self, filename, password, output_path):
        """Recupera archivo de bóveda personal"""
        try:
            # Cargar archivo cifrado
            with open(f'{self.vault_dir}/{filename}.enc', 'r') as f:
                file_info = json.load(f)
            
            # Cargar claves
            private_key = self._get_private_key(password)

            # Descifrar clave AES
            aes_key = self.asymmetric_crypto.decrypt_with_private_key(file_info['encrypted_key'], private_key)
            
            # Descifrar archivo (GCM verifica autenticación automáticamente)
            try:
                decrypted_data = self.crypto.decrypt_aes_gcm(file_info['encrypted_data'], aes_key)
            except Exception as e:
                print(f"Error al descifrar archivo: {e}")
                return False

            # Guardar archivo
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"Archivo '{filename}' recuperado con éxito.")

            # Eliminar archivo cifrado
            os.remove(f'{self.vault_dir}/{filename}.enc')

            return True
        
        except Exception as e:
            print(f"Error al recuperar archivo: {e}")
            return False
    
    def delete_file(self, filename: str) -> bool:
        """Elimina un archivo de la bóveda personal"""
        try:
            file_path = f'{self.vault_dir}/{filename}.enc'
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Archivo '{filename}' eliminado de la bóveda.")
                return True
            else:
                print("Error: El archivo no existe en la bóveda.")
                return False
        except Exception as e:
            print(f"Error al eliminar archivo: {e}")
            return False
    
    def list_files(self):
        """Lista archivos en bóveda"""
        files = []
        for file in os.listdir(self.vault_dir):
            if file.endswith('.enc'):
                files.append(file[:-4]) # Quitar .enc
        
        if not files:
            print("No hay archivos en la bóveda.")
        else:
            print("Archivos en bóveda:")
            for file in files:
                print(f"\t- {file}")
        
        return files
