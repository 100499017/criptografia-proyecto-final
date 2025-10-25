# src/personal_vault.py
import os
import json
from crypto import CryptoManager
from asymmetric_crypto import AsymmetricCrypto

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

            # Generar claves para este archivo
            aes_key = self.crypto.generate_symmetric_key()
            hmac_key = self.crypto.generate_symmetric_key()

            # Cifrar archivo con AES
            encrypted_file = self.crypto.encrypt_aes(file_data, aes_key)

            # Generar HMAC para autenticación
            hmac_tag = self.crypto.generate_hmac(file_data, hmac_key)

            # Cifrar claves con RSA
            encrypted_aes_key = self.asymmetric_crypto.encrypt_with_public_key(aes_key, public_key)
            encrypted_hmac_key = self.asymmetric_crypto.encrypt_with_public_key(hmac_key, public_key)

            # Guardar
            filename = os.path.basename(file_path)
            file_info = {
                'filename': filename,
                'encrypted_aes_key': encrypted_aes_key,
                'encrypted_hmac_key': encrypted_hmac_key,
                'encrypted_data': encrypted_file,
                'hmac': hmac_tag
            }

            with open(f'{self.vault_dir}/{filename}.enc', 'w') as f:
                json.dump(file_info, f, indent=4)
            
            print(f"Archivo {filename} guardado en la bóveda.")
            print("\tCifrado: AES-256-CBC")
            print("\tAutenticación: HMAC-SHA256")
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def retrieve_file(self, filename, password, output_path):
        """Recupera archivo de bóveda personal"""
        try:
            # Cargar archivo cifrado
            with open(f'{self.vault_dir}/{filename}.enc', 'r') as f:
                file_info = json.load(f)
            
            # Cargar claves
            private_key = self._get_private_key(password)

            # Descifrar claves AES y HMAC
            aes_key = self.asymmetric_crypto.decrypt_with_private_key(file_info['encrypted_aes_key'], private_key)
            hmac_key = self.crypto.decrypt_data(file_info['encrypted_hmac_key'], private_key)

            # Descifrar archivo
            decrypted_data = self.crypto.decrypt_aes(file_info['encrypted_data'], aes_key)

            # Verificar autenticación con HMAC
            if not self.crypto.verify_hmac(decrypted_data, hmac_key, file_info['hmac']):
                print("Error: El archivo ha sido modificado o está corrupto")
                return False

            # Guardar archivo
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"Archivo '{filename}' recuperado con éxito.")
            return True
        
        except Exception as e:
            print(f"Error al recuperar archivo: {e}")
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
