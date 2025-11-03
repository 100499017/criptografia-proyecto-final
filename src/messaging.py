# src/messaging.py
import os
import json
import uuid
from src.crypto import CryptoManager
from src.asymmetric_crypto import AsymmetricCrypto
from src.user_manager import UserManager

class MessagingSystem:
    def __init__(self):
        self.crypto = CryptoManager()
        self.asymmetric_crypto = AsymmetricCrypto()
        self.messages_dir = 'data/messages'
        
        os.makedirs(self.messages_dir, exist_ok=True)
    
    def _get_private_key(self, username, password):
        """Obtiene clave privada del usuario"""
        key_path = f'data/keys/{username}/private_key.pem'
        with open(key_path, 'rb') as f:
            private_pem = f.read()
        return self.asymmetric_crypto.load_private_key(private_pem, password)
    
    def _get_public_key(self, username):
        """Obtiene clave pública del usuario"""
        key_path = f'data/public_keys/{username}_public.pem'
        with open(key_path, 'rb') as f:
            public_pem = f.read()
        return self.asymmetric_crypto.load_public_key(public_pem)
    
    def send_file(self, sender, receiver, file_path, password, message=""):
        """Envía archivo a otro usuario"""
        try:
            # Verificar que el receptor existe
            if not UserManager().user_exists(receiver):
                print("Error: El usuario receptor no existe.")
                return False
            
            # Leer archivos
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Cargar claves
            sender_private_key = self._get_private_key(sender, password)
            receiver_public_key = self._get_public_key(receiver)

            # Generar clave AES para este archivo
            aes_key = self.crypto.generate_symmetric_key()

            # Cifrar archivo con AES-GCM
            encrypted_file = self.crypto.encrypt_aes_gcm(file_data, aes_key)

            # Cifrar la clave AES con RSA del receptor
            encrypted_aes_key = self.asymmetric_crypto.encrypt_with_public_key(aes_key, receiver_public_key)

            # Crear mensaje
            file_message = {
                'sender': sender,
                'filename': os.path.basename(file_path),
                'message': message,
                'encrypted_key': encrypted_aes_key,
                'encrypted_file': encrypted_file
            }

            # Guardar mensaje
            message_id = str(uuid.uuid4())
            receiver_dir = f'{self.messages_dir}/{receiver}'
            os.makedirs(receiver_dir, exist_ok=True)

            with open(f'{receiver_dir}/{message_id}.json', 'w') as f:
                json.dump(file_message, f, indent=4)
            
            # Mostrar detalles del envío al usuario
            print(f"Archivo enviado a {receiver}.")
            print("\tCifrado: AES-256-GCM (cifrado autenticado)")

            # Mostrar el resultado en un log
            print(f"--- Log de Envío de Archivo ---")
            print(f"Cifrado Utilizado: {self.crypto.key_size * 8}-bit AES-GCM")
            print(f"Clave Pública del Receptor: RSA-{self.asymmetric_crypto.key_size}-bit")
            print(f"--------------------------------")

            return True
            
        
        except Exception as e:
            print(f"Error al enviar archivo: {e}")
            return False
    
    def get_messages(self, username, password):
        """Obtiene mensajes recibidos"""
        try:
            user_dir = f'{self.messages_dir}/{username}'
            if not os.path.exists(user_dir) or not os.listdir(user_dir):
                print("No hay mensajes")
                return []
            
            messages = []
            for message_file in os.listdir(user_dir):
                try:
                    with open(f'{user_dir}/{message_file}', 'r') as f:
                        message_data = json.load(f)
                    
                    # Descifrar clave AES
                    private_key = self._get_private_key(username, password)
                    aes_key = self.asymmetric_crypto.decrypt_with_private_key(message_data['encrypted_key'], private_key)
                    
                    # Descifrar archivo (GCM verifica autenticación automáticamente)
                    try:
                        file_data = self.crypto.decrypt_aes_gcm(message_data['encrypted_file'], aes_key)
                        auth_success = True
                        auth_error = None
                    except Exception as e:
                        file_data = None
                        auth_success = False
                        auth_error = str(e)

                    # Mostrar el resultado en un log
                    print(f"--- Log de Recepción de Archivo ---")
                    print(f"Descifrado de claves con RSA-{self.asymmetric_crypto.key_size}-bit")
                    print(f"Descifrado de archivo con AES-{self.crypto.key_size * 8}-bit")
                    print(f"Autenticación: {'Válida' if auth_success else 'Inválida'}")
                    print(f"-----------------------------------")

                    # Guardar mensaje a la lista
                    messages.append({
                        'sender': message_data['sender'],
                        'filename': message_data['filename'],
                        'message': message_data['message'],
                        'file_data': file_data,
                        'auth_success': auth_success,
                        'auth_error': auth_error,
                        'message_file': message_file
                    })
                
                except Exception as e:
                    print(f"Error procesando mensaje {message_file}: {e}")
                    continue
                
            return messages
        
        except Exception as e:
            print(f"Error al obtener mensajes: {e}")
            return []
    
    def save_received_file(self, username, message, output_dir="downloads"):
        """Guarda archivo recibido"""
        try:
            os.makedirs(f"{output_dir}/{username}", exist_ok=True)
            output_path = f"{output_dir}/{username}/{message['filename']}"
            
            with open(output_path, 'wb') as f:
                f.write(message['file_data'])
            
            print(f"Archivo guardado como: {output_path}")
            return True
            
        except Exception as e:
            print(f"Error al guardar archivo: {e}")
            return False
    
    def delete_message_file(self, username: str, message_file: str) -> bool:
        """Elimina un archivo de mensaje específico"""
        try:
            file_path = f'{self.messages_dir}/{username}/{message_file}'
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
            return False
        except Exception as e:
            print(f"Error eliminando mensaje: {e}")
            return False
