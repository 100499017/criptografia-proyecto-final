# src/messaging.py
import os
import json
import uuid
import base64
from datetime import datetime
from src.crypto import CryptoManager
from src.asymmetric_crypto import AsymmetricCrypto
from src.user_manager import UserManager
from src.digital_signature import DigitalSignature

class MessagingSystem:
    def __init__(self):
        self.crypto = CryptoManager()
        self.asymmetric_crypto = AsymmetricCrypto()
        self.user_manager = UserManager()
        self.digital_signature = DigitalSignature()
        self.messages_dir = 'data/messages'
        
        os.makedirs(self.messages_dir, exist_ok=True)
    
    def _get_private_key(self, username, password):
        """Obtiene clave privada del usuario"""
        key_path = f'data/keys/{username}/private_key.pem'
        try:
            with open(key_path, 'rb') as f:
                private_pem = f.read()
            return self.asymmetric_crypto.load_private_key(private_pem, password)
        except Exception as e:
            print(f"Error cargando clave privada de {username}: {e}")
            return None
    
    def _get_public_key(self, username):
        """
        Intenta obtener la clave pública de un usuario desde su certificado.
        Si falla, la obtiene del archivo PEM.
        """
        return self.user_manager.get_public_key_from_certificate(username)
    
    def send_file(self, sender, receiver, file_path, password, message=""):
        """Envía archivo a otro usuario"""
        try:
            # Verificar que el receptor existe
            if not self.user_manager.user_exists(receiver):
                print(f"Error: El usuario destinatario {receiver} no existe.")
                return False
            
            # Verificar que el archivo existe
            if not os.path.exists(file_path):
                print("Error: El archivo a enviar no existe.")
                return False
            
            # Leer archivo
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Cargar claves
            sender_private_key = self._get_private_key(sender, password)
            if not sender_private_key:
                print("Error: Contraseña incorrecta o clave privada no encontrada.")
                return False

            receiver_public_key = self._get_public_key(receiver)
            if not receiver_public_key:
                print(f"Error: No se pudo obtener el certificado válido de {receiver}.")
                return False
            
            # Firmamos el archivo original antes de cifrarlo
            print("Firmando digitalmente el archivo...")
            signature = self.digital_signature.sign_data(file_data, sender_private_key)

            # Generar clave AES para este archivo
            aes_key = self.crypto.generate_symmetric_key()

            # Cifrar archivo con AES-GCM
            encrypted_file = self.crypto.encrypt_aes_gcm(file_data, aes_key)

            # Cifrar la clave AES con RSA del receptor
            encrypted_aes_key = self.asymmetric_crypto.encrypt_with_public_key(aes_key, receiver_public_key)

            # Crear mensaje
            file_message = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'sender': sender,
                'receiver': receiver,
                'filename': os.path.basename(file_path),
                'message': message,
                'encrypted_key': encrypted_aes_key,
                'encrypted_file': encrypted_file,
                'signature': signature
            }

            # Guardar mensaje
            receiver_dir = os.path.join(self.messages_dir, receiver)
            os.makedirs(receiver_dir, exist_ok=True)

            msg_path = os.path.join(receiver_dir, f'{file_message['id']}.json')
            with open(msg_path, 'w') as f:
                json.dump(file_message, f, indent=4)
            
            # Mostrar detalles del envío al usuario
            print(f"Archivo enviado a {receiver}.")

            # Mostrar el resultado en un log
            print(f"--- Log de Envío de Archivo ---")
            print(f"Cifrado Utilizado: {self.crypto.key_size * 8}-bit AES-GCM")
            print(f"Clave Pública del Receptor: RSA-{self.asymmetric_crypto.key_size}-bit")
            print(f"Firma Digital del Emisor: RSA-PSS")
            print(f"--------------------------------")

            return True
            
        
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
            return False
    
    def get_messages(self, username, password):
        """Obtiene mensajes recibidos"""
        try:
            user_dir = os.path.join(self.messages_dir, username)
            if not os.path.exists(user_dir) or not os.listdir(user_dir):
                print("No hay mensajes")
                return []
            
            messages = []
            for message_file in os.listdir(user_dir):
                if not message_file.endswith('.json'):
                    continue

                try:
                    msg_path = os.path.join(user_dir, message_file)
                    with open(msg_path, 'r') as f:
                        message_data = json.load(f)
                    
                    # Descifrar clave AES
                    private_key = self._get_private_key(username, password)
                    aes_key = self.asymmetric_crypto.decrypt_with_private_key(message_data['encrypted_key'], private_key)
                    
                    # Descifrar archivo (GCM verifica autenticación automáticamente)
                    file_data = self.crypto.decrypt_aes_gcm(message_data['encrypted_file'], aes_key)

                    if file_data is None:
                        print(f"Error: Fallo de integridad AES-GCM en mensaje de {message_data['sender']}. Mensaje corrupto.")
                        continue

                    # Verificar firma digital
                    sender = message_data['sender']
                    signature = message_data.get('signature')
                    is_signature_valid = False

                    if signature:
                        # Obtener clave pública del emisor desde su certificado
                        sender_public_key = self._get_public_key(sender)
                        if sender_public_key:
                            # Verificar que la firma corresponda al archivo descifrado
                            is_signature_valid = self.digital_signature.verify_signature(
                                file_data,
                                signature,
                                sender_public_key
                            )

                    # Mostrar el resultado en un log
                    print(f"--- Log de Recepción de Archivo ---")
                    print(f"Descifrado de claves con RSA-{self.asymmetric_crypto.key_size}-bit")
                    print(f"Descifrado de archivo con AES-{self.crypto.key_size * 8}-bit")
                    print(f"Firma digital RSA-PSS: {'Válida' if is_signature_valid else 'Inválida'}")
                    print(f"-----------------------------------")

                    # Guardar mensaje a la lista
                    messages.append({
                        'id': message_data['id'],
                        'sender': message_data['sender'],
                        'timestamp': message_data['timestamp'],
                        'filename': message_data['filename'],
                        'message': message_data['message'],
                        'file_data': file_data,
                        'auth_success': is_signature_valid,
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
