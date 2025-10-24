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

            # Generar y cifrar clave AES
            aes_key = self.crypto.generate_key()
            encrypted_aes_key = self.asymmetric_crypto.encrypt_with_public_key(aes_key, receiver_public_key)

            # Cifrar archivo
            encrypted_file = self.crypto.encrypt_data(file_data, aes_key)

            # Firmar mensaje
            message_data = f"{message}{os.path.basename(file_path)}".encode()
            signature = self.asymmetric_crypto.sign_data(message_data, sender_private_key)

            # Crear mensaje
            file_message = {
                'sender': sender,
                'filename': os.path.basename(file_path),
                'message': message,
                'encrypted_key': encrypted_aes_key,
                'encrypted_file': encrypted_file,
                'signature': signature
            }

            # Guardar mensaje
            message_id = str(uuid.uuid4())
            receiver_dir = f'{self.messages_dir}/{receiver}'
            os.makedirs(receiver_dir, exist_ok=True)

            with open(f'{receiver_dir}/{message_id}.json', 'w') as f:
                json.dump(file_message, f)
            
            print(f"Archivo enviado a {receiver}.")
            return True
        
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def get_messages(self, username, password):
        """Obtiene mensajes recibidos"""
        try:
            user_dir = f'{self.messages_dir}/{username}'
            if not os.path.exists(user_dir):
                print("No hay mensajes")
                return []
            
            messages = []
            for message_file in os.listdir(user_dir):
                if message_file.endswith('.json'):
                    with open(f'{user_dir}/{message_file}', 'r') as f:
                        message_data = json.load(f)
                    
                    # Descifrar archivo
                    private_key = self._get_private_key(username, password)
                    aes_key = self.asymmetric_crypto.decrypt_with_private_key(message_data['encrypted_key'], private_key)
                    file_data = self.crypto.decrypt_data(message_data['encrypted_file'], aes_key)
                    
                    # Verificar firma
                    sender_public_key = self._get_public_key(message_data['sender'])
                    message_to_verify = f"{message_data['message']}{message_data['filename']}".encode()
                    signature_valid = self.asymmetric_crypto.verify_signature(
                        message_to_verify, 
                        message_data['signature'], 
                        sender_public_key
                    )

                    messages.append({
                        'sender': message_data['sender'],
                        'filename': message_data['filename'],
                        'message': message_data['message'],
                        'file_data': file_data,
                        'signature_valid': signature_valid
                    })
                
            return messages
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def save_received_file(self, message, output_dir="downloads"):
        """Guarda archivo recibido"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            output_path = f"{output_dir}/{message['filename']}"
            
            with open(output_path, 'wb') as f:
                f.write(message['file_data'])
            
            print(f"Archivo guardado como: {output_path}")
            return True
            
        except Exception as e:
            print(f"Error: {e}")
            return False
