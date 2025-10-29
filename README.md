# Sistema de Mensajería Segura

Este proyecto es un sistema de mensajería segura que permite a los usuarios registrar una cuenta, iniciar sesión, almacenar archivos en una bóveda personal y enviar archivos de forma segura a otros usuarios. Utiliza cifrado asimétrico (AES-256-CBC) y asimétrico (RSA-2048) junto con HMAC-SHA256 para autenticación, implementando el paradigma Encrypt-then-MAC para garantizar la integridad, la confidencialidad y la autenticidad de los datos.

## Características

- Registro e inicio de sesión de usuarios con almacenamiento seguro de contraseñas (Scrypt).
- Bóveda personal para almacenar archivos de forma cifrada.
- Envío de archivos a otros usuarios con cifrado end-to-end.
- Autenticación de mensajes con HMAC (Encrypt-then-MAC).
- Gestión de claves RSA para cada usuario.

## Esquema de seguridad implementado

### Para Mensajería:

- Cifrado: AES-256-CBC con claves de sesión únicas.
- Intercambio de claves: RSA-2048 con OAEP padding.
- Autenticación: HMAC-SHA256 sobre datos cifrados (Encrypt-then-MAC).
- Protección de claves: Claves RSA protegidas con contraseña.

### Para Almacenamiento Local:

- Cifrado: AES-256-CBC.
- Autenticación: HMAC-SHA256 sobre datos cifrados (Encrypt-then-MAC).
- Protección de claves: Claves cifradas con RSA del propietario.

## Instalación de dependencias

1. Clona el repositorio o descarga los archivos del proyecto.
   
2. Crea un entorno virtual (recomendado) y actívalo.
   ```bash
   python -m venv venv
   source venv/bin/activate # En Windows: venv\Scripts\activate
   ```

3. Instala las dependencias
   ```bash
   pip install -r requirements.txt
   ```

## Uso

1. Ejecuta el programa principal:
   ```bash
   python main.py
   ```

2. Sigue las opciones del menú:
   - **Registrar usuario**: Crea un nuevo usuario. Se generará un par de claves RSA protegidas por contraseña.
   - **Iniciar sesión**: Accede a tu cuenta.
   - **Salir**: Termina el programa.
   - **Borrar todos los datos y salir**: Elimina todos los datos del sistema (usuarios, claves, bóvedas, mensajes) y sale.
  
3. Una vez dentro de la sesión de usuario, puedes:
   - **Guardar archivo en tu bóveda**: Cifra y almacena un archivo en tu bóveda personal.
   - **Recuperar archivo de tu bóveda**: Descifra y recupera un archivo de tu bóveda.
   - **Listar tus archivos**: Muestra los archivos almacenados en tu bóveda.
   - **Enviar archivo a otro usuario**: Cifra y envía un archivo a otro usuario registrado.
   - **Ver archivos recibidos**: Lista los archivos que te han enviado y te da la opción de descargarlos.
   - **Listar usuarios**: Muestra todos los usuarios registrados.
   - **Cerrar sesión**: Vuelve al menú principal.

## Estructura de archivos

- `main.py`: Programa principal.
- `src/`: Contiene los módulos del sistema.
  - `auth.py`: Gestiona el registro y autenticación de usuarios.
  - `user_manager.py`: Gestiona la información de los usuarios.
  - `personal_vault.py`: Gestiona la bóveda personal de archivos.
  - `messaging.py`: Sistema de mensajería para enviar y recibir archivos.
  - `crypto.py`: Utilidades de cifrado simétrico y HMAC.
  - `asymmetric_crypto.py`: Utilidades de cifrado asimétrico.
  - `cli.py`:Interfaz de línea de comandos.
