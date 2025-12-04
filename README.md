# Bóveda Segura y Mensajería Cifrada

Este proyecto implementa una aplicación de seguridad en Python que ofrece:

1. **Bóveda Personal:** Cifrado de archivos locales para almacenamiento seguro (Data-at-Rest).

2. **Mensajería Segura:** Envío de archivos cifrados y firmados a otros usuarios (Data-in-Transit).

3. **Infraestructura PKI:** Gestión de certificados digitales X.509 con una jerarquía de confianza (Root CA -> Sub CA -> Usuario).

El sistema utiliza algoritmos modernos como **AES-256-GCM** (cifrado autenticado), **RSA-OAEP** (intercambio de claves), **RSA-PSS** (firma digital) y **Scrypt** (hashing de contraseñas).

## Requisitos Previos

- **Python 3.8** o superior instalado en tu sistema.

- **pip** (gestor de paquetes de Python).

- (Opcional) **Conda** si prefieres usar entornos de Anaconda/Miniconda.

## Instalación y Configuración del Entorno

Se recomienda encarecidamente utilizar un entorno virtual para aislar las dependencias del proyecto y evitar conflictos con otras librerías del sistema.

### Opción A: Usando `venv` (Estándar de Python)

1. **Crear el entorno virtual:** Abre una terminal en la carpeta raíz del proyecto y ejecuta:

```bash
# En Windows
python -m venv venv

# En macOS / Linux
python3 -m venv venv
```

2. **Activar el entorno:**

```bash
# En Windows
venv\Scripts\activate

# En macOS / Linux
source venv/bin/activate
```

Deberías ver `(venv)` al principio de tu línea de comandos.

3. **Instalar dependencias:**

```bash
pip install -r requirements.txt
```

### Opción B: Usando `conda`

1. **Crear el entorno:**

```bash
conda create --name boveda-segura python=3.9
```

2. **Activar el entorno:**

```bash
conda activate boveda-segura
```

3. **Instalar dependencias:**

```bash
pip install -r requirements.txt
```

## Cómo utilizar la aplicación

Una vez configurado el entorno, puedes iniciar la aplicación principal.

1. **Iniciar el programa**

Asegúrate de estar en la carpeta raíz del proyecto y ejecuta:

```bash
python main.py
```

2. **Flujo de Uso Recomendado**

Al iniciar, verás un menú principal. Sigue estos pasos para probar todas las funcionalidades:

   1. **Registrar Usuario (Opción 1):**

      - Crea un nuevo usuario (ej: `alice`).

      - El sistema generará automáticamente:

        - Un hash seguro de tu contraseña (Scrypt).

        - Un par de claves RSA (privada/pública).

        - Una solicitud de certificado (CSR).

        - Un certificado X.509 firmado por la SubCA local.

   2. **Iniciar Sesión (Opción 2):**

      - Ingresa con tus credenciales.

      - Accederás al **Panel de Usuario**.

   3. **Uso de la Bóveda Personal:**

      - Selecciona "Bóveda Personal" para cifrar un archivo local.

      - El archivo cifrado se guardará en `data/vault/alice/`.

      - Usa "Recuperar archivo" para descifrarlo y restaurarlo.

   4. **Mensajería Segura (Requiere 2 usuarios):**

      - Registra un segundo usuario (ej: `bob`) en otra terminal o reiniciando el programa.

      - Inicia sesión como `alice`.

      - Selecciona **"Enviar mensaje seguro"**.

      - Destinatario: `bob`.

      - El sistema validará el certificado de Bob, firmará tu archivo, lo cifrará y lo enviará.

      - Inicia sesión como `bob` y selecciona **"Ver buzón de entrada"** para recibir, descifrar y verificar la firma del mensaje.

## Ejecución de Pruebas (Testing)

El proyecto incluye una suite completa de pruebas unitarias y de integración para verificar la seguridad y robustez del código.

Para ejecutar todas las pruebas automáticamente:

```bash
python tests/run_tests.py
```

Esto verificará:

- Generación y cifrado de claves.

- Integridad de AES-GCM (detectando manipulaciones).

- Validez de firmas digitales RSA-PSS.

- Cadena de confianza de certificados PKI.

- Flujo completo de registro y mensajería.

## Estructura del Proyecto

- `src/`: Código fuente de la aplicación.

  - `cli.py`: Muestra los distintos menús y recibe los inputs del usuario.

  - `auth.py`: Gestión de usuarios y contraseñas (Scrypt).

  - `personal_vault.py`: Gestiona la bóveda personal de cada usuario.

  - `crypto.py`: Cifrado simétrico (AES-GCM).

  - `asymmetric_crypto.py`: Cifrado asimétrico (RSA-OAEP).

  - `digital_signature.py`: Firmas digitales (RSA-PSS).

  - `pki_manager.py`: Gestión de CAs y Certificados.

  - `messaging.py`: Lógica de envío y recepción segura.

- `data/`: Almacenamiento persistente (creado automáticamente).

  - `users.json`: Base de datos de usuarios.

  - `keys/`: Claves privadas cifradas.

  - `public_keys/`: Claves públicas.

  - `vault/`: Bóvedas personales.

  - `certificates/`: Certificados públicos.

  - `pki/`: Infraestructura de la CA.

  - `messages/`: Buzones de mensajes cifrados.

- `downloads/`: Contiene una carpeta para cada usuario, y cada una de esas carpetas contiene los archivos que el usuario ha descargado de los mensajes que ha recibido.

- `tests/`: Scripts de prueba (unittest).

  - `run_tests.py`: Ejecuta todos los tests automáticamente.

  - `test_asymmetric_crypto.py`: Prueba el módulo asymmetric_crypto.py.

  - `test_auth.py`: Prueba el módulo auth.py.

  - `test_crypto.py`: Prueba el módulo crypto.py.

  - `test_digital_signature.py`: Prueba el módulo digital_signature.py.

  - `test_pki.py`: Prueba el módulo pki_manager.py.

  - `test_user_manager.py`: Prueba el módulo user_manager.py.

  - `test_integration.py`: Prueba la integración de los distintos módulos.
