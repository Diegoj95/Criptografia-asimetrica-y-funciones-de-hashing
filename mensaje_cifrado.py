""""Cifrando un mensaje con RSA y AES"""
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

def cargar_llave_publica(archivo):
    """Función para leer una clave pública desde un archivo"""
    with open(archivo, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def cargar_llave_privada(archivo):
    """Función para leer una clave privada desde un archivo"""
    with open(archivo, "rb") as archivo_llave:
        llave_privada = serialization.load_pem_private_key(
            archivo_llave.read(),
            password=None,
            backend=default_backend()
        )
    return llave_privada

def escribir_archivo(filename, data):
    """Función para escribir datos en un archivo"""
    with open(filename, "wb") as file:
        file.write(data)

def leer_archivo(filename):
    """Función para leer datos de un archivo"""
    with open(filename, "rb") as file:
        data = file.read()
    return data


USUARIO = 0
#Ingresar usuario
while(USUARIO<1 or USUARIO>2):
    USUARIO = int(input("Que usuario es?\n1.Diego\n2.Felipe\n"))

# Solicitar texto desde teclado a Diego
texto_plano = input("Ingresa el texto a cifrar: ")

# Rutas de los archivos
LLAVE_PRIVADA_DIEGO_FILE = "llave_privada_Diego.pem"
LLAVE_PUBLICA_DIEGO_FILE = "llave_publica_Diego.pem"

LLAVE_PRIVADA_FELIPE_FILE = "llave_privada_Felipe.pem"
LLAVE_PUBLICA_FELIPE_FILE = "llave_publica_Felipe.pem"

FIRMA_FILE_DIEGO = "Signature_Diego.sig"
FIRMA_FILE_FELIPE = "Signature_Felipe.sig"
TEXTO_CIFRADO_DIEGO = "texto_cifrado_de_Diego.txt"
TEXTO_CIFRADO_FELIPE = "texto_cifrado_de_Felipe.txt"
IV_FILE = "IV.iv"
LLAVE_AES_CIFRADA_FILE = "llave_AES_cifrada.key"

if USUARIO == 1:
    # Leer llave privada de Diego
    llave_privada_diego = cargar_llave_privada(LLAVE_PRIVADA_DIEGO_FILE)

# Leer llave pública de Diego
llave_publica_diego = cargar_llave_publica(LLAVE_PUBLICA_DIEGO_FILE)

if USUARIO == 2:
    # Leer llave privada de Felipe
    llave_privada_felipe = cargar_llave_privada(LLAVE_PRIVADA_FELIPE_FILE)

# Leer llave pública de Felipe
llave_publica_felipe = cargar_llave_publica(LLAVE_PUBLICA_FELIPE_FILE)

# Firmar texto plano con llave privada de correspondiente
if USUARIO == 1:
    firma = llave_privada_diego.sign(
    texto_plano.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    escribir_archivo(FIRMA_FILE_DIEGO, firma)
elif USUARIO ==2:
    firma = llave_privada_felipe.sign(
    texto_plano.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    escribir_archivo(FIRMA_FILE_FELIPE, firma)

# Generar una llave AES y cifrar texto plano en modo CBC con AES
llave_aes = os.urandom(32)

if os.path.exists("IV.iv"):
    print("El archivo IV.iv ya existe")
    iv = leer_archivo(IV_FILE)
else:
    iv = os.urandom(16)
cipher = Cipher(algorithms.AES(llave_aes), modes.CBC(iv), backend=default_backend())
ENCRYPTOR = cipher.encryptor()
texto_plano_padder = sym_padding.PKCS7(128).padder()
texto_plano_padded = texto_plano_padder.update(texto_plano.encode()) + texto_plano_padder.finalize()
texto_cifrado = ENCRYPTOR.update(texto_plano_padded) + ENCRYPTOR.finalize()

if USUARIO == 1:
    escribir_archivo(TEXTO_CIFRADO_DIEGO, texto_cifrado)
elif USUARIO == 2:
    escribir_archivo(TEXTO_CIFRADO_FELIPE, texto_cifrado)
escribir_archivo(IV_FILE, iv)

if USUARIO == 1:
    # Cifrar la llave AES con llave pública de Diego
    llave_aes_cifrada = llave_publica_felipe.encrypt(
    llave_aes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None))
    escribir_archivo(LLAVE_AES_CIFRADA_FILE, llave_aes_cifrada)
elif USUARIO == 2:
    # Cifrar la llave AES con llave pública de Felipe
    llave_aes_cifrada = llave_publica_diego.encrypt(
    llave_aes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None))
    escribir_archivo(LLAVE_AES_CIFRADA_FILE, llave_aes_cifrada)

print("El mensaje ha sido cifrado y los archivos generados:")
print("- Texto cifrado")
print("- Vector IV")
print("- Llave AES cifrada")
