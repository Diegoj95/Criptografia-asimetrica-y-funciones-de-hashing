"""El programa lee archivos de texto y llaves para desencriptar un mensaje cifrado con AES y RSA"""
import sys
from cryptography.hazmat.primitives import serialization, hashes
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
    with open(archivo, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def leer_archivo(archivo):
    """Función para leer datos de un archivo"""
    with open(archivo, "rb") as file:
        data = file.read()
    return data

def desencriptar_llave_aes(aes_key, felipe_priv_key):
    """Función para desencriptar la llave AES cifrada con la llave privada de Felipe"""
    print("Desencriptando la llave AES...")
    llave_privada_felipe = cargar_llave_privada(felipe_priv_key)
    llave_aes_cifrada = leer_archivo(aes_key)
    aes_key = llave_privada_felipe.decrypt(
        llave_aes_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def desencriptar_texto_cifrado(encrypted_text, vector, aes_key):
    """Función para desencriptar el texto cifrado con la llave AES"""
    print("Desencriptando el texto cifrado...")
    texto_cifrado = leer_archivo(encrypted_text)
    vector = leer_archivo(vector)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(vector), backend=default_backend())
    decryptor = cipher.decryptor()
    texto_plano_padded = decryptor.update(texto_cifrado) + decryptor.finalize()
    texto_plano_unpadder = sym_padding.PKCS7(128).unpadder()
    plain_text = texto_plano_unpadder.update(texto_plano_padded) + texto_plano_unpadder.finalize()
    return plain_text.decode()

def verificar_firma(plain_text, firma_file, diego_public_key):
    """Función para verificar la firma digital del mensaje"""
    print("Verificando la firma digital...")
    llave_publica_diego = cargar_llave_publica(diego_public_key)
    firma = leer_archivo(firma_file)
    try:
        llave_publica_diego.verify(
            firma,
            plain_text.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except SystemExit:
        return False

USUARIO = 0
#Identificar usuario
while(USUARIO<1 or USUARIO>2):
    USUARIO = int(input("Que usuario es?\n1.Diego\n2.Felipe\n"))

# Rutas de los archivos
LLAVE_PRIVADA_DIEGO_FILE = "llave_privada_Diego.pem"
LLAVE_PUBLICA_DIEGO_FILE = "llave_publica_Diego.pem"
LLAVE_PRIVADA_FELIPE_FILE = "llave_privada_Felipe.pem"
LLAVE_PUBLICA_FELIPE_FILE = "llave_publica_Felipe.pem"
FIRMA_FILE_DIEGO = "Signature_Diego.sig"
FIRMA_FILE_FELIPE = "Signature_Felipe.sig"
TEXTO_CIFRADO_FILE = "texto_cifrado.txt"
IV_FILE = "IV.iv"
LLAVE_AES_CIFRADA_FILE = "llave_AES_cifrada.key"

# Desencriptar la llave AES
try:
    if USUARIO == 1:
        llave_aes = desencriptar_llave_aes(LLAVE_AES_CIFRADA_FILE, LLAVE_PRIVADA_DIEGO_FILE)
    else:
        llave_aes = desencriptar_llave_aes(LLAVE_AES_CIFRADA_FILE, LLAVE_PRIVADA_FELIPE_FILE)
    print("Llave AES desencriptada.")
except SystemExit:
    print("ESTE MENSAJE NO ES PARA USTED, LE INVITO CORDIALMENTE A RETIRARSE")
    sys.exit()

# Desencriptar el texto cifrado
texto_plano = desencriptar_texto_cifrado(TEXTO_CIFRADO_FILE, IV_FILE, llave_aes)
print("Texto cifrado desencriptado:", texto_plano)

# Verificar la firma digital del mensaje
if USUARIO==1:
    VERIFICADO = verificar_firma(texto_plano, FIRMA_FILE_FELIPE, LLAVE_PUBLICA_FELIPE_FILE)
else:
    VERIFICADO = verificar_firma(texto_plano, FIRMA_FILE_DIEGO, LLAVE_PUBLICA_DIEGO_FILE)

if VERIFICADO:
    print("La firma digital es válida. El mensaje no ha sido modificado.")
else:
    print("La firma digital no es válida. El mensaje puede haber sido modificado.")
    