'''
Tercer programa debe leer varios archivos: archivo del mensaje, archivo con la firma del mensaje  llave pública del emisor (Alice) del mensaje, 
vector de inicialización, llave privada del destino (Bob) y llave AES cifrada.
-Descifre llave AES cifrada con llave privada de Bob
-Desencripte texto cifrado de Alice con llave AES
-Verifique que el mensaje es genuino y señala si la firma es válida. Genere un archivo de prueba distinto al mensaje original para probar esta situación.
-Solo si el mensaje es genuino, muestre el contenido del texto plano en pantalla
'''

import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# Función para leer una clave pública desde un archivo
def cargar_llave_publica(archivo):
    with open(archivo, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

# Función para leer una clave privada desde un archivo
def cargar_llave_privada(archivo):
    with open(archivo, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

# Función para leer datos de un archivo
def leer_archivo(archivo):
    with open(archivo, "rb") as file:
        data = file.read()
    return data

# Función para desencriptar la llave AES cifrada con la llave privada de Felipe
def desencriptar_llave_aes(llave_aes_cifrada_file, llave_privada_felipe_file):
    print("Desencriptando la llave AES...")
    llave_privada_felipe = cargar_llave_privada(llave_privada_felipe_file)
    llave_aes_cifrada = leer_archivo(llave_aes_cifrada_file)
    llave_aes = llave_privada_felipe.decrypt(
        llave_aes_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return llave_aes

# Función para desencriptar el texto cifrado con la llave AES
def desencriptar_texto_cifrado(texto_cifrado_file, iv_file, llave_aes):
    print("Desencriptando el texto cifrado...")
    texto_cifrado = leer_archivo(texto_cifrado_file)
    iv = leer_archivo(iv_file)
    cipher = Cipher(algorithms.AES(llave_aes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    texto_plano_padded = decryptor.update(texto_cifrado) + decryptor.finalize()
    texto_plano_unpadder = sym_padding.PKCS7(128).unpadder()
    texto_plano = texto_plano_unpadder.update(texto_plano_padded) + texto_plano_unpadder.finalize()
    return texto_plano.decode()

# Función para verificar la firma digital del mensaje
def verificar_firma(texto_plano, firma_file, llave_publica_diego_file):
    print("Verificando la firma digital...")
    llave_publica_diego = cargar_llave_publica(llave_publica_diego_file)
    firma = leer_archivo(firma_file)
    try:
        llave_publica_diego.verify(
            firma,
            texto_plano.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

usuario = 0
#Identificar usuario
while(usuario<1 or usuario>2):
    usuario = int(input("Que usuario es?\n1.Diego\n2.Felipe\n"))

# Rutas de los archivos
llave_privada_diego_file = "llave_privada_Diego.pem"
llave_publica_diego_file = "llave_publica_Diego.pem"
llave_privada_felipe_file = "llave_privada_Felipe.pem"
llave_publica_felipe_file = "llave_publica_Felipe.pem"
firma_file_Diego = "Signature_Diego.sig"
firma_file_Felipe = "Signature_Felipe.sig"
texto_cifrado_file = "texto_cifrado.txt"
iv_file = "IV.iv"
llave_aes_cifrada_file = "llave_AES_cifrada.key"

# Desencriptar la llave AES
try:
    if(usuario == 1):
        llave_aes = desencriptar_llave_aes(llave_aes_cifrada_file, llave_privada_diego_file)
    
    else:
        llave_aes = desencriptar_llave_aes(llave_aes_cifrada_file, llave_privada_felipe_file)
    print("Llave AES desencriptada.")
except:
    print("ESTE MENSAJE NO ES PARA USTED, LE INVITO CORDIALMENTE A RETIRARSE")
    exit()



# Desencriptar el texto cifrado
texto_plano = desencriptar_texto_cifrado(texto_cifrado_file, iv_file, llave_aes)
print("Texto cifrado desencriptado:", texto_plano)

# Verificar la firma digital del mensaje
if(usuario==1):
    verificado = verificar_firma(texto_plano, firma_file_Felipe, llave_publica_felipe_file)
else:
    verificado = verificar_firma(texto_plano, firma_file_Diego, llave_publica_diego_file)

if verificado:
    print("La firma digital es válida. El mensaje no ha sido modificado.")
else:
    print("La firma digital no es válida. El mensaje puede haber sido modificado.")

