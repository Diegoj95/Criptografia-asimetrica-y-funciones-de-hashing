'''
El segundo programa debe permitir que dos personas intercambien mensajes cifrados. 
Por simplicidad piense que usted es  Alice desee enviar un mensaje a su compañero Bob:
1-Solicitar un texto desde teclado a Alice,
2-Lee llave privada de Alice y llave pública de Bob
3-Firma texto plano con llave privada de Alice. Escriba firma en un archivo  (Por ejemplo "Signature_Alice. sig")
4-Genera una llave AES y cifra texto plano en modo CBC con AES (no cifre la firma) y escribe texto cifrado en un archivo. También escribe vector IV en un archivo (IV.iv)
5-Cifra la llave AES con llave pública de Bob y almacena llave AES cifrada en otro archivo. (Ejemplo llave_AES_cifrada.key)
'''
import os
from cryptography.hazmat.primitives import hashes, serialization
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
    with open(archivo, "rb") as archivo_llave:
        llave_privada = serialization.load_pem_private_key(
            archivo_llave.read(),
            password=None,
            backend=default_backend()
        )
    return llave_privada

# Función para escribir datos en un archivo
def escribir_archivo(filename, data):
    with open(filename, "wb") as file:
        file.write(data)

# Función para leer datos de un archivo
def leer_archivo(filename):
    with open(filename, "rb") as file:
        data = file.read()
    return data

usuario = 0
#Ingresar usuario
while(usuario<1 or usuario>2):
    usuario = int(input("Que usuario es?\n1.Diego\n2.Felipe\n"))
   

# Solicitar texto desde teclado a Diego
texto_plano = input("Ingresa el texto a cifrar: ")

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

# Leer llave privada de Diego
llave_privada_diego = cargar_llave_privada(llave_privada_diego_file)

# Leer llave pública de Diego
llave_publica_diego = cargar_llave_publica(llave_publica_diego_file)

# Leer llave privada de Felipe
llave_privada_felipe = cargar_llave_privada(llave_privada_felipe_file)

# Leer llave pública de Felipe
llave_publica_felipe = cargar_llave_publica(llave_publica_felipe_file)

# Firmar texto plano con llave privada de correspondiente
if(usuario == 1):
    firma = llave_privada_diego.sign(
    texto_plano.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    escribir_archivo(firma_file_Diego, firma)
elif(usuario ==2):
    firma = llave_privada_felipe.sign(
    texto_plano.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    escribir_archivo(firma_file_Felipe, firma)

# Generar una llave AES y cifrar texto plano en modo CBC con AES
llave_aes = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(llave_aes), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
texto_plano_padder = sym_padding.PKCS7(128).padder()
texto_plano_padded = texto_plano_padder.update(texto_plano.encode()) + texto_plano_padder.finalize()
texto_cifrado = encryptor.update(texto_plano_padded) + encryptor.finalize()
escribir_archivo(texto_cifrado_file, texto_cifrado)
escribir_archivo(iv_file, iv)

if(usuario == 1):
    # Cifrar la llave AES con llave pública de Diego
    llave_aes_cifrada = llave_publica_felipe.encrypt(
    llave_aes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
    escribir_archivo(llave_aes_cifrada_file, llave_aes_cifrada)
elif(usuario == 2):
    # Cifrar la llave AES con llave pública de Felipe
    llave_aes_cifrada = llave_publica_diego.encrypt(
    llave_aes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
    escribir_archivo(llave_aes_cifrada_file, llave_aes_cifrada)


print("El mensaje ha sido cifrado y los archivos generados:")
print("- Texto cifrado: {}".format(texto_cifrado_file))
print("- Vector IV: {}".format(iv_file))
print("- Llave AES cifrada: {}".format(llave_aes_cifrada_file))