'''
El primer programa debe crear un par de llaves asimétricas RSA para ambos integrantes del grupo.
Las parejas de llaves deben ser almacenadas en un archivo formato PEM y etiquetadas con el nombre de su dueño. 
Ejemplo: llave_privada_Alice.key y llave_publica_Alice. key (de manera equivalente para Bob)
Intercambien los archivos que contienen sus llaves públicas
'''
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

# Creación de Llaves de Diego
llave_privada_Diego = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
llave_publica_Diego = llave_privada_Diego.public_key()
# Llaves en formato PEM
pem_llave_privada_Diego = llave_privada_Diego.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
pem_llave_publica_Diego = llave_publica_Diego.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")  
# Guardar llaves en archivos
with open('llave_privada_Diego.pem', 'wb') as myprivatekey:
    myprivatekey.write(pem_llave_privada_Diego)
with open('llave_publica_Diego.pem', 'w') as mypublickey:
    mypublickey.write(pem_llave_publica_Diego)

# Creación de llaves de Felipe
llave_privada_Felipe = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
llave_publica_Felipe = llave_privada_Felipe.public_key()
# Llaves en formato PEM
pem_llave_privada_Felipe = llave_privada_Felipe.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
pem_llave_publica_Felipe = llave_publica_Felipe.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
# Guardar llaves en archivos
with open('llave_privada_Felipe.pem', 'wb') as myprivatekey:
    myprivatekey.write(pem_llave_privada_Felipe)
with open('llave_publica_Felipe.pem', 'w') as mypublickey:
    mypublickey.write(pem_llave_publica_Felipe)
