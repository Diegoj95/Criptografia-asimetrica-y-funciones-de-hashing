# Criptografia Asimetrica y funciones de hashing

## Contenidos
- [Criptografia Asimetrica y funciones de hashing](#Criptografia-asimetrica-y-funciones-de-hashing)
  - [Contenidos](#contenidos)
  - [Descripción](#Descripción)
  - [Construido con](#Construido-con)
  - [Instalación de librerias](#Instalación-de-librerias)
  - [Autores](#Autores)
    

## Descripción

El [primer programa](#https://github.com/Diegoj95/Criptografia-asimetrica-y-funciones-de-hashing/blob/master/crear_llaves.py) debe crear un par de llaves asimétricas RSA para ambos integrantes del grupo.
Las parejas de llaves deben ser almacenadas en un archivo formato PEM y etiquetadas con el nombre de su dueño. Ejemplo: llave_privada_Alice.key y llave_publica_Alice. key (de manera equivalente para Bob)
Intercambien los archivos que contienen sus llaves públicas.

El [segundo programa](https://github.com/Diegoj95/Criptografia-asimetrica-y-funciones-de-hashing/blob/master/mensaje_cifrado.py) debe permitir que dos personas intercambien mensajes cifrados. Por simplicidad piense que usted es  Alice desee enviar un mensaje a su compañero Bob:
* Solicitar un texto desde teclado a Alice,
* Lee llave privada de Alice y llave pública de Bob
* Firma texto plano con llave privada de Alice. Escriba firma en un archivo  (Por ejemplo "Signature_Alice. sig")
* Genera una llave AES y cifra texto plano en modo CBC con AES (no cifre la firma) y escribe texto cifrado en un archivo. También escribe vector IV en un archivo (IV.iv)
* Cifra la llave AES con llave pública de Bob y almacena llave AES cifrada en otro archivo. (Ejemplo llave_AES_cifrada.key)

[Tercer programa](https://github.com/Diegoj95/Criptografia-asimetrica-y-funciones-de-hashing/blob/master/leer_archivos.py) debe leer varios archivos: archivo del mensaje, archivo con la firma del mensaje  llave pública del emisor (Alice) del mensaje, vector de inicialización, llave privada del destino (Bob) y llave AES cifrada.
Descifre llave AES cifrada con llave privada de Bob
Desencripte texto cifrado de Alice con llave AES
Verifique que el mensaje es genuino y señala si la firma es válida. Genere un archivo de prueba distinto al mensaje original para probar esta situación.
Solo si el mensaje es genuino, muestre el contenido del texto plano en pantalla


## Construido con

- Python

## Instalación de librerias

```python
python -m pip install --upgrade pip
```
```python
pip install cryptography
```

## Autores

* Diego Jiménez Muñoz - diego.jimenez1901@alumnos.ubiobio.cl
* Felipe Vásquez Araneda - felipe.vasquez1902@alumnos.ubiobio.cl
