'''
El segundo programa debe permitir que dos personas intercambien mensajes cifrados. 
Por simplicidad piense que usted es  Alice desee enviar un mensaje a su compañero Bob:
1-Solicitar un texto desde teclado a Alice,
2-Lee llave privada de Alice y llave pública de Bob
3-Firma texto plano con llave privada de Alice. Escriba firma en un archivo  (Por ejemplo "Signature_Alice. sig")
4-Genera una llave AES y cifra texto plano en modo CBC con AES (no cifre la firma) y escribe texto cifrado en un archivo. También escribe vector IV en un archivo (IV.iv)
5-Cifra la llave AES con llave pública de Bob y almacena llave AES cifrada en otro archivo. (Ejemplo llave_AES_cifrada.key)
'''