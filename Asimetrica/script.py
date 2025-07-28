#Se realiza la instalion de la libreria que se requiere para el cifrado y descifrado de mensajes.
# Para instalar la librería cryptography, puedes usar el siguiente comando:
# pip install cryptography
# Importar las librerías necesarias
#from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.asymmetric import rsa, padding
#from cryptography.hazmat.primitives import serialization
#from cryptography.hazmat.backends import default_backend    


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

# 1. Generar claves y guardarlas si no existen
def generar_claves():
    if not os.path.exists("clave_privada.pem") or not os.path.exists("clave_publica.pem"):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Guardar clave privada
        with open("clave_privada.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Guardar clave pública
        with open("clave_publica.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("🔐 Claves generadas y guardadas.")
    else:
        print("🔑 Las claves ya existen. No se generaron nuevas.")

# 2. Cargar clave pública desde archivo
def cargar_clave_publica():
    with open("clave_publica.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

# 3. Cargar clave privada desde archivo
def cargar_clave_privada():
    with open("clave_privada.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# 4. Cifrar mensaje con clave pública
def cifrar_mensaje(mensaje, clave_publica):
    return clave_publica.encrypt(
        mensaje.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# 5. Descifrar mensaje con clave privada
def descifrar_mensaje(mensaje_cifrado, clave_privada):
    return clave_privada.decrypt(
        mensaje_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# ==== EJECUCIÓN ====
generar_claves()

mensaje_original = "Este es un mensaje muy confidencial."

clave_publica = cargar_clave_publica()
clave_privada = cargar_clave_privada()

mensaje_cifrado = cifrar_mensaje(mensaje_original, clave_publica)
print("\n🔒 Mensaje cifrado (bytes):", mensaje_cifrado)

mensaje_descifrado = descifrar_mensaje(mensaje_cifrado, clave_privada)
print("\n🔓 Mensaje descifrado:", mensaje_descifrado)