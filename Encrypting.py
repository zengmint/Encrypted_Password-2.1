import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_password(password: str, encryption_key: bytes) -> dict:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_length = 16 - len(password) % 16
    padded_password = password + chr(pad_length) * pad_length
    encrypted_password = encryptor.update(padded_password.encode()) + encryptor.finalize()
    return {
        'ciphertext': base64.b64encode(encrypted_password).decode(),
        'iv': base64.b64encode(iv).decode()
    }

def decrypt_password(encrypted_data: dict, encryption_key: bytes) -> str:
    encrypted_password = base64.b64decode(encrypted_data['ciphertext'])
    iv = base64.b64decode(encrypted_data['iv'])
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
    pad_length = decrypted_password[-1]
    return decrypted_password[:-pad_length].decode()

def main():
    print("Bienvenido al gestor de cifrado de contraseñas")
    option = input("Elija una opción (1: Cifrar, 2: Descifrar): ")

    if option == '1':
        password = input("Ingrese la contraseña a cifrar: ")
        master_password = input("Ingrese una contraseña maestra: ")
        salt = os.urandom(16)
        key = generate_key(master_password, salt)
        encrypted_data = encrypt_password(password, key)
        print("Contraseña cifrada: ", encrypted_data['ciphertext'])
        print("Vector de inicialización (IV): ", encrypted_data['iv'])
        print("Salt: ", base64.b64encode(salt).decode())

    elif option == '2':
        encrypted_password = input("Ingrese la contraseña cifrada: ")
        iv = input("Ingrese el IV: ")
        salt = input("Ingrese el salt: ")
        master_password = input("Ingrese la contraseña maestra: ")
        salt = base64.b64decode(salt)
        key = generate_key(master_password, salt)
        encrypted_data = {'ciphertext': encrypted_password, 'iv': iv}
        try:
            decrypted_password = decrypt_password(encrypted_data, key)
            print("Contraseña descifrada: ", decrypted_password)
        except Exception as e:
            print("Error al descifrar la contraseña: ", e)

    else:
        print("Opción no válida")

if __name__ == "__main__":
    main()
