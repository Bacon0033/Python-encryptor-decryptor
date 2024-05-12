from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

def get_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode())) # Can only use kdf once
    return key

def encrypt_message(message: str, password: str) -> dict:
    salt = os.urandom(16) # Generate a random 16-byte salt
    key = get_key(password, salt)
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return {
        'salt': salt.hex(), # Convert salt to hexadecimal for easier handling
        'encrypted_message': encrypted_message.hex() # Convert message to hexadecimal for easier handling
    }

def decrypt_message(encrypted_message: str, password: str, salt: str) -> str:
    salt = bytes.fromhex(salt) # Convert salt back from hexadecimal
    key = get_key(password, salt)
    encrypted_message = bytes.fromhex(encrypted_message) # Convert message back from hexadecimal
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

def main():
    action = input("Do you want to encrypt or decrypt? ")
    if action.lower() == "encrypt":
        message = input("Enter your message: ")
        password = input("Enter your password: ")
        result = encrypt_message(message, password)
        print(f"Your encrypted message is: {result['encrypted_message']}")
        print(f"Your salt is: {result['salt']}")
    elif action.lower() == "decrypt":
        password = input("Enter your password: ")
        salt = input("Enter your salt: ")
        encrypted_message = input("Enter your encrypted message: ")
        message = decrypt_message(encrypted_message, password, salt)
        print(f"Your decrypted message is: {message}")
    else:
        print("Invalid action. Please enter 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
