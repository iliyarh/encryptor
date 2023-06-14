import pyfiglet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import os
import json
from datetime import datetime

# Function to encrypt plaintext using AES-256 CBC
def encrypt(plaintext, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Function to decrypt ciphertext using AES-256 CBC
def decrypt(ciphertext, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext

# Function to write encrypted text in Base64 format to a file
def write_base64_file(base64_text):
    directory = "encrypted"
    if not os.path.exists(directory):
        os.makedirs(directory)

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"encrypted_text_base64_{timestamp}.txt"
    with open(os.path.join(directory, filename), "w") as file:
        file.write(base64_text)
    print("Encrypted text (Base64) saved to:", filename)

# Function to print big text
def print_big_text(text):
    ascii_art = pyfiglet.figlet_format(text)
    print(ascii_art)

# Load key and IV from config.json
def load_config():
    with open("config.json") as file:
        config = json.load(file)
        key = config.get("key", "").encode("utf-8")
        iv = config.get("iv", "").encode("utf-8")
    return key, iv

print_big_text("iliya RH Encryptor")
# Main loop
while True:
    print("\n1. Encrypt")
    print("2. Decrypt")
    print("0. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":  # Encrypt
        plaintext = input("Enter the text to encrypt: ")
        key, iv = load_config()

        ciphertext = encrypt(plaintext.encode('utf-8'), key, iv)
        base64_text = base64.b64encode(ciphertext).decode('utf-8')
        write_base64_file(base64_text)

    elif choice == "2":  # Decrypt
        ciphertext = input("Enter the ciphertext to decrypt: ")
        key, iv = load_config()

        ciphertext_bytes = base64.b64decode(ciphertext)
        decrypted_text = decrypt(ciphertext_bytes, key, iv)
        print("Decrypted text:", decrypted_text.decode('utf-8'))

    elif choice == "0":  # Exit
        break

    else:
        print("Invalid choice. Please try again.")

print("Program ended.")
