import pyfiglet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import colorama
import base64
import os
import json
import secrets
from datetime import datetime

# Function to generate a random key
def generate_key():
    return secrets.token_bytes(32)

# Function to generate a random IV
def generate_iv():
    return secrets.token_bytes(16)

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
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

# Function to print big text
def print_big_text(text, color=colorama.Fore.WHITE):
    ascii_art = pyfiglet.figlet_format(text)
    colored_ascii_art = color + ascii_art + colorama.Style.RESET_ALL
    print(colored_ascii_art)

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

# Load key and IV from config.json
def load_config():
    if os.path.exists("config.json"):
        with open("config.json") as file:
            try:
                config = json.load(file)
                key = bytes.fromhex(config.get("key", ""))
                iv = bytes.fromhex(config.get("iv", ""))
                if len(key) == 32 and len(iv) == 16:
                    return key, iv
                else:
                    print("Invalid key or IV length in config.json.")
            except json.JSONDecodeError:
                print("Invalid JSON data in config.json.")
    
    # Generate random key and IV if config.json doesn't exist or contains invalid data
    key = generate_key()
    iv = generate_iv()
    with open("config.json", "w") as file:
        config = {"key": key.hex(), "iv": iv.hex()}
        json.dump(config, file)
    return key, iv

# Initialize colorama
colorama.init()

print_big_text("iliya RH Encryptor")

# Main loop
while True:
    print(colorama.Fore.GREEN, "1. Encrypt", colorama.Style.RESET_ALL)
    print(colorama.Fore.RED, "2. Decrypt", colorama.Style.RESET_ALL)
    if os.path.exists("config.json"):
        print(colorama.Fore.YELLOW, "3. Show Key and IV", colorama.Style.RESET_ALL)
        print(colorama.Fore.MAGENTA, "4. Reset Key and IV", colorama.Style.RESET_ALL)
    print(colorama.Fore.BLUE, "0. Exit", colorama.Style.RESET_ALL)

    choice = input("Select an option: ")

    if choice == "1":  # Encrypt
        plaintext = input("Enter the plaintext to encrypt: ")
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

    elif choice == "3":  # Show Key and IV
        key, iv = load_config()
        print("Key:", key.hex())
        print("IV:", iv.hex())

    elif choice == "4" and os.path.exists("config.json"):  # Reset Key and IV
        confirmation = input("Are you sure you want to reset the Key and IV? This will make all previous encrypted data unreadable. (yes/no): ")
        if confirmation.lower() == "yes":
            key = generate_key()
            iv = generate_iv()
            with open("config.json", "w") as file:
                config = {"key": key.hex(), "iv": iv.hex()}
                json.dump(config, file)
            print("Key and IV reset. Previous encrypted data is no longer readable.")
        else:
            print("Key and IV reset cancelled.")

    elif choice == "0":  # Exit
        break

    else:
        print("Invalid choice. Please try again.")

print("Program ended.")
