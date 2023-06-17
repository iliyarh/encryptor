from art import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import colorama
import base64
import os
import shutil
import time
import json
import secrets
from datetime import datetime
import platform

# Function to generate a random key
def generate_key():
    return secrets.token_bytes(32)

# Function to generate a random IV
def generate_iv():
    return secrets.token_bytes(16)

# Function to encrypt plaintext
def encrypt(plaintext, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Function to decrypt ciphertext
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
    ascii_art = text2art(text, font='standard')
    print(ascii_art)

# Function to write encrypted text to a file
def write_base64_file(base64_text, file_name):
    directory = "Data/encrypted"
    if not os.path.exists(directory):
        os.makedirs(directory)

    file_path = os.path.join(directory, file_name)
    with open(file_path, "w") as file:
        file.write(base64_text)
    print("Encrypted text saved to:", file_name)

# Load key and IV from config.json
def load_config():
    config_file = "Data/config.json"
    if os.path.exists(config_file):
        with open(config_file) as file:
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
    if not os.path.exists("Data"):
        os.makedirs("Data")
    with open(config_file, "w") as file:
        config = {"key": key.hex(), "iv": iv.hex()}
        json.dump(config, file)
    print("New config generated.")
    return key, iv

# Function to display encrypted files
def display_encrypted_files():
    directory = "Data/encrypted"
    if os.path.exists(directory):
        files = os.listdir(directory)
        if files:
            print("Encrypted files:")
            for i, file in enumerate(files, start=1):
                print(f"{i}. {file}")
            return False  # Files exist
    return True  # No files

# Function to select a file from the encrypted folder
def select_file():
    display_encrypted_files()
    while True:
        file_number = input("Select the file number to decrypt: ")
        directory = "Data/encrypted"
        files = os.listdir(directory)
        try:
            file_index = int(file_number) - 1
            if file_index >= 0 and file_index < len(files):
                file_name = files[file_index]
                file_path = os.path.join(directory, file_name)
                return file_path
            else:
                print("Invalid file number. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a valid file number.")

# Function to clear the console
def clear_console():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

# Initialize colorama
colorama.init()

print_big_text("iliya RH Encryptor")

if os.path.exists("Data"):
    print("The program is using existing Data.\n")
else:
    print("The program couldn't find any existing Data. It will create a new one if you encrypt a text.\n")

# Main loop
while True:
    print(colorama.Fore.GREEN, "1. Encrypt", colorama.Style.RESET_ALL)
    files_exist = display_encrypted_files()
    if os.path.exists("Data/config.json"):
        print(colorama.Fore.YELLOW, "3. Show Config", colorama.Style.RESET_ALL)
        print(colorama.Fore.MAGENTA, "4. Reset Data", colorama.Style.RESET_ALL)
    print(colorama.Fore.CYAN, "5. Clear Console", colorama.Style.RESET_ALL)
    print(colorama.Fore.BLUE, "0. Exit", colorama.Style.RESET_ALL)

    choice = input("Select an option: ")

    if choice == "1":  # Encrypt
        plaintext = input("Enter the plaintext to encrypt: ")
        key, iv = load_config()

        while True:
            file_name = input("Enter the file name: ")
            file_path = os.path.join("Data/encrypted", f"encrypted_text_{file_name}.iliyarh")
            if os.path.exists(file_path):
                print("File name already exists. Please choose a different name.")
            else:
                break

        ciphertext = encrypt(plaintext.encode('utf-8'), key, iv)
        base64_text = base64.b64encode(ciphertext).decode('utf-8')
        write_base64_file(base64_text, f"encrypted_text_{file_name}.iliyarh")

    elif choice == "2" and not files_exist:  # Decrypt
        file_path = select_file()
        with open(file_path, "r") as file:
            ciphertext = file.read()
        key, iv = load_config()

        ciphertext_bytes = base64.b64decode(ciphertext)
        decrypted_text = decrypt(ciphertext_bytes, key, iv)
        print("Decrypted text:", decrypted_text.decode('utf-8'))

    elif choice == "3":  # Show Key and IV
        key, iv = load_config()
        print("Key:", key.hex())
        print("IV:", iv.hex())

    elif choice == "4" and os.path.exists("Data/config.json"):  # Reset Key and IV
        confirmation = input("Are you sure you want to reset the Data? This will delete all the previous encrypted data. (yes/no): ")
        if confirmation.lower() == "yes":
            key = generate_key()
            iv = generate_iv()
            with open("Data/config.json", "w") as file:
                config = {"key": key.hex(), "iv": iv.hex()}
                json.dump(config, file)
            print("Data reset and new config generated.")
        else:
            print("Data reset aborted.")

    elif choice == "5":  # Clear Console
        clear_console()

    elif choice == "0":  # Exit
        break

    else:
        print("Invalid choice. Please try again.\n")

print_big_text("Goodbye")
time.sleep(2)
