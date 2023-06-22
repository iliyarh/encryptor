from art import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import colorama
import base64
import os
import sys
import shutil
import time
import json
import secrets
from datetime import datetime
import platform
import requests

version = '1.2'

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
    print(color, ascii_art, colorama.Style.RESET_ALL)

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

# Get The Update Version
github_repo = "https://api.github.com/repos/iliyarh/encryptor/contents/main.py"
response = requests.get(github_repo)
data = response.json()

# Extract the content and decode it
content = data["content"]
content = base64.b64decode(content).decode("utf-8")

# Find the value of the version variable
version_line = next(line for line in content.splitlines() if line.startswith("version ="))
update_version = version_line.split("=")[1].strip().strip("'").strip('"')


def compare_files(local_file, github_file):
    with open(local_file, "r") as file:
        local_content = file.read()

    response = requests.get(github_file)
    github_content = response.text

    if local_content == github_content:
        print("The Program is up to date.")
    else:
        print("\U0001F514 There is an update available!: \U00002699 Version "+ update_version)
        confirm_update = input("Are you sure you want to update the Program? (yes/no): ")
        if confirm_update == 'yes':
            with open(local_file, "w") as file:
                file.write(github_content)
            print("Local file has been updated.")
        else:
            print('Update has been cancelled.')

# Function to update local Python file from GitHub
def update_python_file():
    github_repo = "https://raw.githubusercontent.com/iliyarh/encryptor/main/main.py"
    local_file = __file__

    if os.path.exists(local_file):
        compare_files(local_file, github_repo)

def restart_program():
    python = sys.executable
    os.execl(python, python, *sys.argv)


# Extract the content and decode it
content = data["content"]
content = base64.b64decode(content).decode("utf-8")

# Find the value of the version variable
version_line = next(line for line in content.splitlines() if line.startswith("version ="))
version = version_line.split("=")[1].strip().strip("'").strip('"')

# Initialize colorama
colorama.init()

clear_console()
print_big_text("iliya RH Encryptor")
print("\U00002699 Version: " + version)

if os.path.exists("Data"):
    print("The program is using existing Data.\n")
else:
    print("The program couldn't find any existing Data. It will create a new one if you encrypt a text.\n")

# Main loop
while True:
    print(colorama.Fore.GREEN, "1. \U0001F510 Encrypt", colorama.Style.RESET_ALL)
    if len(os.listdir('Data/encrypted')) > 0:
        print(colorama.Fore.RED, "2. \U0001F513 Decrypt", colorama.Style.RESET_ALL)
    if os.path.exists("Data/config.json"):
        print(colorama.Fore.YELLOW, "3. \U0001F4DD Show Config", colorama.Style.RESET_ALL)
        print(colorama.Fore.MAGENTA, "4. \U0001F4BE Reset Data", colorama.Style.RESET_ALL)
    print(colorama.Fore.CYAN, "5. \U0001F5D1  Clear Console", colorama.Style.RESET_ALL)
    print(colorama.Fore.WHITE, "6. \U0001F504 Update Program", colorama.Style.RESET_ALL)
    print(colorama.Fore.BLUE, "0. \U0001F6AA Exit", colorama.Style.RESET_ALL)

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

    elif choice == "2" and len(os.listdir('Data/encrypted')) > 0:  # Decrypt
        file_path = select_file()
        with open(file_path, "r") as file:
            ciphertext = file.read()
        key, iv = load_config()
    
        ciphertext_bytes = base64.b64decode(ciphertext)
        try:
            decrypted_text = decrypt(ciphertext_bytes, key, iv)
            print("Decrypted text:", decrypted_text.decode('utf-8'))
        except Exception as e:
            print("An error occurred during decryption:", str(e))

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
        print_big_text("iliya RH Encryptor")
        print("\U00002699 Version: " + version)

        if os.path.exists("Data"):
            print("The program is using existing Data.\n")
        else:
            print("The program couldn't find any existing Data. It will create a new one if you encrypt a text.\n")


    elif choice == "6":
        update_python_file()
        restart_program()

    elif choice == "0":  # Exit
        break

    else:
        print("Invalid choice. Please try again.\n")

print_big_text("Goodbye")
time.sleep(2)
