import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import subprocess
import os
from multiprocessing import Process


files_list = []


def generate_key():
    pass_from_user = input("Please enter your password: ")
    password = pass_from_user.encode()
    mysalt = b'Xo)\xc3\x08Z\xcf\xc0!\xfd\x918\x10\xf4\xb8\xc8'

    kdf = PBKDF2HMAC (
        algorithm = hashes.SHA256,
        length = 32,
        salt = mysalt,
        iterations = 100000,
        backend = default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key
    
def encrypt_file(key):
    cipher = Fernet(key)
    
    for filename in os.listdir("."):
        if filename.endswith(".txt"):
            if (filename.find("encrypted")!=-1) or (filename == "README.txt"):
                continue
            
            files_list.append(filename)
            
            with open(filename, 'rb') as f:
                e_file = f.read()
                
            encrypted_file = cipher.encrypt(e_file)
            
            filename = filename[:filename.find(".txt")]
            filename = filename + "_encrypted.txt"

            with open(filename, 'wb') as ef:
                ef.write(encrypted_file)

def check_if_files_to_decrypt_exist():
    is_file_to_decrypt_found = 0
    for filename in os.listdir("."):
        if filename.endswith("_encrypted.txt"):
            is_file_to_decrypt_found = 1
            break
    return is_file_to_decrypt_found

def decrypt_file(key):
    cipher = Fernet(key)
    for filename in os.listdir("."):
        if filename.endswith("_encrypted.txt"):
            with open(filename, 'rb') as ef:
                encrypted_data = ef.read()
                
            decrypted_file = cipher.decrypt(encrypted_data)
            
            new_file_name = filename[:filename.find("_encrypted.txt")] + ".txt"

            with open(new_file_name, 'wb') as df:
                df.write(decrypted_file)
                
            files_list.append(new_file_name)
        
def erase_plaintext_files():
    for file_name in files_list:
        os.remove(file_name)

def erase_ciphertext_file():
    for file_name in files_list:
        with open(file_name, 'a') as file:
           file.close()

        with open(file_name, 'rb') as f:
            first_line = f.readline().decode().rstrip()
            
        file_to_remove = file_name[:file_name.find(".txt")] + "_encrypted.txt"
        os.remove(file_to_remove)


if __name__ == "__main__":
    user_request = input("Please type 'E' for Encryption, or 'D' for Decryption of the existing text files: ").lower()
    while (user_request != 'e') and (user_request != 'd'):
        user_request = input("Invalid option, try again please. \nPlease type 'E' for encryption, or 'D' for decryption: ").lower()
        
    if (user_request == 'd' and check_if_files_to_decrypt_exist() == 0):
        print("No files to decrypt were found in this folder.")
        exit()
        
    key = generate_key()
    
    if (user_request == 'e'):
        encrypt_file(key)
        erase_plaintext_files()
    elif (user_request == 'd'):
        process = Process(target=decrypt_file(key))
        process.start()
        process.join()
        erase_ciphertext_file()