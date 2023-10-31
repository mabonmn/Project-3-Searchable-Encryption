from utilities import (
    writeKeys, readKeys, generatekey, printKey,find_unique_words_and_files,pad
)
import binascii

import os
import argparse
import sys
# Add the '../data' directory to the Python path, allowing you to import modules from there
os.sys.path.append('../data')
import hashlib
token_file_path = "data/token.txt"
index_file_path = "../data/index.txt"

import base64
from Crypto.Cipher import AES

def prf_encrypt(key, data):
    # Ensure both the key is in bytes format
    key_bytes = key.encode('utf-8') if isinstance(key, str) else key
    # Ensure the data is in bytes format
    data_bytes = data.encode('utf-8') if isinstance(data, str) else data
    # Create an HMAC object using SHA-256 as the hash function
    hmac = hashlib.new('sha256')
    # Set the key for the HMAC
    hmac.update(key_bytes)
    # Update the HMAC with the data to be encrypted
    hmac.update(data_bytes)
    # Get the PRF result
    prf_result = hmac.digest()
    
    return prf_result

def encrypt_keyword(keyword, sk):
    # Implement your PRF encryption here
    # This is a placeholder; you should replace this with your PRF encryption function
    encrypted_keyword = prf_encrypt(keyword, sk)
    return encrypted_keyword


def genKeys(bits, filename):
    sk = generatekey(bits)  # Generate a random key for AES or seed for PRF
    #printKey(sk)
    writeKeys(sk, filename)



def build_encrypted_index(folder_path, sk):
    unique_words_and_files = find_unique_words_and_files(folder_path)
    encrypted_index = {}

    for word, files in unique_words_and_files.items():
        encrypted_word = encrypt_keyword(word, sk)
        encrypted_files = [f"{i}" for i in files]
        encrypted_index[encrypted_word] = encrypted_files

    return encrypted_index
    
# Function to perform AES encryption in CBC mode
def aes_encrypt_block(block, key):
    # This example uses AES-256
    key_hash = hashlib.sha256(key).digest()  # Calculate SHA-256 hash of the key
    # Perform your AES encryption logic here (e.g., using bitwise operations)
    # For educational purposes, this example uses a simple XOR operation
    encrypted_block = bytes(x ^ y for x, y in zip(block, key_hash))
    return encrypted_block



def encrypt_aes_cbc(plaintext, key):
    block_size = 16  # AES block size is 16 bytes for AES-256
    plaintext = pad(plaintext.encode('utf-8'), block_size)
    ciphertext = b''

    prev_block = bytes(block_size)  # Initialize prev_block with all zeros

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        xor_block = bytes(x ^ y for x, y in zip(block, prev_block))
        encrypted_block = aes_encrypt_block(xor_block, key)
        ciphertext += encrypted_block
        prev_block = encrypted_block

    return ciphertext

def EncAES(sk1,f):
    printKey(sk1)


    print("PLAIN TEXT: ", f)

    c = encrypt_aes_cbc(f, sk1)
    print("CIPHERTEXT: ", c)


# Dictionary to map old names to new names
name_mapping = {"f1": "c1", "f2": "c2","f4": "c4", "f3": "c3","f5": "c5", "f6": "c6"}

def update_file_name(file_name):
    for old_name, new_name in name_mapping.items():
        file_name = file_name.replace(old_name, new_name)
    return file_name

def main():
    # For AES encryption, generate a 256-bit key
    filename_aes = 'skaes.txt'
    genKeys(256, filename_aes)
    # For PRF, generate an appropriate key or seed
    # If using AES-ECB-256, generate a 256-bit key
    filename_prf_aes = 'skprf.txt'
    genKeys(256, filename_prf_aes)


    sk1=readKeys(filename_aes)
    sk2=readKeys(filename_prf_aes)
    folder_path = 'data/files'
    unique_words_and_files = find_unique_words_and_files(folder_path)
    words = list(unique_words_and_files.keys())
    files = list(unique_words_and_files.values())
    encrypted_index = build_encrypted_index(folder_path, sk2)

    for word, encrypted_files in encrypted_index.items():
        # Convert the bytes word to a hexadecimal string
        hex_word = binascii.hexlify(word).decode('utf-8')

        print(f'Word: {hex_word}')
        print(f'Files it appears in: {", ".join(encrypted_files)}')
        print()
        # Write the encrypted index to a file

    # Sample list of file names
    data_directory = 'data/files'  # Replace with the path to your data directory
    ciphertext_directory = 'data/ciphertextfiles'
    # Function to update file names

    with open('data/index.txt', 'w') as index_file:
        for word, encrypted_files in encrypted_index.items():
            # Convert the bytes word to a hexadecimal string
            hex_word = binascii.hexlify(word).decode('utf-8')

            # Write the word and its associated files to the file
            index_file.write(f'Word: {hex_word}\n')
            index_file.write(f'Files it appears in: {", ".join(encrypted_files)}\n\n')
            for i in encrypted_files:
                new_file_name = update_file_name(i)
                file_name = os.path.join(ciphertext_directory, new_file_name)
                # Check if the file exists
                if not os.path.exists(file_name):
                    # If the file doesn't exist, create it and add the word
                    with open(file_name, "w") as file:
                        file.write(hex_word)
                    print(f"File '{file_name}' created and word added.")
                else:
                    # If the file already exists, append the word
                    with open(file_name, "a") as file:
                        file.write("\n" + hex_word)
                    print(f"Word appended to '{file_name}'.")
    
    w = "steelers"
    print("TOKENIZER :", w)
    if sk1:
        # Step 2: Generate a token based on the keyword and secret key
        # Here, we use a simple hash function as an example
        tk = hashlib.sha256(f"{w}{sk1}".encode()).hexdigest()

        # Step 3: Print the generated token to the terminal
        print(f"Generated Token: {tk}")

        # Step 4: Write the token to the token file
        try:
            with open(token_file_path, "w") as token_file:
                token_file.write(tk)
            print(f"Token saved to '{token_file_path}'.")
        except IOError:
            print(f"Error writing the token to '{token_file_path}'.")
    else:
        print("Token generation failed due to missing secret key.")
        
    # Read the token from the token file
    try:
        with open(token_file_path, "r") as token_file:
            token = token_file.read().strip()
    except FileNotFoundError:
        print(f"Token file '{token_file_path}' not found.")
        token = None
    if token:
        # Read the encrypted index file
        try:
            with open(index_file_path, "rb") as index_file:
                encrypted_index = base64.b64decode(index_file.read())
        except FileNotFoundError:
            print(f"Encrypted index file '{index_file_path}' not found.")
            encrypted_index = None

        if encrypted_index:
            # Decrypt the index using AES-CBC-256 encryption
            # You'll need the encryption key and IV for decryption
            # Replace 'encryption_key' and 'iv' with your actual values
            encryption_key = sk1# Replace with your key
            iv = token  # Replace with your IV

            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            decrypted_index = cipher.decrypt(encrypted_index).decode('utf-8')

            # Find files associated with the token
            associated_files = {}
            lines = decrypted_index.split('\n')
            current_file = None
            for line in lines:
                if line.startswith("c"):
                    current_file = line.strip()
                    associated_files[current_file] = []
                elif line:
                    associated_files[current_file].extend(line.split())

            # Print file identifiers and their contents
            for file_id, content in associated_files.items():
                print(file_id, " ".join(content))

        else:
            print("Failed to read or decrypt the index.")
    else:
        print("Token not found or could not be read.")

    
#---------------------------------------------------------------------------------------
# This calls the main function in order to run the code
# --------------------------------------------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()