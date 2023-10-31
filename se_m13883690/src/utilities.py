import secrets
from hashlib import sha256
from base64 import b64encode, b64decode
import os
import sys


def writeKeys(key, filename):
    hex_key = key.hex()  # Convert the bytes key to a hexadecimal string
    file_path = 'data/' + filename  # Adjust the file path
    with open(file_path, 'w') as file:
        file.write(hex_key)


def find_unique_words_and_files(folder_path):
    word_to_files = {}

    for root, _, files in os.walk(folder_path):
        for filename in files:
            with open(os.path.join(root, filename), 'r') as file:
                content = file.read()
                words = content.split()
                for word in set(words):
                    if word not in word_to_files:
                        word_to_files[word] = []
                    word_to_files[word].append(filename)

    return word_to_files
       

def readKeys(filename):
    file_path = 'data/' + filename  # Adjust the file path
    try:
        with open(file_path, 'r') as file:
            hex_key = file.read().strip()  # Read the hexadecimal key as a string
            key = bytes.fromhex(hex_key)  # Convert the hexadecimal string to bytes
        return key
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        return None


def generatekey(bits):
    # Generate a random 256-bit key
    if bits % 8 != 0:
        raise ValueError("Number of bits must be a multiple of 8")
    key = secrets.token_bytes(bits)
    return key


def printKey(sk):
    if sk:
        print(f'key:')
        hex_values = ' '.join([format(byte, '02X') for byte in sk])
        print(hex_values)

# Function to load plaintext from a file
def loadPlaintext():
    # Define the path to the plaintext file
    file_path = 'data/plaintext.txt'

    # Initialize an empty list to store the words
    word_array = []

    # Open the plaintext file for reading
    with open(file_path, 'r') as file:
        # Read the content of the file and split it into words
        words = file.read().split()

        # Add each word to the word_array
        word_array.extend(words)
    
    # Return the list of words from the plaintext file
    return word_array

# Function to load ciphertext from a file
def loadCiphertxt():
    # Define the path to the ciphertext file
    file_path = 'data/ciphertext.txt'

    try:
        # Try to open the ciphertext file for reading
        with open(file_path, "r") as file:
            # Read each line of the file into an array
            array = [line.strip() for line in file]
        return array
    except FileNotFoundError:
        # Handle the case where the file is not found
        print(f"File '{file_path}' not found.")
        return []

# Function to write ciphertext to a file
def writeCiphertxt(ciphertext):
    # Define the path to the output ciphertext file
    output_file_path = 'data/ciphertext.txt'
    with open(output_file_path, "w") as file:
        # Write each item in the ciphertext array to the file, one per line
        for item in ciphertext:
            file.write(str(item) + "\n")

# Function to write results to a file
def writeResults(plaintext):
    # Define the path to the output result file
    output_file_path = 'data/result.txt'
    with open(output_file_path, "w") as file:
        # Write each item in the plaintext array to the file, one per line
        for item in plaintext:
            file.write(str(item) + "\n")

# Function to perform a binary XOR operation on two binary strings
def binary_xor(str1, str2):
    return ''.join('1' if bit1 != bit2 else '0' for bit1, bit2 in zip(str1, str2))

# Function to perform OTP (One-Time Pad) encryption
def otp_encrypt(plaintext, secret_key):
    # Perform binary XOR between the plaintext and the secret key
    ciphertext = binary_xor(plaintext, secret_key)
    return ciphertext

# Function to convert text to binary representation
def text_to_binary(text):
    # Convert each character in the text to an 8-bit binary representation
    binary_result = ''.join(format(ord(char), '08b') for char in text)
    return binary_result

# Function to convert binary representation back to text
def binary_to_text(binary_str):
    text = ""
    # Convert binary back to characters, assuming 8-bit characters
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        text += chr(int(byte, 2))
    return text

def writekeys(keys):
    # Define the path to the output ciphertext file
    output_file_path = 'data/newkey.txt'
    with open(output_file_path, "w") as file:
        # Write each item in the ciphertext array to the file, one per line
        file.write(str(keys) + "\n")

# Function to pad the plaintext to match the block size
def pad(plaintext, block_size):
    padding_length = block_size - (len(plaintext) % block_size)
    padding = bytes([padding_length] * padding_length)
    return plaintext + padding