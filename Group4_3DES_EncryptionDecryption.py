import os
import sys
from tqdm import tqdm
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding  # Used pkc7 to ensure blocks are padded to 8 byte lengths


# Setting up functions.
def file_path():
    """
    Requests file path from user, and verifies that path exists.
    """
    while True:
        path = input('Enter the file path to a valid file: \n\n').rstrip()  # remove trailing white space
        file_path = os.path.dirname(path) + '/'
        file_name = os.path.basename(path).split(".")[0]
        file_extension = '.' + os.path.basename(path).split(".")[-1]

        # Check if path is valid
        if os.path.exists(path):
            # Check file type matches input requirement
            if choice == 1 and file_extension == '.txt':
                break
            elif choice == 2 and file_extension == '.encrypted':
                break
            else:
                print("Something seems wrong. Please ensure the file type is correct")
        else:
            print("Something seems wrong. Please ensure that path is correct")

    return file_path, file_name, file_extension


def generate_key():
    """
    Generates a 24 byte key
    Adjusts the parity bits
    Saves it into a file.

    ValueError – if the TDES key is not 16 or 24 bytes long
    """
    while True:
        try:
            key = DES3.adjust_key_parity(get_random_bytes(24))
            break
        except ValueError:
            pass

    with open(file_path + file_name + '.key', "wb") as key_file:
        key_file.write(key)


def load_key():
    """
    Loads the key from the current directory named `{file_name}.key`
    """
    try:
        # Read the key from an external file
        with open(file_path + file_name + '.key', 'rb') as key_file:
            key = key_file.read()
        return key

    except FileNotFoundError:
        print(f"The key file {key_file} was not found.")
    except OSError as e:
        print(f"An error occurred while trying to read the key file: {e}")
    except UnicodeDecodeError as e:
        print(f"The key file is not a valid binary file: {e}")


def convert_to_blocks():
    """
    Takes in file as binary and splits into 8 byte chunks
    If padding required, padded to pkcs7
    Returns 8 byte blocks
    """
    with open(file_path + file_name + file_extension, 'rb') as file:
        data = file.read()
        # Add padding to the data
        padded_data = Padding.pad(data, 8, style='pkcs7')
        blocks = [padded_data[i:i+8] for i in range(0, len(padded_data), 8)]
    return blocks


def encrypt_file():
    """
    Given a filename (str) and key (bytes), it encrypts the file and saves an encrypted version
    """
    # Open plain text file & convert to 64 bit blocks
    blocks = convert_to_blocks()

    # Create a 3DES object and set the key
    # INFO: https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#eax-mode
    des3 = DES3.new(key, DES3.MODE_EAX)

    # Encrypted text as bytes
    ciphertext = b''
    for block in tqdm(blocks, desc="Encrypting: "):
        ciphertext += des3.encrypt(block)

    # Set nonce
    nonce = des3.nonce

    # Create a file with the encrypted text, [:-4] eliminates .txt from new name.
    with open(file_path + file_name + '.encrypted', 'wb') as file:
        file.write(ciphertext)
    with open(file_path + file_name + '.nonce', 'wb') as file:
        file.write(nonce)

    print(f'File has successfully been encrypted in DES3.MODE_EAX and saved as "{file_name}.encrypted".\n'
          f'Please keep safe "{file_name}.key" and "{file_name}.nonce", as they will be required for decryption')


def decrypt_file():
    """
    Given a filename (str) and key (bytes), it decrypts the file and saves an unencrypted version
    """
    with open(file_path + file_name + '.encrypted', 'rb') as file:
        ciphertext = file.read()

    with open(file_path + file_name + '.nonce', 'rb') as file:
        nonce = file.read()

    # Create a 3DES object and set the key
    des3 = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
    padded_data = des3.decrypt(ciphertext)

    # Remove the padding
    data = Padding.unpad(padded_data, 8, style='pkcs7')

    # Create a file with the decrypted text
    with open(file_path + file_name + '_decrypted.txt', 'w') as file:
        file.write(data.decode())

    print('File has successfully been decrypted.')


# Main Program
if __name__ == '__main__':
    open_text = '\nWelcome. Here you can encrypt plain text files (".txt") and decrypt those ending in ".encrypted".'
    user_input_text = '\nPlease select option:\n 1. Encryption\n 2. Decryption\n 3. Exit\n'
    user_input_error_text1 = 'That is not a valid option!'
    user_input_error_text2 = 'Non integer entered.'
    print(open_text, user_input_text)

    while True:  # Ensure only valid input is used.
        try:
            choice = int(input("Choose a option: "))
            if choice in [1, 2, 3]:
                break
            else:
                print(user_input_error_text1, user_input_text)
        except ValueError:
            print(user_input_error_text2, user_input_text)

    # Encryption
    if choice == 1:
        print("User has chosen: Encryption")
        try:
            file_path, file_name, file_extension = file_path()
            key = generate_key()
            key = load_key()
            encrypt_file()
        except Exception as e:
            print("An error occurred in encryption: ", e)

    # Decryption
    elif choice == 2:
        print("User has chosen: Decryption")
        print('\nPlease ensure that the key.key and .nonce files are located in the same location\n'
              'as the encrypted file.'
              'Please ensure the file to be decrypted ends in ".encrypted".\n')
        try:
            file_path, file_name, file_extension = file_path()
            key = load_key()
            decrypt_file()
        except Exception as e:
            print("An error occurred in decryption: ", e)

    # Exit
    else:
        sys.exit()
