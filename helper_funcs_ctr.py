from getpass import getpass
from pathlib import Path
from itertools import islice
from Crypto.Cipher import AES
from hashlib import sha256
import base64
from Crypto import Random


def decrypt_file(args):
    """
    Decrypts a certain .txt file, asks user for previously used enc_key
    :param args: Empty tuple
    :return: None
    """

    filename = Path(input("Enter absolute path to the file to decrypt: "))

    try:
        with open(filename, 'rb') as f:

            """Recreate the cipher used while encrypting the file contents"""
            key = getpass(
                "Input secret phrase that was used to encrypt the files: ")
            key = sha256(key.encode()).digest()
            nonce = bytes(input("Enter nonce used while encrypting the file: "))
            nonce = base64.b64decode(nonce)
            cipher_dec = AES.new(key, AES.MODE_CTR, nonce=nonce)

            enc_c = f.read()

            try:
                dec_c = cipher_dec.decrypt(enc_c)
            except (ValueError, KeyError):
                print("Incorrect data, key and/or nonce combination!")

        with open(filename, 'w') as f:
            f.write(dec_c.decode())

        print(f'File {filename} decrypted.')

    except FileNotFoundError:
        print(f'File at {filename} not found!')


def decrypt_folder(args):
    """
    Decrypts all .txt files in given folder with previously used enc_key
    :param args: Empty tuple
    :return: None
    """

    file_path = Path(input("Enter absolute path to the folder to decrypt: ")).rglob('*.txt')
    files = [x for x in file_path]

    if len(files) == 0:
        print("No .txt files in the folder!")
        return

    """Create AES cipher to use in decrypting results"""
    """Ask for encryption key to use and creates cipher based on it"""
    key = getpass("Input secret phrase that was used to encrypt the files: ")
    key = sha256(key.encode()).digest()
    nonce = input("Enter nonce used while encrypting the files: ").encode()
    nonce = base64.b64decode(nonce)
    cipher_dec = AES.new(key, AES.MODE_CTR, nonce=nonce)

    for file_path in files:
        with open(file_path, 'rb') as f:
            enc_c = f.read()
            dec_c = cipher_dec.decrypt(enc_c)

        with open(file_path, 'w') as f:
            f.write(dec_c.decode())

    print("Files decrypted.")


def encrypt_folder(filenames, enc_key):
    """
    Encrypts all files .txt in a folder
    :param filenames: List of files in the folder
    :param enc_key: Key to use in encryption
    :return: None
    """

    """Create new AES cipher to use in decrypting the files"""
    nonce = Random.get_random_bytes(16)
    cipher_enc = AES.new(enc_key, AES.MODE_CTR, nonce=nonce)

    for name in filenames:
        with open(name, "r") as file:
            file_c = file.read()
            enc_c = cipher_enc.encrypt(file_c.encode())

        with open(name, "wb") as file:
            file.write(enc_c)

    return f'Nonce generated: {base64.b64encode(nonce).decode("utf-8")}' \
           f'\nUse it when DECRYPTING the FILES!'


def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', print_end="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """

    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)

    """Print New Line on Complete"""
    if iteration == total:
        print()


def strip_word(word):
    """
    Simplifies a word by removing all special characters from it
    :param word: A word to simplify
    :return: The simplified word
    """

    return ''.join(e for e in word if e.isalnum()).lower()


def chunks(data, size):
    """
    Chops a dictionary into smaller chunks for easier multiprocessing
    :param data: A dictionary of a file's contents
    :param size: Size that the new dictionaries will be
    :return: Generator object to yield smaller dictionaries
    """

    it = iter(data)
    for i in range(0, len(data), size):
        yield {k: data[k] for k in islice(it, size)}
