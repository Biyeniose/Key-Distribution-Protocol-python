from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


def encrypt(plaintext, key):
    #key = b'This is a key123'
    # Ensure the key is the correct length, AES requires keys of 16, 24, or 32 bytes
    aes_cipher = AES.new(key, AES.MODE_ECB)
    # Pad the plaintext to be a multiple of the block size
    padded_plaintext = pad(plaintext, AES.block_size)
    # Encrypt
    ciphertext = aes_cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt(ciphertext, key):
    #key = b'This is a key123'
    aes_cipher = AES.new(key, AES.MODE_ECB)
    # Decrypt
    decrypted_padded_plaintext = aes_cipher.decrypt(ciphertext)
    # Unpad the plaintext
    plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
    return plaintext

def generate_nonce(length=16):
    return os.urandom(length).hex()