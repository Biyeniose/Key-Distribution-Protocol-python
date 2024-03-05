import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import os

def generate_keys_kdc():
    (pubkey, privkey) = rsa.newkeys(1024)
    with open('kdc_keys/pubkey.pem', 'wb') as f:
        f.write(pubkey.save_pkcs1("PEM"))

    with open('kdc_keys/privkey.pem', 'wb') as f:
        f.write(privkey.save_pkcs1("PEM"))

def generate_keys_alice():
    (pubkey, privkey) = rsa.newkeys(1024)
    with open('a_keys/pubkey.pem', 'wb') as f:
        f.write(pubkey.save_pkcs1("PEM"))

    with open('a_keys/privkey.pem', 'wb') as f:
        f.write(privkey.save_pkcs1("PEM"))

def generate_keys_bob():
    (pubkey, privkey) = rsa.newkeys(1024)
    with open('b_keys/pubkey.pem', 'wb') as f:
        f.write(pubkey.save_pkcs1("PEM"))

    with open('b_keys/privkey.pem', 'wb') as f:
        f.write(privkey.save_pkcs1("PEM"))

def a_load_keys():
    with open('a_keys/pubkey.pem', 'rb') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())

    with open('a_keys/privkey.pem', 'rb') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubkey, privkey

def b_load_keys():
    with open('b_keys/pubkey.pem', 'rb') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())

    with open('b_keys/privkey.pem', 'rb') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubkey, privkey

def kdc_load_keys():
    with open('kdc_keys/pubkey.pem', 'rb') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())

    with open('kdc_keys/privkey.pem', 'rb') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubkey, privkey

def encrypt(msg, key):
    return rsa.encrypt(msg.encode('utf-8'), key)
    #return rsa.encrypt(msg, key)

def decrypt(ciph, key):
    try:
        return rsa.decrypt(ciph, key).decode('utf-8')
    except Exception as e:
        return e
    
def generate_nonce(length=16):
    return os.urandom(length).hex()

def sign(msg, key):
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1')

def verify(msg, pub_key, sig):
    try:
        return rsa.verify(msg.encode('ascii'), sig, pub_key) == 'SHA-1'
    except:
        return False