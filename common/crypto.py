# sources: 
# RSA cryptography: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
# PEM key storage: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/ 
# updating file permissions: https://docs.python.org/3/library/os.html 
# AES encryption: https://cryptography.io/en/latest/hazmat/primitives/aead/

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_rsa_keypair():

    # recommended values for RSA encryption
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )

    public_key = private_key.public_key()

    return private_key, public_key

# Storing private key as password-protected PEM file
def store_private_key(private_key, password, filename):
    
    if not password: 
        raise ValueError("Password cannot be empty for private key storage.")

    pem_encrypted = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    with open(filename, 'wb') as f:
        f.write(pem_encrypted)
    
    # If the operating system is POSIX (Linux, macOS), set file permissions to read/write for the owner only
    if os.name == "posix":
        os.chmod(filename, 0o600)


# Load a password-protected private key from PEM file
def load_private_key(password, filename):
    
    if not password:
        raise ValueError("Password cannot be empty for private key loading.")

    with open(filename, 'rb') as f:
        pem_data = f.read()

    private_key = serialization.load_pem_private_key(
        data=pem_data,
        password=password.encode()
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Expected an RSA private key")

    return private_key


# Load an RSA public key from PEM bytes or a PEM string.
def load_public_key(public_key):

    # if public key provided as a string, convert it to bytes; if already bytes, use it directly
    if isinstance(public_key, bytes):
        pem_data = public_key
    elif isinstance(public_key, str):
        pem_data = public_key.encode()
    else:
        raise ValueError("Public key must be a PEM string or bytes.")

    # deserialize the public key from PEM format
    public_key = serialization.load_pem_public_key(pem_data)

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Expected an RSA public key")

    return public_key


# Encrypt a message using symmetric encryption: AES-256-GCM
# Encrypt the symmetric AES key with the recipient's RSA public key.
#
# Returns:
#     ciphertext, encrypted_key, nonce
def encrypt_message(message, public_key):

    if isinstance(public_key, (bytes, str)):
        public_key = load_public_key(public_key)
    
    # Generate a random 256-bit (32-byte) AES key for AES-256
    aes_key = os.urandom(32)

    # Generate a random 96-bit (12-byte) nonce for AES-GCM
    nonce = os.urandom(12)

    # Encrypt the message using AES-GCM
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

    # Encrypt the AES key using the recipient's RSA public key
    # OAEP padding added because it adds randomness to the encryption process, making it more secure against certain attacks
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext, encrypted_key, nonce


# Decrypt a message using the recipient's RSA private key and AES-256-GCM.
# Returns:
#     plaintext
def decrypt_message(ciphertext, encrypted_key, nonce, private_key):

    if isinstance(private_key, (bytes, str)):
        raise ValueError("Private key must be an RSA private key object, not bytes or string.")

    # Decrypt the AES key using the recipient's RSA private key
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the message using AES-GCM
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode()


# Sign data using an RSA private key
def sign_data(data, private_key):
    if isinstance(private_key, (bytes, str)):
        raise ValueError("Private key must be an RSA private key object, not bytes or string.")

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


# Verify an RSA signature
def verify_signature(data, signature, public_key):
    if isinstance(public_key, (bytes, str)):
        public_key = load_public_key(public_key)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False