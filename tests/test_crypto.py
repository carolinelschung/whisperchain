# Setup:
# cd whisperchain
# python -m venv .venv 
# source .venv/bin/activate
# pip install -r requirements.txt
# python -m tests.test_crypto

from cryptography.hazmat.primitives import serialization

from client.crypto import (
    generate_rsa_keypair,
    store_private_key,
    load_private_key,
    load_public_key,
    encrypt_message,
    decrypt_message
)

def test_generate_rsa_keypair():
    private_key, public_key = generate_rsa_keypair()
    assert private_key is not None
    assert public_key is not None
    assert isinstance(private_key, type(private_key))
    assert isinstance(public_key, type(public_key))

def test_store_and_load_private_key():
    private_key, _ = generate_rsa_keypair()
    password = "testpassword"
    filename = "test_private_key.pem"

    # Store the private key
    store_private_key(private_key, password, filename)

    # Load the private key
    loaded_private_key = load_private_key(password, filename)

    assert loaded_private_key is not None
    assert isinstance(loaded_private_key, type(private_key))
    assert loaded_private_key.private_numbers() == private_key.private_numbers()

def test_load_private_key_with_empty_password():
    private_key, _ = generate_rsa_keypair()
    password = "testpassword"
    filename = "test_private_key.pem"

    # Store the private key
    store_private_key(private_key, password, filename)

    try:
        load_private_key("", filename)
        assert False, "Expected ValueError for empty password"
    except ValueError as e:
        assert str(e) == "Password cannot be empty for private key loading."

def test_load_public_key():
    private_key, public_key = generate_rsa_keypair()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    loaded_public_key = load_public_key(pem_public_key)

    assert loaded_public_key is not None
    assert isinstance(loaded_public_key, type(public_key))
    assert loaded_public_key.public_numbers() == public_key.public_numbers()

def test_load_public_key_with_string():
    private_key, public_key = generate_rsa_keypair()
    pem_public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    loaded_public_key = load_public_key(pem_public_key_str)

    assert loaded_public_key is not None
    assert isinstance(loaded_public_key, type(public_key))
    assert loaded_public_key.public_numbers() == public_key.public_numbers()

def test_encrypt_message():
    private_key, public_key = generate_rsa_keypair()
    message = "Hello, this is a test message."

    encrypted_message, encrypted_key, nonce = encrypt_message(message, public_key)

    assert isinstance(encrypted_message, bytes)
    assert isinstance(encrypted_key, bytes)
    assert isinstance(nonce, bytes)


def test_decrypt_message():
    private_key, public_key = generate_rsa_keypair()
    message = "Hello, this is a test message."

    encrypted_message, encrypted_key, nonce = encrypt_message(message, public_key)

    decrypted_message = decrypt_message(encrypted_message, encrypted_key, nonce, private_key)

    assert decrypted_message == message
    


if __name__ == "__main__":
    test_generate_rsa_keypair()
    test_store_and_load_private_key()
    test_load_private_key_with_empty_password()
    test_load_public_key()
    test_load_public_key_with_string()
    test_encrypt_message()
    test_decrypt_message()
    print("All tests passed!")