# helpers.py - small functions the server tests share (test_rbac.py).
# conftest.py holds the pytest functions, this file holds the plain helper functions.
import base64

from cryptography.hazmat.primitives import serialization

from common.crypto import encrypt_message, generate_rsa_keypair
from server.db import get_conn

PASSWORD = "a-long-test-password"       


# Make an RSA keypair. Returns the private key object and the public key as PEM text,
# which is the form the server stores and the client sends.
def new_keypair():
    private_key, public_key = generate_rsa_keypair()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_key, public_pem


# Register a client with given username and roles.
def register(client, username, roles, public_key):
    res = client.post("/register", json={
        "username": username, "password": PASSWORD, "roles": roles, "public_key": public_key,
    })
    assert res.status_code == 201


# Log in and return the headers to send with later requests
def login(client, username):
    res = client.post("/login", json={"username": username, "password": PASSWORD})
    assert res.status_code == 200
    return {"Authorization": "Bearer " + res.json()["session_token"]}


# Give a user exactly one role by editing the database directly
def set_roles(username, role):
    conn = get_conn()
    conn.execute(
        "UPDATE user_roles SET role = ? WHERE user_id = (SELECT id FROM users WHERE username = ?)",
        (role, username),
    )
    conn.commit()
    conn.close()


# an Admin can't register themselves, so add one straight to the database like create_admin.py does
def make_admin(client, username):
    register(client, username, ["Sender"], "none")
    set_roles(username, "Admin")


# Make a Moderator with a real keypair. 
# Returns the private key so a test can decrypt what a Recipient flags
def make_moderator(client, username):
    private_key, public_pem = new_keypair()
    register(client, username, ["Sender"], public_pem)
    set_roles(username, "Moderator")
    return private_key


# Register and log in a Sender and/or Recipient with a real keypair.
# Returns (headers, private_key)
def make_user(client, username, roles):
    private_key, public_pem = new_keypair()
    register(client, username, roles, public_pem)
    return login(client, username), private_key


# Turn encrypted bytes into text for sending. The client (client/client.py) uses Base64 for the
# ciphertext, wrapped key and nonce, so the tests do too
def to_text(data):
    return base64.b64encode(data).decode()


# Encrypt plaintext for the recipient and post it to /messages (no login header, token only).
# Returns the response
def send_message(client, token, recipient_public_key, recipient, plaintext):
    ciphertext, wrapped_key, nonce = encrypt_message(plaintext, recipient_public_key)
    return client.post("/messages", json={
        "token": token,
        "recipient": recipient,
        "ciphertext": to_text(ciphertext),
        "wrapped_key": to_text(wrapped_key),
        "nonce": to_text(nonce),
    })
