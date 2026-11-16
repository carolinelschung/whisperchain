# create_admin.py - creates a Moderator or Admin account. /register refuses these roles,
# so this script (run by whoever has the server's files) is the only way to make the first ones.
# Run from the project folder:
#   python -m server.create_admin <username> <password> <Moderator|Admin>
import os
import sys

from cryptography.hazmat.primitives import serialization

from common.crypto import generate_rsa_keypair, store_private_key
from server.db import get_conn, init_db
from server.passwords import hash_password

username, password, role = sys.argv[1], sys.argv[2], sys.argv[3]

if role not in ("Moderator", "Admin"):
    sys.exit("role must be Moderator or Admin")
if len(password) < 15:
    sys.exit("password must be at least 15 characters")

# a Moderator needs a real keypair, because recipients encrypt flagged messages to its public key.
# the private key is saved to keys/<username>.pem, protected by the account password.
# an Admin never decrypts anything, so a placeholder is enough
if role == "Moderator":
    private_key, public_key = generate_rsa_keypair()
    os.makedirs("keys", exist_ok=True)
    store_private_key(private_key, password, f"keys/{username}.pem")
    public_key_text = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
else:
    public_key_text = "none"

# same two inserts as /register, just with a role that /register doesn't allow
init_db()
salt = os.urandom(16).hex()
conn = get_conn()
cur = conn.execute(
    "INSERT INTO users (username, salt, password_hash, public_key) VALUES (?, ?, ?, ?)",
    (username, salt, hash_password(password, salt), public_key_text),
)
conn.execute("INSERT INTO user_roles (user_id, role) VALUES (?, ?)", (cur.lastrowid, role))
conn.commit()
conn.close()
print(f"created {role} '{username}'")
