# passwords.py - password hashing, used by the server (main.py) and by create_admin.py.
import hashlib

ITERATIONS = 600_000                                        # PBKDF2 rounds


def hash_password(password, salt):
    """Turn a password and salt into a hash (hex text) using PBKDF2."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()
