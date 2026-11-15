# main.py - the WhisperChain+ server. Run from the project folder with:
#   uvicorn server.main:app --reload
import hashlib
import hmac
import os
import secrets
import sqlite3

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from server.db import get_conn, init_db
from server.rbac import get_current_user, hash_token, require_permission

ITERATIONS = 600_000  # PBKDF2 rounds
SELF_REGISTER_ROLES = {"Sender", "Recipient"}  # Moderator and Admin can only be given by an Admin

app = FastAPI()
init_db()  # make sure the tables exist when the server starts


# ---------- helpers ----------

def hash_password(password, salt):
    """Turn a password and salt into a hash (hex text) using PBKDF2."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()


# ---------- what the client must send ----------

class RegisterRequest(BaseModel):
    username: str
    password: str
    roles: list[str]
    public_key: str


class LoginRequest(BaseModel):
    username: str
    password: str


class MessageRequest(BaseModel):
    token: str          # the anonymous token from /token/issue
    recipient: str      # username of who the message is for
    ciphertext: str     # the encrypted message (the server can't read it)
    wrapped_key: str    # the message's key, encrypted with the recipient's public key
    nonce: str


# ---------- endpoints ----------

@app.post("/register", status_code=201)
def register(req: RegisterRequest):
    # only Sender and Recipient are allowed here, and at least one is required
    roles = set(req.roles)
    if not roles or not roles <= SELF_REGISTER_ROLES:
        raise HTTPException(status_code=400, detail="roles must be Sender and/or Recipient")

    if len(req.password) < 15:
        raise HTTPException(status_code=400, detail="password must be at least 15 characters")

    # a new random salt for every user, then hash the password with it
    salt = os.urandom(16).hex()
    password_hash = hash_password(req.password, salt)

    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, salt, password_hash, public_key) VALUES (?, ?, ?, ?)",
            (req.username, salt, password_hash, req.public_key),
        )
    except sqlite3.IntegrityError:  # the username column is UNIQUE, so a repeat fails here
        conn.close()
        raise HTTPException(status_code=409, detail="username already taken")

    for role in roles:
        conn.execute("INSERT INTO user_roles (user_id, role) VALUES (?, ?)", (cur.lastrowid, role))
    
    conn.commit()
    conn.close()
    return {"username": req.username, "roles": sorted(roles)}


@app.post("/login")
def login(req: LoginRequest):
    conn = get_conn()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()

    # same 401 error for "no such user" and "wrong password" so nobody can guess usernames
    if user is None:
        conn.close()
        raise HTTPException(status_code=401, detail="bad username or password")
    attempt = hash_password(req.password, user["salt"])
    if not hmac.compare_digest(attempt, user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="bad username or password")

    # login worked: make a random session token, save its hash, give the token to the client
    token = secrets.token_hex(32)
    conn.execute("INSERT INTO sessions (token_hash, user_id) VALUES (?, ?)", (hash_token(token), user["id"]))
    conn.commit()
    conn.close()
    return {"session_token": token}


@app.get("/round")
def get_round(authorization: str = Header(default=None)):
    # any logged-in user may ask, no specific role needed
    get_current_user(authorization)

    conn = get_conn()
    round_id = conn.execute("SELECT round_id FROM current_round WHERE id = 1").fetchone()["round_id"]
    conn.close()
    return {"round_id": round_id}


@app.post("/token/issue")
def issue_token(authorization: str = Header(default=None)):
    # only a Sender may get a token
    user = require_permission(authorization, "request_token")

    conn = get_conn()
    round_id = conn.execute("SELECT round_id FROM current_round WHERE id = 1").fetchone()["round_id"]

    # record that this user got a token this round. (user_id, round_id) is the primary key,
    # so a second try in the same round fails here
    try:
        conn.execute("INSERT INTO token_issuance (user_id, round_id) VALUES (?, ?)", (user["id"], round_id))
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="you already got a token this round")

    # make the token and save only its hash. this row has no user id, so it can't be linked back
    token = secrets.token_hex(32)
    conn.execute("INSERT INTO valid_tokens (token_hash, round_id) VALUES (?, ?)", (hash_token(token), round_id))
    conn.commit()
    conn.close()
    return {"token": token, "round_id": round_id}


@app.post("/messages", status_code=201)
def send_message(req: MessageRequest):
    # NO login or role check here on purpose. the anonymous token is the only proof we ask for,
    # so the server never learns who is sending
    conn = get_conn()
    round_id = conn.execute("SELECT round_id FROM current_round WHERE id = 1").fetchone()["round_id"]

    # the token must exist, be unspent, not frozen, and be from this round
    # one generic error for every kind of bad token so nothing is revealed
    token_hash = hash_token(req.token)
    token = conn.execute("SELECT * FROM valid_tokens WHERE token_hash = ?", (token_hash,)).fetchone()
    if token is None or token["spent"] or token["frozen"] or token["round_id"] != round_id:
        conn.close()
        raise HTTPException(status_code=403, detail="invalid token")

    # the recipient must exist and have the Recipient role
    recipient = conn.execute(
        "SELECT u.id FROM users u JOIN user_roles r ON r.user_id = u.id "
        "WHERE u.username = ? AND r.role = 'Recipient'", (req.recipient,)
    ).fetchone()
    if recipient is None:
        conn.close()
        raise HTTPException(status_code=404, detail="no such recipient")

    # spend the token. "AND spent = 0" means if two requests race, only one can win
    spent = conn.execute("UPDATE valid_tokens SET spent = 1 WHERE token_hash = ? AND spent = 0", (token_hash,))
    if spent.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=403, detail="invalid token")

    # save the message with a random id. there is no sender anywhere in this row
    message_id = secrets.token_hex(16)
    conn.execute(
        "INSERT INTO messages (id, recipient_id, ciphertext, wrapped_key, nonce, round_id, token_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (message_id, recipient["id"], req.ciphertext, req.wrapped_key, req.nonce, round_id, token_hash),
    )
    conn.commit()
    conn.close()
    return {"message_id": message_id}


@app.get("/inbox")
def get_inbox(authorization: str = Header(default=None)):
    # only a Recipient may read an inbox, and they only ever see their own messages
    user = require_permission(authorization, "read_inbox")

    conn = get_conn()
    rows = conn.execute(
        "SELECT id, ciphertext, wrapped_key, nonce, round_id FROM messages WHERE recipient_id = ?",
        (user["id"],),
    ).fetchall()
    conn.close()

    # turn each database row into a plain dict so it can be sent back as JSON
    messages = []
    for row in rows:
        messages.append({
            "message_id": row["id"],
            "ciphertext": row["ciphertext"],
            "wrapped_key": row["wrapped_key"],
            "nonce": row["nonce"],
            "round_id": row["round_id"],
        })
    return messages
