# main.py - the WhisperChain+ server. Run from the project folder with:
#   uvicorn server.main:app --reload
import hmac
import json
import os
import secrets
import sqlite3

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from server.audit import check_log, log_event, read_log
from server.db import get_conn, init_db
from server.passwords import hash_password
from server.rbac import get_current_user, hash_token, require_permission

SELF_REGISTER_ROLES = {"Sender", "Recipient"}               # Moderator and Admin can only be given by an Admin
ALL_ROLES = {"Sender", "Recipient", "Moderator", "Admin"}
FLAG_THRESHOLD = 3                                          # this many flagged messages in one round raises an alert
FAILED_LOGIN_THRESHOLD = 5                                  # this many failed logins in a row raises an alert

app = FastAPI()
init_db()                                                   # make sure the tables exist when the server starts


# ---------- helpers ----------

def log_failed_login(conn):
    """Log a failed login, then raise an alert if the last few log records
    are all failed logins."""
    log_event(conn, "login_failed", "unknown")

    # this connection can already see the record we just added
    last_rows = conn.execute(
        "SELECT entry FROM audit_log ORDER BY log_id DESC LIMIT ?", (FAILED_LOGIN_THRESHOLD,)
    ).fetchall()
    if len(last_rows) < FAILED_LOGIN_THRESHOLD:
        return
    for row in last_rows:
        if json.loads(row["entry"])["event"] != "login_failed":
            return  # something else happened in between, so it isn't a streak

    log_event(conn, "alert_raised", "System", {"rule": "failed_logins", "count": FAILED_LOGIN_THRESHOLD})


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
    token: str                      # the anonymous token from /token/issue
    recipient: str                  # username of who the message is for
    ciphertext: str                 # the encrypted message (the server can't read it)
    wrapped_key: str                # the message's key, encrypted with the recipient's public key
    nonce: str

class RolesRequest(BaseModel):
    roles: list[str]


# the same message, re-encrypted by the recipient's client for the Moderator
class FlagRequest(BaseModel):
    mod_ciphertext: str
    mod_wrapped_key: str
    mod_nonce: str


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
    
    # log the event with the roles chosen, but not the username
    log_event(conn, "user_registered", ",".join(sorted(roles)))
    conn.commit()
    conn.close()
    return {"username": req.username, "roles": sorted(roles)}


@app.post("/login")
def login(req: LoginRequest):
    conn = get_conn()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()

    # same 401 error for "no such user" and "wrong password" so nobody can guess usernames.
    # a failed login is logged with no username and no role, so both cases look the same
    if user is None:
        log_failed_login(conn)
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="bad username or password")
    attempt = hash_password(req.password, user["salt"])
    if not hmac.compare_digest(attempt, user["password_hash"]):
        log_failed_login(conn)
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="bad username or password")

    # login worked: make a random session token, save its hash, give the token to the client
    token = secrets.token_hex(32)
    conn.execute("INSERT INTO sessions (token_hash, user_id) VALUES (?, ?)", (hash_token(token), user["id"]))

    # log the event with the account's roles, but not the username
    role_names = []
    for row in conn.execute("SELECT role FROM user_roles WHERE user_id = ?", (user["id"],)):
        role_names.append(row["role"])
    log_event(conn, "login_succeeded", ",".join(sorted(role_names)))
    conn.commit()
    conn.close()
    return {"session_token": token}


@app.get("/rounds/current")
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
    log_event(conn, "token_issued", "Sender")
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
    # no login here, so the role is recorded as a sender token being used, nothing more
    log_event(conn, "message_sent", "Sender (token)", {"message_id": message_id})
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


@app.get("/moderation/pubkey")
def get_moderator_pubkey(authorization: str = Header(default=None)):
    # any logged-in user may ask, since recipients need it to flag a message
    get_current_user(authorization)

    # with several Moderators we just use the one with the lowest id
    conn = get_conn()
    moderator = conn.execute(
        "SELECT u.public_key FROM users u JOIN user_roles r ON r.user_id = u.id "
        "WHERE r.role = 'Moderator' ORDER BY u.id LIMIT 1"
    ).fetchone()
    conn.close()
    if moderator is None:
        raise HTTPException(status_code=404, detail="no moderator exists")
    return {"public_key": moderator["public_key"]}


@app.get("/users/{username}/pubkey")
def get_user_pubkey(username: str, authorization: str = Header(default=None)):
    # any logged-in user may ask, since senders need it to encrypt a message
    get_current_user(authorization)

    # only users with the Recipient role can receive messages, so only they can be looked up
    conn = get_conn()
    user = conn.execute(
        "SELECT u.username, u.public_key FROM users u JOIN user_roles r ON r.user_id = u.id "
        "WHERE u.username = ? AND r.role = 'Recipient'",
        (username,),
    ).fetchone()
    conn.close()
    if user is None:
        raise HTTPException(status_code=404, detail="no such recipient")
    return {"username": user["username"], "public_key": user["public_key"]}


@app.post("/messages/{message_id}/flag")
def flag_message(message_id: str, req: FlagRequest, authorization: str = Header(default=None)):
    # only a Recipient may flag
    user = require_permission(authorization, "flag_message")

    # the message must exist AND be addressed to the caller. one error for both cases
    conn = get_conn()
    message = conn.execute(
        "SELECT id, round_id FROM messages WHERE id = ? AND recipient_id = ?", (message_id, user["id"])
    ).fetchone()
    if message is None:
        conn.close()
        raise HTTPException(status_code=404, detail="no such message")

    # message_id is the primary key of flags, so flagging the same message twice fails here
    try:
        conn.execute(
            "INSERT INTO flags (message_id, mod_ciphertext, mod_wrapped_key, mod_nonce) VALUES (?, ?, ?, ?)",
            (message_id, req.mod_ciphertext, req.mod_wrapped_key, req.mod_nonce),
        )
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="already flagged")

    conn.execute("UPDATE messages SET flagged = 1 WHERE id = ?", (message_id,))
    log_event(conn, "message_flagged", "Recipient", {"message_id": message_id})

    # count the flagged messages from the same round. this one is already included.
    # "==" and not ">=" so the alert fires once per round, not on every flag after it
    flagged_count = conn.execute(
        "SELECT COUNT(*) FROM messages WHERE flagged = 1 AND round_id = ?", (message["round_id"],)
    ).fetchone()[0]
    if flagged_count == FLAG_THRESHOLD:
        log_event(conn, "alert_raised", "System",
                  {"rule": "flags_per_round", "round_id": message["round_id"], "count": flagged_count})
    conn.commit()
    conn.close()
    return {"flagged": message_id}


@app.get("/moderation/queue")
def get_flag_queue(authorization: str = Header(default=None)):
    # only a Moderator may see flagged messages
    require_permission(authorization, "view_flag_queue")

    conn = get_conn()
    rows = conn.execute("SELECT message_id, mod_ciphertext, mod_wrapped_key, mod_nonce FROM flags").fetchall()
    conn.close()

    queue = []
    for row in rows:
        queue.append({
            "message_id": row["message_id"],
            "mod_ciphertext": row["mod_ciphertext"],
            "mod_wrapped_key": row["mod_wrapped_key"],
            "mod_nonce": row["mod_nonce"],
        })
    return queue


@app.post("/moderation/freeze/{message_id}")
def freeze_token(message_id: str, authorization: str = Header(default=None)):
    # only a Moderator may freeze a token
    require_permission(authorization, "freeze_token")

    # only flagged messages can be frozen, since those are the only ones a Moderator sees
    conn = get_conn()
    message = conn.execute("SELECT token_hash FROM messages WHERE id = ? AND flagged = 1", (message_id,)).fetchone()
    if message is None:
        conn.close()
        raise HTTPException(status_code=404, detail="no such flagged message")

    # mark that message's token as frozen.
    # (the token is already spent, so this is a record of abuse, not a block. see the report)
    conn.execute("UPDATE valid_tokens SET frozen = 1 WHERE token_hash = ?", (message["token_hash"],))
    log_event(conn, "token_frozen", "Moderator", {"message_id": message_id})
    conn.commit()
    conn.close()
    return {"frozen": message_id}


@app.patch("/users/{username}/roles")
def assign_roles(username: str, req: RolesRequest, authorization: str = Header(default=None)):
    # only an Admin may change roles
    admin = require_permission(authorization, "assign_roles")

    # the list must be non-empty and only contain the four real roles
    roles = set(req.roles)
    if not roles or not roles <= ALL_ROLES:
        raise HTTPException(status_code=400, detail="invalid roles")

    conn = get_conn()
    user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        conn.close()
        raise HTTPException(status_code=404, detail="no such user")

    # an Admin can't change their own roles, so they can't quietly make themselves a Moderator
    if user["id"] == admin["id"]:
        conn.close()
        raise HTTPException(status_code=403, detail="admins can't change their own roles")

    # replace the old roles with the new ones. roles are read from the database on every
    # request, so this takes effect right away
    conn.execute("DELETE FROM user_roles WHERE user_id = ?", (user["id"],))
    for role in roles:
        conn.execute("INSERT INTO user_roles (user_id, role) VALUES (?, ?)", (user["id"], role))
    # log the new roles only, not whose roles they are
    log_event(conn, "roles_changed", "Admin", {"new_roles": sorted(roles)})
    conn.commit()
    conn.close()
    return {"username": username, "roles": sorted(roles)}


@app.post("/admin/round/advance")
def advance_round(authorization: str = Header(default=None)):
    # only an Admin may move everyone on to the next round
    require_permission(authorization, "advance_round")

    # old tokens stop working (send_message checks the round), and Senders can get new ones
    conn = get_conn()
    conn.execute("UPDATE current_round SET round_id = round_id + 1 WHERE id = 1")
    round_id = conn.execute("SELECT round_id FROM current_round WHERE id = 1").fetchone()["round_id"]
    log_event(conn, "round_advanced", "Admin", {"round_id": round_id})
    conn.commit()
    conn.close()
    return {"round_id": round_id}


@app.post("/logout")
def logout(authorization: str = Header(default=None)):
    # must be logged in. this also checks the header is in the "Bearer <token>" form
    user = get_current_user(authorization)

    # delete this one session. the same token won't work again, but the user's other
    # sessions (for example a login on another computer) are left alone
    token = authorization[len("Bearer "):]
    conn = get_conn()
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
    log_event(conn, "logout", ",".join(sorted(user["roles"])))
    conn.commit()
    conn.close()
    return {"logged_out": True}


@app.get("/audit")
def get_audit_log(authorization: str = Header(default=None)):
    # only a Moderator may read the audit log
    require_permission(authorization, "view_audit_log")

    conn = get_conn()
    records = read_log(conn)
    conn.close()
    return records


@app.get("/audit/verify")
def verify_audit_log(authorization: str = Header(default=None)):
    # only a Moderator may run the check
    require_permission(authorization, "view_audit_log")

    # check_log gives back None if the log is intact, or the log_id of the first bad record
    conn = get_conn()
    bad_log_id = check_log(conn)
    conn.close()
    if bad_log_id is None:
        return {"ok": True}
    return {"ok": False, "first_bad_log_id": bad_log_id}
