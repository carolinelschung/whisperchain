# rbac.py - the gatekeeper that every protected endpoint calls, answering the questions of "who is this?" and "are they allowed to do this?"
import hashlib

from fastapi import HTTPException

from server.db import get_conn

# ---------- permission dictionary ----------
# each role maps to the actions only that role may do based on docs/rbac_matrix.md
permission_dict = dict()
permission_dict["Sender"] = ["request_token"]
permission_dict["Recipient"] = ["read_inbox", "flag_message"]
permission_dict["Moderator"] = ["view_flag_queue", "freeze_token", "view_audit_full", "view_audit_meta"]
permission_dict["Admin"] = ["assign_roles", "advance_round", "view_audit_meta"]

# ---------- functions ----------
# Hash a session token so the database never holds a usable token.
# (login in main.py uses this too, so the same hash is saved and looked up)
def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


# answers "who is this?" and checks the token with the stored hashed token
# if match is found, it loads that person's username and their roles from user_roles
# authorization_header is the text the client sent, which looks like: "Bearer abc123..."
def get_current_user(authorization_header):
    # no header, or not in the "Bearer <token>" form, means they aren't logged in
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="not logged in")

    # pull out the token - everything after "Bearer "
    token = authorization_header[len("Bearer "):]

    # look up the hash of the token in the sessions table
    conn = get_conn()
    session = conn.execute(
        "SELECT user_id FROM sessions WHERE token_hash = ?", (hash_token(token),)
    ).fetchone()

    # no matching session means the token is fake or old
    if session is None:
        conn.close()
        raise HTTPException(status_code=401, detail="not logged in")

    # else we know who it is, so get their id, username, and set of roles
    user = conn.execute(
        "SELECT id, username FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    role_rows = conn.execute(
        "SELECT role FROM user_roles WHERE user_id = ?", (user["id"],)
    ).fetchall()
    conn.close()

    roles = set()
    for row in role_rows:
        roles.add(row["role"])

    return {"id": user["id"], "username": user["username"], "roles": roles}


# permission - the name of the action the endpoint needs, like "request_token"
def require_permission(authorization_header, permission):
    user = get_current_user(authorization_header)

    # check each of the user's roles, and let them in as soon as one has the permission
    for role in user["roles"]:
        permission_list = permission_dict.get(role, [])
        for p in permission_list:
            if permission == p:
                return user

    # we only get here if none of their roles had it, so deny (deny by default)
    raise HTTPException(status_code=403, detail="not allowed")
