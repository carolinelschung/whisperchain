# test_rbac.py - checks that each role can only do what docs/rbac_matrix.md says it can
import json
import pytest

import server.db
from common.crypto import encrypt_message
from helpers import PASSWORD, login, make_admin, make_moderator, make_user, register, send_message, set_roles
from server.db import get_conn
from server.rbac import hash_token

ROLES = ["Sender", "Recipient", "Moderator", "Admin"]

# a valid body for the flag endpoint. FastAPI checks the body before our code runs,
# so without one a denied request would get a 422 instead of the 403 we want to see
FLAG_BODY = {"mod_ciphertext": "aa", "mod_wrapped_key": "bb", "mod_nonce": "cc"}

# (method, path, body, the one role allowed to call it) with one row per protected endpoint
ENDPOINTS = [
    ("POST", "/token/issue", None, "Sender"),
    ("GET", "/inbox", None, "Recipient"),
    ("POST", "/messages/fakeid/flag", FLAG_BODY, "Recipient"),
    ("GET", "/moderation/queue", None, "Moderator"),
    ("POST", "/moderation/freeze/fakeid", None, "Moderator"),
    ("GET", "/audit", None, "Moderator"),
    ("GET", "/audit/verify", None, "Moderator"),
    ("PATCH", "/users/alice/roles", {"roles": ["Sender"]}, "Admin"),
    ("POST", "/admin/round/advance", None, "Admin"),
]


# one logged-in user for each role, returned as {role: headers}
# the public key is a placeholder because none of these tests encrypt anything
@pytest.fixture
def people(client):
    register(client, "alice", ["Sender"], "none")
    register(client, "bob", ["Recipient"], "none")
    register(client, "mod", ["Sender"], "none")
    set_roles("mod", "Moderator")
    make_admin(client, "addy")
    return {
        "Sender": login(client, "alice"),
        "Recipient": login(client, "bob"),
        "Moderator": login(client, "mod"),
        "Admin": login(client, "addy"),
    }


# every endpoint: the allowed role gets in, and every other role gets 403
@pytest.mark.parametrize("method, path, body, allowed", ENDPOINTS, ids=[e[1] for e in ENDPOINTS])
def test_only_the_allowed_role_gets_in(client, people, method, path, body, allowed):
    for role in ROLES:
        res = client.request(method, path, headers=people[role], json=body)
        if role == allowed:
            # must not be a denial
            assert res.status_code not in (401, 403), f"{role} should be allowed on {method} {path}"
        else:
            assert res.status_code == 403, f"{role} should get 403 on {method} {path}"


# every endpoint: no login header at all means 401, not 403
@pytest.mark.parametrize("method, path, body, allowed", ENDPOINTS, ids=[e[1] for e in ENDPOINTS])
def test_no_header_is_401(client, method, path, body, allowed):
    res = client.request(method, path, json=body)
    assert res.status_code == 401


def test_bad_token_is_401(client):
    res = client.get("/inbox", headers={"Authorization": "Bearer faketoken"})
    assert res.status_code == 401


# an Admin could otherwise quietly make themselves a Moderator
def test_admin_cannot_change_their_own_roles(client, people):
    res = client.patch("/users/addy/roles", headers=people["Admin"], json={"roles": ["Moderator"]})
    assert res.status_code == 403


# an action is allowed if any of the user's roles allows it
def test_user_with_two_roles_gets_both_sets_of_actions(client):
    register(client, "sender_and_recipient", ["Sender", "Recipient"], "none")
    headers = login(client, "sender_and_recipient")
    assert client.post("/token/issue", headers=headers).status_code == 200      # Sender action
    assert client.get("/inbox", headers=headers).status_code == 200             # Recipient action
    assert client.get("/moderation/queue", headers=headers).status_code == 403  # neither role allows this


# a role change takes effect on the very next request, with no new login
def test_role_change_takes_effect_immediately(client, people):
    assert client.get("/moderation/queue", headers=people["Sender"]).status_code == 403
    res = client.patch("/users/alice/roles", headers=people["Admin"], json={"roles": ["Moderator"]})
    assert res.status_code == 200
    assert client.get("/moderation/queue", headers=people["Sender"]).status_code == 200


# ---------- tokens and inbox (these use full_flow from conftest.py: alice sent one message to bob) ----------

# count the rows in a table, to check nothing extra was saved
def count_rows(table):
    conn = get_conn()
    n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    conn.close()
    return n


# a token is one use only
def test_double_spent_token_is_rejected(client, full_flow):
    bob_key = client.get("/users/bob/pubkey", headers=full_flow["sender"]).json()["public_key"]
    res = send_message(client, full_flow["token"], bob_key, "bob", "a second message")
    assert res.status_code == 403
    assert count_rows("messages") == 1


# going through the API: a Recipient flags, then a Moderator freezes the token of that message
def test_freezing_marks_the_token_frozen_and_logs_it(client, full_flow):
    make_moderator(client, "mod")
    mod = login(client, "mod")

    res = client.post(f"/messages/{full_flow['message_id']}/flag", headers=full_flow["recipient"], json=FLAG_BODY)
    assert res.status_code == 200
    res = client.post(f"/moderation/freeze/{full_flow['message_id']}", headers=mod)
    assert res.status_code == 200

    conn = get_conn()
    row = conn.execute(
        "SELECT frozen FROM valid_tokens WHERE token_hash = ?", (hash_token(full_flow["token"]),)
    ).fetchone()
    conn.close()
    assert row["frozen"] == 1

    events = [record["entry"]["event"] for record in client.get("/audit", headers=mod).json()]
    assert "token_frozen" in events


# freezing only works on a token that is already spent, so the API can't make a token that is
# frozen and unused. we set frozen straight in the database to check that submit refuses it
def test_frozen_token_is_rejected_on_submit(client):
    sender, _ = make_user(client, "alice", ["Sender"])
    _, _ = make_user(client, "bob", ["Recipient"])
    bob_key = client.get("/users/bob/pubkey", headers=sender).json()["public_key"]
    token = client.post("/token/issue", headers=sender).json()["token"]

    conn = get_conn()
    conn.execute("UPDATE valid_tokens SET frozen = 1 WHERE token_hash = ?", (hash_token(token),))
    conn.commit()
    conn.close()

    res = send_message(client, token, bob_key, "bob", "hello")
    assert res.status_code == 403
    assert count_rows("messages") == 0


# a Recipient can only see and flag their own messages
def test_wrong_recipient_cannot_read_or_flag_a_message(client, full_flow):
    dave, _ = make_user(client, "dave", ["Recipient"])

    assert client.get("/inbox", headers=dave).json() == []
    res = client.post(f"/messages/{full_flow['message_id']}/flag", headers=dave, json=FLAG_BODY)
    assert res.status_code == 404

    # bob still has his message, and dave's failed flag changed nothing
    inbox = client.get("/inbox", headers=full_flow["recipient"]).json()
    assert [m["message_id"] for m in inbox] == [full_flow["message_id"]]
    assert count_rows("flags") == 0


# an Admin can never read message content, even once a message has been flagged
def test_admin_gets_403_on_content(client, full_flow):
    res = client.post(f"/messages/{full_flow['message_id']}/flag", headers=full_flow["recipient"], json=FLAG_BODY)
    assert res.status_code == 200

    make_admin(client, "addy")
    admin = login(client, "addy")
    for path in ("/inbox", "/moderation/queue", "/audit"):
        assert client.get(path, headers=admin).status_code == 403, f"Admin should get 403 on {path}"


# ---------- what a database dump reveals ----------

# the whole database file as raw bytes, which is what someone who stole the file would have
def db_bytes():
    with open(server.db.DB_FILE, "rb") as f:
        return f.read()


# the names of the columns in a table
def column_names(table):
    conn = get_conn()
    names = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    conn.close()
    return names


# full_flow plus the rest of the story: bob flags the message (re-encrypted for the Moderator,
# like a real client would), and someone fails to log in under a name that doesn't exist
@pytest.fixture
def flagged_flow(client, full_flow):
    make_moderator(client, "mod")
    mod_key = client.get("/moderation/pubkey", headers=full_flow["recipient"]).json()["public_key"]
    ciphertext, wrapped_key, nonce = encrypt_message(full_flow["plaintext"], mod_key)
    res = client.post(f"/messages/{full_flow['message_id']}/flag", headers=full_flow["recipient"], json={
        "mod_ciphertext": ciphertext.hex(), "mod_wrapped_key": wrapped_key.hex(), "mod_nonce": nonce.hex(),
    })
    assert res.status_code == 200

    res = client.post("/login", json={"username": "mallory", "password": "not-the-real-password"})
    assert res.status_code == 401
    return full_flow


# the server only ever holds ciphertext, for the Recipient's copy and for the Moderator's copy
def test_dump_has_no_readable_message_content(flagged_flow):
    data = db_bytes()
    # check we are reading the right file: a value we know was saved should be in it
    assert flagged_flow["message_id"].encode() in data
    assert flagged_flow["plaintext"].encode() not in data


# no table ties a message or a token to a person
def test_message_and_token_tables_have_no_sender_column(client):
    forbidden = {"user_id", "sender", "sender_id", "username", "from"}
    for table in ("messages", "valid_tokens", "flags"):
        assert not forbidden & column_names(table), f"{table} must not say who a row belongs to"

    # the table that does hold user ids says who got a token in a round, but never which token
    assert column_names("token_issuance") == {"user_id", "round_id"}


# the log says what happened and in which role, never who
def test_audit_log_has_no_usernames(client, flagged_flow):
    conn = get_conn()
    entries = " ".join(row["entry"] for row in conn.execute("SELECT entry FROM audit_log"))
    conn.close()
    assert "event" in entries                       # the log is not empty
    for username in ("alice", "bob", "mod", "mallory"):
        assert username not in entries, f"{username} must not appear in the audit log"


# only hashes are stored, so a stolen database has no passwords or usable tokens
def test_dump_has_no_raw_passwords_or_tokens(flagged_flow):
    data = db_bytes()
    session_token = flagged_flow["sender"]["Authorization"][len("Bearer "):]
    assert PASSWORD.encode() not in data
    assert session_token.encode() not in data
    assert flagged_flow["token"].encode() not in data

    # the hash of the message token IS stored, which is what lets a Moderator freeze it
    assert hash_token(flagged_flow["token"]).encode() in data


# ---------- tampering with the audit log ----------

# a log where the Moderator has checked that it is intact, before anyone touches it
@pytest.fixture
def checked_log(client, full_flow):
    make_moderator(client, "mod")
    mod = login(client, "mod")
    assert client.get("/audit/verify", headers=mod).json() == {"ok": True}
    return mod


# the log_id of the second record, which has records both before and after it
def second_log_id():
    conn = get_conn()
    log_id = conn.execute("SELECT log_id FROM audit_log ORDER BY log_id LIMIT 1 OFFSET 1").fetchone()["log_id"]
    conn.close()
    return log_id


# changing a record after it was written is caught, and the check says which record
def test_editing_a_log_record_is_detected(client, checked_log):
    log_id = second_log_id()
    conn = get_conn()
    row = conn.execute("SELECT entry FROM audit_log WHERE log_id = ?", (log_id,)).fetchone()
    entry = json.loads(row["entry"])
    entry["role"] = "Admin"                          # rewrite who did it
    conn.execute("UPDATE audit_log SET entry = ? WHERE log_id = ?", (json.dumps(entry, sort_keys=True), log_id))
    conn.commit()
    conn.close()

    res = client.get("/audit/verify", headers=checked_log)
    assert res.json() == {"ok": False, "first_bad_log_id": log_id}


# deleting a record is caught too, because the next record no longer links to the one before it
def test_deleting_a_log_record_is_detected(client, checked_log):
    log_id = second_log_id()
    conn = get_conn()
    conn.execute("DELETE FROM audit_log WHERE log_id = ?", (log_id,))
    conn.commit()
    conn.close()

    res = client.get("/audit/verify", headers=checked_log)
    assert res.json() == {"ok": False, "first_bad_log_id": log_id + 1}


# ---------- public key lookup: GET /users/{username}/pubkey ----------

def test_pubkey_no_header_is_401(client):
    assert client.get("/users/bob/pubkey").status_code == 401


def test_pubkey_recipient_returns_their_key(client):
    register(client, "alice", ["Sender"], "alice-key")
    register(client, "bob", ["Recipient"], "bob-key")
    res = client.get("/users/bob/pubkey", headers=login(client, "alice"))
    assert res.status_code == 200
    assert res.json() == {"username": "bob", "public_key": "bob-key"}


def test_pubkey_unknown_user_is_404(client):
    register(client, "alice", ["Sender"], "alice-key")
    res = client.get("/users/nobody/pubkey", headers=login(client, "alice"))
    assert res.status_code == 404


# only Recipients can be looked up, so an Admin's placeholder key is never handed out
def test_pubkey_non_recipient_is_404(client):
    register(client, "alice", ["Sender"], "alice-key")
    make_admin(client, "addy")
    headers = login(client, "alice")
    assert client.get("/users/alice/pubkey", headers=headers).status_code == 404
    assert client.get("/users/addy/pubkey", headers=headers).status_code == 404
