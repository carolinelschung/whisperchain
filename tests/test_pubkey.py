# test_pubkey.py - tests for GET /users/{username}/pubkey
import pytest
from fastapi.testclient import TestClient

import server.db
import server.main
from server.db import get_conn

PASSWORD = "a-long-test-password"        # the server needs at least 15 characters


@pytest.fixture
def client(tmp_path, monkeypatch):
    # give every test its own empty database (and its own folder for any key files)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(server.db, "DB_FILE", str(tmp_path / "test.db"))
    server.db.init_db()
    return TestClient(server.main.app)


def register(client, username, roles, public_key):
    res = client.post("/register", json={
        "username": username, "password": PASSWORD, "roles": roles, "public_key": public_key,
    })
    assert res.status_code == 201


def login(client, username):
    res = client.post("/login", json={"username": username, "password": PASSWORD})
    assert res.status_code == 200
    return {"Authorization": "Bearer " + res.json()["session_token"]}


def make_admin(client, username):
    # an Admin can't self-register, so add one straight to the database like create_admin.py does
    register(client, username, ["Sender"], "none")
    conn = get_conn()
    conn.execute(
        "UPDATE user_roles SET role = 'Admin' WHERE user_id = (SELECT id FROM users WHERE username = ?)",
        (username,),
    )
    conn.commit()
    conn.close()


def test_no_header_is_401(client):
    assert client.get("/users/bob/pubkey").status_code == 401


def test_bad_token_is_401(client):
    res = client.get("/users/bob/pubkey", headers={"Authorization": "Bearer notarealtoken"})
    assert res.status_code == 401


def test_recipient_returns_their_key(client):
    register(client, "alice", ["Sender"], "alice-key")
    register(client, "bob", ["Recipient"], "bob-key")
    res = client.get("/users/bob/pubkey", headers=login(client, "alice"))
    assert res.status_code == 200
    assert res.json() == {"username": "bob", "public_key": "bob-key"}


def test_unknown_user_is_404(client):
    register(client, "alice", ["Sender"], "alice-key")
    res = client.get("/users/nobody/pubkey", headers=login(client, "alice"))
    assert res.status_code == 404


def test_non_recipient_is_404(client):
    # alice is only a Sender and carol is an Admin, so neither can be looked up
    register(client, "alice", ["Sender"], "alice-key")
    make_admin(client, "carol")
    headers = login(client, "alice")
    assert client.get("/users/alice/pubkey", headers=headers).status_code == 404
    assert client.get("/users/carol/pubkey", headers=headers).status_code == 404


def test_sender_and_admin_can_both_call_it(client):
    register(client, "alice", ["Sender"], "alice-key")
    register(client, "bob", ["Recipient"], "bob-key")
    make_admin(client, "carol")
    for who in ("alice", "carol"):
        res = client.get("/users/bob/pubkey", headers=login(client, who))
        assert res.status_code == 200
        assert res.json()["public_key"] == "bob-key"
