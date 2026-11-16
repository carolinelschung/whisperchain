# conftest.py - pytest fixtures shared by every test file in this folder.

# Sources:
# pytest documentation (fixtures, conftest.py, monkeypatch, tmp_path): https://docs.pytest.org/en/stable/

import pytest
from fastapi.testclient import TestClient

import server.db
import server.main
from helpers import login, make_user, send_message

PLAINTEXT = "SUPER-SECRET-PLAINTEXT-MESSAGE"     


# give every test its own empty database (and its own folder for any key files)
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(server.db, "DB_FILE", str(tmp_path / "test.db"))
    server.db.init_db()
    return TestClient(server.main.app)


# A Sender sends one message to a Recipient. Returns a dict with everything a test might need:
# sender and recipient headers, the recipient's private key, the token used, the message id
@pytest.fixture
def full_flow(client):
    sender, _ = make_user(client, "alice", ["Sender"])
    recipient, recipient_key = make_user(client, "bob", ["Recipient"])

    token = client.post("/token/issue", headers=sender).json()["token"]
    public_key = client.get("/users/bob/pubkey", headers=sender).json()["public_key"]
    res = send_message(client, token, public_key, "bob", PLAINTEXT)
    assert res.status_code == 201

    return {
        "sender": sender,
        "recipient": recipient,
        "recipient_key": recipient_key,
        "token": token,
        "message_id": res.json()["message_id"],
        "plaintext": PLAINTEXT,
    }
