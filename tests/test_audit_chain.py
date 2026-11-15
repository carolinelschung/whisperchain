from common.crypto import generate_rsa_keypair
from server.audit_chain import (
    append,
    verify_chain,
    calculate_hash,
    serialize_entry,
    GENESIS_HASH
)


def test_serialize_entry():
    entry1 = {
        "event": "message_flagged",
        "role": "Recipient"
    }

    entry2 = {
        "role": "Recipient",
        "event": "message_flagged"
    }

    # Same information, different key order = same serialization
    assert serialize_entry(entry1) == serialize_entry(entry2)


def test_calculate_hash():
    entry = {
        "event": "message_flagged",
        "role": "Recipient"
    }

    entry_hash = calculate_hash(GENESIS_HASH, entry)

    # SHA-256 hexadecimal hash should be 64 characters
    assert isinstance(entry_hash, str)
    assert len(entry_hash) == 64


def test_append_and_verify_chain():
    private_key, public_key = generate_rsa_keypair()

    chain = []

    entry1 = {
        "event": "token_issued",
        "timestamp": "2026-11-15T12:00:00",
        "role": "Sender",
        "details": {"round_id": 1}
    }

    entry2 = {
        "event": "message_flagged",
        "timestamp": "2026-11-15T12:05:00",
        "role": "Recipient",
        "details": {"message_id": 42}
    }

    chain = append(entry1, chain, private_key)
    chain = append(entry2, chain, private_key)

    # Both entries should be stored
    assert len(chain) == 2

    # The second entry should link to the first
    assert chain[1]["prev_hash"] == chain[0]["entry_hash"]

    # The complete chain should be valid
    assert verify_chain(chain, public_key) is None


def test_tampered_entry():
    private_key, public_key = generate_rsa_keypair()

    chain = []

    entry = {
        "event": "message_flagged",
        "role": "Recipient"
    }

    chain = append(entry, chain, private_key)

    # Modify the original entry after it has been recorded
    chain[0]["entry"]["event"] = "token_issued"

    # Verification should identify the first entry as invalid
    assert verify_chain(chain, public_key) == 0


def test_wrong_public_key():
    private_key, public_key = generate_rsa_keypair()
    _, wrong_public_key = generate_rsa_keypair()

    chain = []

    entry = {
        "event": "token_issued",
        "role": "Sender"
    }

    chain = append(entry, chain, private_key)

    # A different public key should not verify the signature
    assert verify_chain(chain, wrong_public_key) == 0

    
if __name__ == "__main__":
    test_serialize_entry()
    test_calculate_hash()
    test_append_and_verify_chain()
    test_tampered_entry()
    test_wrong_public_key()
    print("All tests passed!")