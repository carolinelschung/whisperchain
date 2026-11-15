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


