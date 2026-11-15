# Sources:
# hash chains for audit logs: https://dev.to/robertatkinson3570/the-architecture-behind-tamper-proof-audit-logs-56ek, https://dev.to/veritaschain/building-a-tamper-evident-audit-log-with-sha-256-hash-chains-zero-dependencies-h0b 
# JSON: https://docs.python.org/3/library/json.html
# hasing: https://docs.python.org/3/library/hashlib.html 
# NOTE: will need to generate public-private keypair for the system when server is initialized
# using generate_rsa_keypair functionality in common/crypto !!

import hashlib
import json
from common.crypto import sign_data, verify_signature

# Initial hash for the first entry in the chain
GENESIS_HASH = "0" * 64


# Convert an audit entry into a consistent byte representation
#
# Example entry:
# {
#     "event": "message_flagged",
#     "timestamp": "2026-11-15T11:30:00",
#     "role": "Recipient",
#     "details": {
#         "message_id": 42
#     }
# }
#
# Sorting keys ensures that two entries with the same content but different key orders 
# will produce the same hash, necessary for verifying the integrity of the audit chain.
def serialize_entry(entry):
    return json.dumps(entry, sort_keys=True).encode()


# Calculate chain hash: SHA-256(prev_hash + entry)
# Store as hexadecimal string 
def calculate_hash(prev_hash, entry):
    entry_bytes = serialize_entry(entry)
    combined = prev_hash.encode() + entry_bytes
    return hashlib.sha256(combined).hexdigest()


# Create a new audit entry, link it to the previous entry, hash it, and sign the hash.
#
#Returns a new chain without modifying the original.
def append(entry, chain, private_key):

    # Determine previous entry's hash
    if len(chain) == 0:
        prev_hash = GENESIS_HASH
    else:
        prev_hash = chain[-1]["entry_hash"]

    # Calculate new entry's hash
    entry_hash = calculate_hash(prev_hash, entry)

    # Sign hash of the new entry using system's private key
    signature = sign_data(bytes.fromhex(entry_hash), private_key)

    # Create the new audit entry with hash and signature
    new_record = {
        "entry": entry,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "signature": signature
    }

    # Return a new chain with the added entry
    return chain + [new_record]


# Verify the hash links, entry hashes, and RSA signatures
#
# Returns:
#    Index of the first invalid entry, or None if the chain is valid
def verify_chain(chain, public_key):
    expected_prev_hash = GENESIS_HASH

    for index, record in enumerate(chain):

        # Check that entry points to the correct previous hash
        if record["prev_hash"] != expected_prev_hash:
            return index
        
        # Recalculate the hash of the current entry and compare
        recalculated_hash = calculate_hash(record["prev_hash"], record["entry"])
        if recalculated_hash != record["hash"]:
            return index
        
        # Verify the RSA signature
        if not verify_signature(bytes.fromhex(record["entry_hash"]), record["signature"], public_key):
            return index
        
        # Next entry's prev_hash should be the current entry's hash
        expected_prev_hash = record["entry_hash"]
    
    return None  # Chain is valid