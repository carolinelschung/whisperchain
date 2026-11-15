# audit.py - writes and checks the tamper-evident audit log.
# It uses audit_chain.py ( for hash chain + signatures) and common/crypto.py (for RSA keys).
# The log records only the time, the action and the role. Does not keep a username, id or IP address to preserve anonymity

# Sources:
# RSA cryptography: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
# PEM key storage and loading: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
# global key: https://docs.python.org/3/reference/simple_stmts.html

import json
import os
from datetime import datetime
from zoneinfo import ZoneInfo

from common.crypto import generate_rsa_keypair, load_private_key, store_private_key
from server.audit_chain import append, verify_chain

KEY_FILE = "keys/system_log.pem"
# the password that protects the key file. set WHISPERCHAIN_LOG_KEY_PASSWORD if you want to use your own.
# the default is only for the demo, since a real system would keep this in a key vault
KEY_PASSWORD = os.environ.get("WHISPERCHAIN_LOG_KEY_PASSWORD", "demo-log-key-password")

system_key = None  # filled in the first time it's needed


# Load the system's signing key, or make one the first time the server needs it.
def get_system_key():
    global system_key
    if system_key is None:
        if os.path.exists(KEY_FILE):
            system_key = load_private_key(KEY_PASSWORD, KEY_FILE)
        else:
            os.makedirs("keys", exist_ok=True)
            system_key, _ = generate_rsa_keypair()
            store_private_key(system_key, KEY_PASSWORD, KEY_FILE)
    return system_key


# Add one event to the log. 
# event: what happened, like "token_issued". 
# role: which role did it. 
# details: optional extras.
def log_event(conn, event, role, details=None):
    # time in Hanover, NH (Eastern time)
    entry = {
        "event": event,
        "timestamp": datetime.now(ZoneInfo("America/New_York")).isoformat(timespec="seconds"),
        "role": role,
    }
    if details is not None:
        entry["details"] = details

    # audit_chain.append only needs the last record, so we pass just that one
    last = conn.execute("SELECT * FROM audit_log ORDER BY log_id DESC LIMIT 1").fetchone()
    chain = []
    if last is not None:
        chain = [{"entry": json.loads(last["entry"]), "entry_hash": last["entry_hash"]}]

    # append gives back the chain with the new record on the end
    record = append(entry, chain, get_system_key())[-1]

    # the signature is raw bytes, so save it as hex text. sort_keys makes the saved text
    # match exactly what was hashed
    conn.execute(
        "INSERT INTO audit_log (entry, prev_hash, entry_hash, signature) VALUES (?, ?, ?, ?)",
        (json.dumps(entry, sort_keys=True), record["prev_hash"], record["entry_hash"], record["signature"].hex()),
    )


# Return every record in order, with the entry turned back into a dictionary.
def read_log(conn):
    rows = conn.execute("SELECT * FROM audit_log ORDER BY log_id").fetchall()
    records = []
    for row in rows:
        records.append({
            "log_id": row["log_id"],
            "entry": json.loads(row["entry"]),
            "prev_hash": row["prev_hash"],
            "entry_hash": row["entry_hash"],
            "signature": row["signature"],
        })
    return records


# Check the whole log. Returns None if it is intact, or the log_id of the first bad record.
def check_log(conn):
    rows = conn.execute("SELECT * FROM audit_log ORDER BY log_id").fetchall()

    chain = []
    for row in rows:
        # a row that was edited into something unreadable counts as bad too
        try:
            chain.append({
                "entry": json.loads(row["entry"]),
                "prev_hash": row["prev_hash"],
                "entry_hash": row["entry_hash"],
                "signature": bytes.fromhex(row["signature"]),
            })
        except ValueError:
            return row["log_id"]

    bad_index = verify_chain(chain, get_system_key().public_key())
    if bad_index is None:
        return None
    return rows[bad_index]["log_id"]
