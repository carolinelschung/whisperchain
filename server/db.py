# db.py - opens the SQLite database and creates the tables the server needs.
import sqlite3

DB_FILE = "whisperchain.db"

# Open a connection. Rows can be read by column name, like row["username"]
def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Create the tables if they don't exist yet. Safe to run every time the server starts
def init_db():
    conn = get_conn()
    conn.executescript("""
        -- one row per person
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL
        );

        -- one row per role a person has (a person can have several)
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            PRIMARY KEY (user_id, role)
        );

        -- one row per logged-in session; we store a hash of the session token, not the token
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL
        );

        -- the current round number (always exactly one row, with id 1)
        CREATE TABLE IF NOT EXISTS current_round (
            id INTEGER PRIMARY KEY,
            round_id INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO current_round (id, round_id) VALUES (1, 1);

        -- records that a user got a token in a round, so nobody gets two.
        -- it does NOT say which token they got
        CREATE TABLE IF NOT EXISTS token_issuance (
            user_id INTEGER NOT NULL,
            round_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, round_id)
        );

        -- the pool of tokens that can be used to send a message.
        -- there is deliberately NO user_id column here, so a token can't be tied to a person
        CREATE TABLE IF NOT EXISTS valid_tokens (
            token_hash TEXT PRIMARY KEY,
            round_id INTEGER NOT NULL,
            spent INTEGER NOT NULL DEFAULT 0,
            frozen INTEGER NOT NULL DEFAULT 0
        );

        -- the encrypted messages. the server can't read them, and there is deliberately NO
        -- sender column. token_hash is kept only so a moderator can freeze the token later
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            recipient_id INTEGER NOT NULL,
            ciphertext TEXT NOT NULL,
            wrapped_key TEXT NOT NULL,
            nonce TEXT NOT NULL,
            round_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            flagged INTEGER NOT NULL DEFAULT 0
        );

        -- one row per flagged message (message_id is the primary key, so it can only be flagged once).
        -- holds a copy of the message encrypted for the Moderator, which only the Moderator can read
        CREATE TABLE IF NOT EXISTS flags (
            message_id TEXT PRIMARY KEY,
            mod_ciphertext TEXT NOT NULL,
            mod_wrapped_key TEXT NOT NULL,
            mod_nonce TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()
