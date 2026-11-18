# WhisperChain+

Anonymous, encrypted compliment messaging with role-based access control and a tamper-evident audit log.

## Features

- **User registration and authentication:** Register accounts with assigned roles and password-protected RSA private keys.
- **Anonymous messaging:** Send messages using one-time tokens, without attaching the sender's authenticated session to the message request.
- **End-to-end encryption:** Encrypt messages using AES-256-GCM, with the AES key encrypted using the recipient's RSA public key.
- **Role-based access control:** Restrict functionality based on user roles, including Sender, Recipient, Moderator, and Admin.
- **Message moderation:** Allow recipients to flag messages for moderator review. Moderators can decrypt flagged messages and freeze associated tokens.
- **Token restrictions:** Enforce one token per user per round and reject unauthorized or repeated requests.
- **Tamper-evident audit log:** Maintain a SHA-256 hash chain with RSA digital signatures to detect modifications to audit entries.

## Setup

Clone the repository and navigate to the project directory.

Create and activate a virtual environment:

```bash
python -m venv .venv
```

**macOS / Linux:**
```bash
source .venv/bin/activate
```

**Windows:**
```bash
.venv\Scripts\activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

WhisperChain+ uses a FastAPI server and a command-line client.

### 1. Start the server

From the main project directory, run:

```bash
uvicorn server.main:app --reload
```

The server will run at `http://127.0.0.1:8000`.

Keep this terminal open while using the application.

### 2. Run the client

Open a second terminal, navigate to the main project directory, activate the virtual environment, and run:

```bash
python -m client.client
```

Log in with an existing account to access the command-line menu.

## Running the Demo

The demo walks through the main application workflow, including registration, authentication, anonymous encrypted messaging, moderation, and audit log verification.

With the server running in a separate terminal, open another terminal and run:

```bash
python demo.py
```

Follow the prompts to:

1. Register a new recipient account.
2. Advance the current messaging round as an administrator.
3. Log in as the recipient and record existing inbox messages.
4. Log in as the sender and send an anonymous encrypted message.
5. Test unauthorized access and the one-token-per-round restriction.
6. Retrieve and decrypt the message as the recipient, then flag it for moderation.
7. Review and decrypt the flagged message as a moderator, then freeze it.
8. View and verify the audit log.
9. Demonstrate detection of audit log tampering.

The demo uses the existing test accounts:

- `admin1` — Admin
- `jordan` — Sender
- `moderator1` — Moderator

The recipient account is created during the demo. You will be prompted for passwords as needed.

## Project Structure

```text
whisperchain/
├── client/
│   └── client.py          # Client-side API and CLI
├── common/
│   └── crypto.py          # Encryption, decryption, and digital signatures
├── server/
│   ├── main.py            # FastAPI application and endpoints
│   └── audit_chain.py     # Tamper-evident audit log
├── keys/                  # Locally stored private keys
├── samples/               # Generated audit log samples
├── demo.py                # End-to-end application demonstration
├── requirements.txt       # Project dependencies
├── PLAN.md                # Project work plan
└── README.md
```

## Security Notes

- Private keys are stored locally in password-protected PEM files.
- On macOS and Linux, private-key files are restricted to owner read/write permissions.
- Messages are encrypted before being submitted to the server.
- Anonymous message submissions use one-time tokens rather than the sender's authenticated session.
- Moderators receive a separately encrypted copy of flagged messages for review.
- Audit entries are linked using SHA-256 hashes and signed with the system's RSA private key. Verification checks both the hash chain and digital signatures.


## Acknowledgements
We included sources used in the headers of files. AI tools (ChatGPT and/or Claude) were used for the original generation of the repo, README documentation, and file headers.  