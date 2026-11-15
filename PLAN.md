# WhisperChain+ Crash Plan (due Tuesday)

Written for Caroline and Jordan, working async. Undergrad, no bonus items. Goal: every must-have working and documented by Tuesday.

## How the work is split around your schedules
Jordan has more time Friday. Caroline has more time Saturday and Sunday. So:
- **Jordan front-loads Friday** with work that doesn't depend on the server: design docs, and self-contained code modules (crypto, log chain) that Caroline plugs in later.
- **Caroline builds the server on Saturday and Sunday** using Jordan's Friday docs and modules.
- Each task below has a "needs" line. Do tasks whenever you have time, as long as their needs are done.

## Ground rules
- Stack: Python + FastAPI + SQLite + `cryptography`. CLI client, no web UI.
- One branch per task, open a PR, the other skims it before merge. Post "X done, merged" in your chat when finished.
- Don't change the API contract (J2) silently. If you must, message the other person.
- Tokens (simplified, no blind signatures): at issuance the server generates a random token, stores only its hash in a "valid tokens" table with **no user id**, and separately records "user X received a token for round N" in a different table so they can't get two. Server returns the token to the user. At submit, the server checks the hash is valid, unspent, and not frozen. State in the report that this relies on the server not logging the link (a known limitation).

---

## Jordan's track (front-loaded Friday)

- [X] **J1 Repo setup.** GitHub repo, add Caroline, folders `server/ client/ docs/ tests/ samples/`, `requirements.txt` (fastapi, uvicorn, cryptography, httpx, pytest), `.gitignore` (keys, `*.db`). *Needs: nothing. Do first, so Caroline can clone.*
- [X] **J2 API contract** in `docs/design.md`. *Needs: J1.*
  - `POST /register` (username, password, role, public_key)
  - `POST /login` -> session token
  - `POST /token/issue` (Sender) -> random token
  - `POST /messages` (token, recipient, ciphertext, wrapped_key, nonce)
  - `GET /inbox` (Recipient) -> my ciphertexts only
  - `POST /messages/{id}/flag` (Recipient; includes content re-encrypted to the moderator public key)
  - `GET /moderation/queue`, `POST /moderation/freeze/{message_id}` (Moderator)
  - `GET /audit` (Moderator full; Admin meta-events only)
  - `GET /users/{name}/pubkey`
- [X] **J3 RBAC matrix + role descriptions** in `docs/rbac_matrix.md`. *Needs: J2.* Rules: Sender requests a token and sends; Recipient reads own inbox and flags; Moderator sees flagged content, freezes tokens, views logs; Admin manages users/roles/keys and never sees content or sender. Caroline implements the server checks from this table.
- [ ] **J4 Threat model draft** in `docs/threat_model.md` (table: threat / defense / residual risk). Cover: compromised admin, shared or stolen token, nonrepudiation, deanonymization by metadata/timing, spam/flooding, log tampering, false flagging. *Needs: J2.*
- [X] **J5 Crypto module** `common/crypto.py` + `tests/test_crypto.py`. *Needs: J1.* Functions: `generate_keypair()`, save/load private key (password-protected PEM), `encrypt_message(plaintext, recipient_pubkey)` -> ciphertext, wrapped_key, nonce (AES-256-GCM + RSA-OAEP key wrap), `decrypt_message(...)`. Tests: roundtrip works, wrong key fails, tampered ciphertext fails.
- [X] **J6 Audit chain module** `server/audit_chain.py` + tests. *Needs: J1.* `append(entry)` computes `entry_hash = SHA-256(prev_hash + entry)`, signs it with a system Ed25519 key, stores it. `verify_chain()` returns the first bad entry. Pure functions over a list or DB connection so Caroline can call it. Tests: edit a row, verify fails.
- [ ] **J7 CLI client** `client/cli.py` calling the J2 endpoints with `httpx` (register, login, token, send, inbox, flag, moderate, audit). *Needs: J5 and Caroline's server running (C4+). Can start with the contract and fix when the server lands.*
- [ ] **J8 `demo.py`** scripted full story ending with a tamper demo; save output to `samples/audit_log_sample.json`. *Needs: J7 and C6.*
- [ ] **J9 README** (setup, run server, run demo, run tests) and the fresh-clone test. *Needs: J8.*

## Caroline's track (weekend)

- [X] **C1 Read J2, J3 and clone.** *Needs: J1-J3 (Jordan's Friday work).*
- [X] **C2 DB + registration + login.** Tables: users, token_issuance (user, round), valid_tokens (token_hash, spent, frozen; **no user id**), messages, flags, audit_log. Hash passwords (scrypt/argon2), session tokens. *Needs: C1.*
- [X] **C3 RBAC.** One `require_permission("...")` dependency on every endpoint, deny by default, matching the J3 table. *Needs: C2.*
- [X] **C4 Token issue + message submit + inbox.** Implements the simplified token scheme above. Messages stored with no sender field: random id, recipient, ciphertext, wrapped_key, nonce, round. Inbox returns only the caller's messages. *Needs: C3.*
- [X] **C5 Audit logging.** Call Jordan's J6 `append` from every state-changing endpoint, with time, action, role only. No username or IP. *Needs: C3 and J6.*
- [X] **C6 Flagging, moderator queue, freeze, alert rule.** Flag stores the moderator-encrypted copy. Freeze marks the message's token frozen so it's rejected on submit. Alert (logged) when flags in a round exceed a threshold (e.g. 3) or one token is flagged twice. *Needs: C4, C5.*
- [ ] **C7 RBAC + privacy tests** (`tests/test_rbac.py`): each role is denied what it shouldn't do; admin gets 403 on content; double-spend token rejected; frozen token rejected; wrong recipient can't read an inbox message; DB dump has no readable content or sender. *Needs: C6.*
- [ ] **C8 Sample log analysis** (half page: what the log shows, what it deliberately doesn't). *Needs: J8.*
- [ ] **C9 Security design report (3-5 pages)**: architecture, crypto choices and why, RBAC, privacy vs accountability, limitations. Jordan reviews. *Needs: C6.*
- [ ] **C10 Final threat model.** Update J4 with what was built and the residual risks. Jordan reviews. *Needs: C6.*

---

## Suggested timeline (flexible)
- **Friday (Jordan):** J1, J2, J3, J4, then J5 and J6 as far as time allows.
- **Saturday (Caroline):** C1-C4, start C5. Jordan finishes J5/J6 if left over, then starts J7.
- **Sunday (Caroline):** C5-C7. Jordan: J7, then J8 once the server works. Do a quick sync Sunday night to fix integration bugs.
- **Monday (both, short):** C8-C10, J9. Fresh clone test.
- **Tuesday:** final check against the handout checklist (repo + README, security report, RBAC matrix + threat model, audit log sample + analysis), then submit.

## Handoff points (message each other when these land)
1. J1-J3 merged -> Caroline can start the server.
2. J5 and J6 merged -> Caroline can plug them in (C4, C5).
3. C4 working locally -> Jordan can test the CLI against it.
4. C6 done -> Jordan runs the demo (J8).

## Oral exam questions to be ready for
- Why can't the admin see who sent a message?
- How are tokens unlinkable to identities, and what must you trust the server about?
- What does freezing a token actually stop, given tokens are per-round?
- What would a database dump reveal?
- How is the log tamper-evident, and who could still forge it?
- What if a recipient flags a message dishonestly?
- Each of you should be able to explain the other's half.

## If you run short on time
Drop in this order: log signing (keep the hash chain), alert rule, CLI polish. Never cut: RBAC checks, end-to-end encryption, one token per round, flagging + moderator freeze, append-only timestamped log with no sender identity, the report and threat model.
