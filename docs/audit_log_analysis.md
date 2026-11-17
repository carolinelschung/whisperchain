# Audit Log Write Up

Caroline Chung and Jordan Mandel
November 17, 2026

The sample log (`samples/audit_log_sample.json`) came from running our demo and has 115 records. The story is pretty linear and easy to follow. Round 6 is the cleanest example. A Sender gets a token (log ID 88), sends a message (log ID 89), the Recipient flags it (log ID 92), and the Moderator freezes the token (log ID 94). The `message_id` on the last three lines is what ties them together, so you can follow one message through the system without ever seeing a name to protect a user's anonymity. Round 7 (log IDs 108 to 115) does the same thing. The log also shows Admin actions like `round_advanced` and `roles_changed`, and failed logins (10 of them, all with the role "unknown"). Every record has a timestamp, a role, the previous record's hash, its own hash, and a signature, so editing or deleting one in the middle breaks the hash chain.

The log deliberately doesn't show usernames, user ids, message content, or which user got which token. `token_issued` only says "Sender". `roles_changed` only lists the new roles and not whose roles changed. A failed login has no username at all, so you can't tell which account was attacked, which is by design so that someone reading the log (a Moderator or whoever gets the file) can see what happened and when, but not who did it.

The audit log isn't perfect though. Key bits of identifying information can still be inferred from the records. For example, someone could match up a `token_issued` with a `message_sent` by timing, and if they also knew who was online at that moment, they could guess the sender. In the demo there's only one active Sender so it doesn't matter, but with a real user population, someone could match up a `token_issued` with a `message_sent` by timing. The log doesn't have names, but the timestamps leak a little anyway.
