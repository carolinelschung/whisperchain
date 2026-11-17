# RBAC Matrix (draft)

Draft derived from the "access:" lines in `design.md`. Replace or reconcile with Jordan's matrix once it is pushed.

Key: ✓ = allowed, ✗ = denied, "token" = authorized by an anonymous token instead of a login, "own only" = only the caller's own messages, "flagged only" = only messages flagged for review.

| Action | Sender | Recipient | Moderator | Admin |
|---|---|---|---|---|
| Register, log in | ✓ | ✓ | ✓ | ✓ |
| Get current round | ✓ | ✓ | ✓ | ✓ |
| Get a Recipient's public key (`GET /users/{username}/pubkey`) | ✓ | ✓ | ✓ | ✓ |
| Get the Moderator's public key (`GET /moderation/pubkey`) | ✓ | ✓ | ✓ | ✓ |
| Request token | ✓ | ✗ | ✗ | ✗ |
| Submit message (token only, no login) | token | token | token | token |
| Read own inbox | ✗ | ✓ | ✗ | ✗ |
| Flag a message | ✗ | ✓ | ✗ | ✗ |
| View flagged queue | ✗ | ✗ | ✓ | ✗ |
| Freeze token | ✗ | ✗ | ✓ | ✗ |
| View audit logs (and verify them) | ✗ | ✗ | ✓ | ✗ |
| Assign roles / manage users | ✗ | ✗ | ✗ | ✓ |
| Read message content | ✗ | own only | flagged only | ✗ |

## Notes
- A user can hold more than one role (for example Sender and Recipient). An action is allowed if any of their roles allows it
- Submitting a message is authorized by the anonymous token, not by a session, so the server cannot tell who sent it
- The two public key lookups only need a login, with no specific role, because public keys are not secret and a Sender needs the Recipient's key to encrypt. `GET /users/{username}/pubkey` returns 404 unless the user is a Recipient
- Admins can never read message content or see sender information (separation of duties)
