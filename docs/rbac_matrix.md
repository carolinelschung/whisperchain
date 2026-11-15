# WhisperChain+ RBAC Matrix

WhisperChain+ uses Role-Based Access Control (RBAC) to restrict actions according to each user's assigned role.

- **Sender:** Requests an anonymous token and submits one encrypted message per round.
- **Recipient:** Retrieves and decrypts messages addressed to them. Can flag messages they receive.
- **Moderator:** Reviews flagged messages, freezes tokens, and reviews audit logs.
- **Admin:** Manages user registration, roles, public keys, and system policies. Cannot view message contents or identify anonymous Senders.

## RBAC Matrix

| Action | Sender | Recipient | Moderator | Admin |
|---|:---:|:---:|:---:|:---:|
| Register / log in | Y | Y | Y | Y |
| Request an anonymous token | Y | N | N | N |
| Submit an encrypted message | Y | N | N | N |
| View own inbox | N | Y | N | N |
| Decrypt own received messages | N | Y | N | N |
| Flag a received message | N | Y | N | N |
| View flagged messages | N | N | Y | N |
| Freeze a token | N | N | Y | N |
| View audit logs | N | N | Y | N |
| Manage user accounts | N | N | N | Y |
| Assign or change user roles | N | N | N | Y |
| Manage public keys | Own key | Own key | Own key (?) | Y |
| Manage system policies | N | N | N | Y |
| View all users' message contents | N | N | Flagged only | N |
| Identify an anonymous Sender | N | N | N | N |