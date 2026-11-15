List of API endpoints for client-server communication labeled by process (add more as necessary):

## Account registration and authentication
POST /register
- access: anyone not already registered
- request user's username, password, public key (public-private key is generated during registration)
- assign default or assigned role

POST /login
- access: anyone with account
- request username and password
- create authenticated session - create session token

POST /logout
- access: any authenticated user
- request session token
- invalidate token

## User management
GET /users
- access: admin
- list of usernames and roles - not passwords, private keys, or messages
(Not sure if we will need this one, but good to check - NEEDS good input validation)
- **cc note: propose not adding this**

PATCH /users/{username}/role
- access: admin
- change a user's assigned role
- request user's new role

## Public key management
GET /users/{username}/pubkey
- access: authenticated users
- retrieve another user's public key to send a message

PUT /users/{username}/pubkey
- access: users can modify their own public key, admin can modify public keys of any users
- need to make sure non-admin users can only update their own keys
- **cc note: propose not adding this**

## Token and round handling
GET /rounds/current
- access: authenticated users
- find out which messaging round currently active

POST /token/issue
- access: sender
- sender requests anonymous token in order to send their one message per round
- server checks whether sender has received a token for the round
- if not, generates token, stores token hash, & separately records that the sender has received a token without storing link between token & sender

## Messages
POST /messages
- access: sender
- submit an anonymous, encrypted message
- sender provides their token and server checks that token is valid, unspent, and not frozen
- server verifies recipient exists, mark token as spent

GET /inbox
- access: recipient
- retrieve messages addressed to authenticated user
- recipient's client decrypts message locally using private key

## Flagging and moderation
POST /messages/{message_id}/flag
- access: recipient who received message
- allows recipient to flag a message
- server verifies recipient owns the specified message
- recipient's client reencrypts message with moderator's public key

GET /moderation/queue
- access: moderator
- server retrieves messages flagged for review - encrypted for moderator

POST /moderation/freeze/{message_id}
- access: moderator
- freeze anonymous token associated with flagged message
- server finds token hash associated internally with message & marks token as frozen
- prevent any future use of that token


## Audit logging
GET /audit
- access: moderator
- receive timestamped audit events with action type and non-identifying metadata
- sender information should never be revealed 
- audit records should include: registration, token issuance, message submission, flagging, and token freezing (and maybe more?)

## How the client proves who it is
- After `POST /login`, the server returns a `session_token`.
- On every later request that needs a login, the client sends it as the header: `Authorization: Bearer <session_token>` (the word `Bearer`, one space, then the token).
- A missing or invalid header gets a 401 "not logged in".
- Exception: `POST /messages` is authorized by the anonymous token, which goes in the request body, and the client must NOT send a login header with it. That way the server cannot tell who sent the message.
- Reference on bearer tokens: Postman Blog, "What is a bearer token?", https://blog.postman.com/what-is-a-bearer-token/


## Endpoints as built on the server 

### Added endpoints
GET /moderation/pubkey
- access: any logged-in user
- returns the public key of the Moderator (the one with the lowest id)
- recipients need it to encrypt their copy of a message when flagging
- 404 if no Moderator exists

PATCH /users/{username}/roles
- access: admin (this is the role-change endpoint from the list above, with the path made plural because a user can hold several roles)
- request: list of roles, e.g. {"roles": ["Recipient", "Moderator"]}
- replaces the user's roles with the new list; takes effect on the user's next request
- an admin cannot change their own roles (403), so they cannot quietly make themselves a Moderator
- 400 for an empty list or an unknown role, 404 for an unknown user

POST /admin/round/advance
- access: admin
- moves everyone on to the next round and returns the new round number
- unspent tokens from the old round stop working, and Senders can request a new token

### Differences from the list above
- Role change: PATCH /users/{username}/roles (plural), since a user can hold several roles. Otherwise as in the list above.
- POST /messages: access is by the anonymous token only, with no login header (not "access: sender"), so the server cannot tell who sent the message.
- POST /messages/{message_id}/flag: the request body holds the three fields of the moderator copy (mod_ciphertext, mod_wrapped_key, mod_nonce).
- POST /moderation/freeze/{message_id}: only works on a flagged message. The token is already spent by then, so freezing records the abuse and does not block anyone (see the report).
- POST /logout is built as listed above: any logged-in user, deletes only the session whose token was sent.
- Not built (no endpoint): GET /users, PUT /users/{username}/pubkey.
- GET /audit and GET /audit/verify: not built yet. Moderators will see the full log and admins will see meta-events only.
