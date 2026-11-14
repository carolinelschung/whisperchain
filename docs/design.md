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