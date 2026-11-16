# Run in main folder with: python -m client.client

# Sources:
# httpx: https://www.python-httpx.org/ 
# bearer authentication: https://swagger.io/docs/specification/v3_0/authentication/bearer-authentication/
# os: https://docs.python.org/3/library/os.html 

import httpx
import os
from cryptography.hazmat.primitives import serialization
from common.crypto import generate_rsa_keypair, store_private_key, load_private_key, encrypt_message, decrypt_message
import base64

BASE_URL = "http://localhost:8000"


# APIClient client class
# Handles communication between the CLI and the FastAPI server
# Encapsulation helps eliminate repeated code for server connection and request handling
class APIClient:

    def __init__(self):
        self.base_url = BASE_URL
        self.session_token = None
        self.client = httpx.Client(base_url=self.base_url)


    def close(self):
        self.client.close()
    

    # Send a request to the server and handle the response
    def request(self, method, endpoint, authenticated=True, **kwargs):
        headers = kwargs.pop("headers", {}).copy()

        # Uses Bearer authentication to prepare the header if authentication is necessary for the request
        if authenticated and self.session_token:
            headers["Authorization"] = f"Bearer {self.session_token}"
        
        # Send request to server
        response = self.client.request(method, endpoint, headers=headers, **kwargs)

        # Handle server response if not successful 
        if not response.is_success:
            try:
                error_detail = response.json().get("detail", response.text)
            except ValueError:
                error_detail = response.text
            
            raise RuntimeError(
                f"Server error {response.status_code}: {error_detail}"
            )
        
        # Return response if successful
        if response.content:
            return response.json()
        
        return None
    

    # Log in to the server with username and password, and store the session token for future requests
    def login(self, username, password):
        # Send login request
        response = self.request(
            "POST", 
            "/login", 
            authenticated=False,
            json={
                "username": username, 
                "password": password
            }
        )

        self.session_token = response["session_token"]
        
        return response
    

    # Register a new user with username, password, roles, and key password
    def register(self, username, password, roles, key_password):
        # Generate a public/private RSA key pair
        private_key, public_key = generate_rsa_keypair()

        # Create directory for storing private keys in PEM files
        os.makedirs("keys", exist_ok=True)

        # Save the private key locally
        private_key_file = f"keys/{username}_private.pem"
        store_private_key(private_key, key_password, private_key_file)

        # Convert the public key into PEM text
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Send registration request to the server
        response = self.request(
            "POST",
            "/register",
            authenticated=False,
            json={
                "username": username,
                "password": password,
                "roles": roles,
                "public_key": public_key_pem
            }
        )

        return response
    

    # Send request to the server to get a token
    def request_token(self):
        return self.request(
            "POST",
            "/token/issue"
        )
    

    # Load the user's private key from the local PEM file
    def load_my_private_key(self, username, key_password):
        private_key_file = f"keys/{username}_private.pem"

        private_key = load_private_key(
            key_password,
            private_key_file
        )

        return private_key


    # Get the current round number from the server
    def get_current_round(self):
        return self.request(
            "GET",
            "/rounds/current"
        )


    # Get the user's inbox from the server
    def get_inbox(self):
        return self.request(
            "GET",
            "/inbox"
        )

    
    # Get the moderator's public key from the server
    def get_moderator_public_key(self):
        response = self.request(
            "GET",
            "/moderation/pubkey"
        )

        return response["public_key"]
    

    # Flag a message for moderation by sending the encrypted message to the moderator
    def flag_message(self, message_id, message_text):
        # Get the Moderator's public key
        moderator_public_key = self.get_moderator_public_key()

        # Encrypt the message for the Moderator
        ciphertext, encrypted_key, nonce = encrypt_message(
            message_text,
            moderator_public_key
        )

        # Convert encrypted bytes to Base64 text and send the request to the server
        response = self.request(
            "POST",
            f"/messages/{message_id}/flag",
            json={
                "mod_ciphertext": base64.b64encode(ciphertext).decode(),
                "mod_wrapped_key": base64.b64encode(encrypted_key).decode(),
                "mod_nonce": base64.b64encode(nonce).decode()
            }
        )

        return response

    
    # Get the moderation queue from the server
    def get_moderation_queue(self):
        return self.request(
            "GET",
            "/moderation/queue"
        )
    

    # MODERATOR FUNCTIONALITY

    # Freeze a flagged message to prevent it from being sent to the recipient (moderator)
    def freeze_message(self, message_id):
        return self.request(
            "POST",
            f"/moderation/freeze/{message_id}"
    )


    # Get the audit log from the server (moderator)
    def get_audit_log(self):
        return self.request(
            "GET",
            "/audit"
        )
    

    # Verify the integrity of the audit log by checking the hashes and signatures of the entries (moderator)
    def verify_audit_log(self):
        return self.request(
            "GET",
            "/audit/verify"
        )


    # ADMIN FUNCTIONALITY

    # Advance the round number on the server (admin)
    def advance_round(self):
        return self.request(
            "POST",
            "/admin/round/advance"
        )
    

    # Change the roles of a user on the server (admin)
    def change_user_roles(self, username, roles):
        return self.request(
            "PATCH",
            f"/users/{username}/roles",
            json={"roles": roles}
        )

    # Logout the user
    def logout(self):
        response = self.request(
            "POST",
            "/logout"
        )
        
        # Clear the session token after logging out (added precaution - server must also deactivate)
        self.session_token = None
        
        return response



if __name__ == "__main__":
    api = APIClient()
    try:
        # Log in as Moderator
        api.login(
            username="moderator1",
            password="your-secure-password-here"
        )
        print("Moderator login successful!")

        # 1. Get moderation queue
        queue = api.get_moderation_queue()
        print("\nModeration queue:")
        print(queue)

        # 2. Retrieve audit log
        audit_log = api.get_audit_log()
        print("\nAudit log retrieved!")
        print("Number of records:", len(audit_log))

        # 3. Verify audit log
        verification = api.verify_audit_log()
        print("\nAudit verification:")
        print(verification)

        api.logout()
        print("\nModerator logout successful!")

  
    except Exception as e:
        print(f"Registration failed: {e}")

    api.close()