# demo.py - demonstrates user registration, authentication, anonymous encrypted messaging,
# role-based access control, token restrictions, message flagging and freezing,
# audit log verification, and tampering detection.

import getpass
import json
import os
from copy import deepcopy

from client.client import APIClient
from server.audit_chain import calculate_hash

# Helper function to register a new user with the server
def register_user(api):
    username = input("Choose a username: ").strip()
    password = getpass.getpass("Choose a password: ")
    private_key_password = getpass.getpass(
        "Choose a private-key password: "
    )

    result = api.register(
        username,
        password,
        ["Recipient"],
        private_key_password
    )

    print("\nRegistration successful!")
    print("Username:", result["username"])
    print("Roles:", result["roles"])
    print("Public/private keypair generated.")
    print("Private key saved locally.")

    return username


# Helper function to login user
def login(api, username):
    password = getpass.getpass(f"Password for {username}: ")
    api.login(username, password)
    print(f"\n{username} logged in successfully.")


# Helper function to logout user
def logout(api):
    if api.session_token:
        api.logout()
        print("Logged out.")


# Helper function to test that a server request is rejected with the expected status code
def expect_rejection(label, action, expected_status):
    try:
        action()

    except RuntimeError as e:
        if f"Server error {expected_status}:" in str(e):
            print(f"[PASS] {label}")
            print(f"       Server correctly rejected request ({expected_status}).")
        else:
            print(f"[FAIL] {label}")
            print(f"       Unexpected error: {e}")

    else:
        print(f"[FAIL] {label}")
        print("       Server accepted a request that should have been rejected.")


def main():
    api = APIClient()

    # These are the test accounts used in the project.
    admin = "admin1"
    sender = "jordan"
    recipient = "recipient1"
    moderator = "moderator1"

    message_text = input("\nEnter a message to send: ").strip()

    if not message_text:
        print("Message cannot be empty.")
        api.close()
        return

    try:
        # --------------------------------------------------
        # 1. REGISTER: Create a new Recipient
        # --------------------------------------------------
        print("\n========== STEP 1: REGISTRATION ==========")

        new_recipient = register_user(api)

        recipient = new_recipient
        
        # --------------------------------------------------
        # 2. ADMIN: Advance the round
        # --------------------------------------------------
        print("\n========== STEP 1: ADMIN ==========")

        login(api, admin)
        result = api.advance_round()
        print("Round advanced:", result)
        logout(api)

        # --------------------------------------------------
        # 3. RECIPIENT: Record existing inbox messages
        # --------------------------------------------------
        print("\n========== STEP 2: PREPARE RECIPIENT ==========")

        login(api, recipient)

        previous_messages = api.get_inbox()
        previous_ids = {
            message["message_id"] for message in previous_messages
        }

        logout(api)

        # --------------------------------------------------
        # 4. SENDER: Send an anonymous encrypted message
        # --------------------------------------------------
        print("\n========== STEP 3: SENDER ==========")

        login(api, sender)
        print("\nTesting unauthorized access...")

        expect_rejection(
            "Sender cannot access the moderation queue",
            api.get_moderation_queue,
            403
        )

        send_result = api.send_message(recipient, message_text)
        print("Message sent successfully!")
        print("The message was submitted using an anonymous token.")

        print("\nTesting one-token-per-round restriction...")

        expect_rejection(
            "Sender cannot request a second token in the same round",
            api.request_token,
            409
        )

        logout(api)

        # --------------------------------------------------
        # 5. RECIPIENT: Retrieve, decrypt, and flag the message
        # --------------------------------------------------
        print("\n========== STEP 4: RECIPIENT ==========")

        login(api, recipient)

        recipient_key_password = getpass.getpass(
            "Recipient private-key password: "
        )

        # Display and decrypt the inbox locally.
        api.read_inbox(recipient, recipient_key_password)

        # Identify the newly received message.
        current_messages = api.get_inbox()

        new_messages = [
            message for message in current_messages
            if message["message_id"] not in previous_ids
        ]

        if len(new_messages) != 1:
            raise RuntimeError(
                f"Expected one new message, found {len(new_messages)}."
            )

        message_id = new_messages[0]["message_id"]

        print("\nFlagging the newly received message...")
        api.flag_message(message_id, message_text)
        print("Message successfully flagged for moderation.")

        logout(api)

        # --------------------------------------------------
        # 6. MODERATOR: Review and freeze the flagged message
        # --------------------------------------------------
        print("\n========== STEP 5: MODERATOR ==========")

        login(api, moderator)

        moderator_key_password = getpass.getpass(
            "Moderator private-key password: "
        )

        print("\nRetrieving and decrypting moderation queue...")
        api.read_moderation_queue(moderator, moderator_key_password)

        print("\nFreezing the flagged message...")
        api.freeze_message(message_id)
        print("Message successfully frozen.")

        # --------------------------------------------------
        # 7. MODERATOR: Display and verify audit log
        # --------------------------------------------------
        print("\n========== STEP 6: AUDIT LOG ==========")

        records = api.get_audit_log()

        # Save the original, unmodified audit log.
        os.makedirs("samples", exist_ok=True)

        with open("samples/audit_log_sample.json", "w") as file:
            json.dump(records, file, indent=2)

        print("Original audit log saved to samples/audit_log_sample.json")

        api.display_audit_log()

        result = api.verify_audit_log()

        if result["ok"]:
            print("\nAudit log verification successful.")
            print("All entries are intact. No tampering detected.")
        else:
            print("\nWARNING: Audit log verification failed!")
            print("First invalid entry:", result["first_bad_log_id"])

        # --------------------------------------------------
        # 8. DEMONSTRATE AUDIT LOG TAMPERING DETECTION
        # --------------------------------------------------
        print("\n========== STEP 7: TAMPERING DEMONSTRATION ==========")

        tampered_records = deepcopy(records)

        if tampered_records:
            # Alter a copy of the first audit entry.
            tampered_records[0]["entry"]["event"] += "_tampered"

            # Recalculate its hash and compare it with the stored hash.
            altered_hash = calculate_hash(
                tampered_records[0]["prev_hash"],
                tampered_records[0]["entry"]
            )

            if altered_hash != tampered_records[0]["entry_hash"]:
                print("Tampering detected!")
                print("The modified entry no longer matches its stored hash.")
            else:
                print("Tampering was not detected.")
        else:
            print("No audit entries available to test.")

        print("\nThe original database and audit log were not modified.")

        logout(api)

        print("\n========== DEMO COMPLETE ==========")

    except Exception as e:
        print(f"\nDemo failed: {e}")

    finally:
        api.close()


if __name__ == "__main__":
    main()
