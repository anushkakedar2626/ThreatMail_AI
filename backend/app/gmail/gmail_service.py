from pathlib import Path
import base64

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# Gmail permission required to read and modify messages
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


# backend/
BASE_DIR = Path(__file__).resolve().parents[2]

CREDENTIALS_FILE = BASE_DIR / "credentials.json"
TOKEN_FILE = BASE_DIR / "token.json"


def get_gmail_service(interactive=True):
    """Authenticate and return a Gmail API service.

    interactive=False is used by the background monitor so a missing/expired
    token never launches an OAuth browser flow from the server process.
    """

    creds = None

    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(
            str(TOKEN_FILE),
            SCOPES
        )

    if not creds or not creds.valid:

        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

        else:
            if not interactive:
                return None

            if not CREDENTIALS_FILE.exists():
                raise FileNotFoundError(
                    f"credentials.json not found at: {CREDENTIALS_FILE}"
                )

            flow = InstalledAppFlow.from_client_secrets_file(
                str(CREDENTIALS_FILE),
                SCOPES
            )

            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

    return build(
        "gmail",
        "v1",
        credentials=creds
    )


def create_threatmail_label(service):
    """Create the ThreatMail AI Gmail label if it does not exist."""

    label_name = "ThreatMail AI"

    labels = service.users().labels().list(
        userId="me"
    ).execute().get("labels", [])

    for label in labels:
        if label["name"] == label_name:
            print(f"\nLabel already exists: {label_name}")
            return label["id"]

    label_object = {
        "name": label_name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show"
    }

    created_label = service.users().labels().create(
        userId="me",
        body=label_object
    ).execute()

    print(f"\nCreated Gmail label: {label_name}")

    return created_label["id"]


def apply_threat_label(service, message_id):
    """Applies the ThreatMail AI label and removes INBOX."""
    label_id = create_threatmail_label(service)
    
    body = {
        "addLabelIds": [label_id],
        "removeLabelIds": ["INBOX", "SPAM"]
    }
    
    result = service.users().messages().modify(
        userId="me",
        id=message_id,
        body=body
    ).execute()
    
    print(f"\nApplied ThreatMail AI label and removed INBOX for message: {message_id}")
    return result


def release_threat_message(service, message_id):
    """Release a quarantined Gmail message back to the Inbox."""
    label_id = create_threatmail_label(service)
    body = {
        "addLabelIds": ["INBOX"],
        "removeLabelIds": [label_id],
    }
    return service.users().messages().modify(
        userId="me",
        id=message_id,
        body=body
    ).execute()


def release_to_inbox(service, message_id):
    """Ensure a message is in the normal Inbox, including messages Gmail put in Spam."""
    label_id = create_threatmail_label(service)
    body = {
        "addLabelIds": ["INBOX"],
        "removeLabelIds": [label_id, "SPAM"],
    }
    return service.users().messages().modify(
        userId="me",
        id=message_id,
        body=body
    ).execute()


def get_recent_message_ids(service, max_results=20):
    """Return recent message IDs without downloading message bodies."""
    results = service.users().messages().list(
        userId="me",
        q="in:anywhere -in:sent -in:drafts",
        maxResults=max_results,
        includeSpamTrash=True
    ).execute()
    return [m["id"] for m in results.get("messages", [])]


def get_recent_message_raw(service):
    """Retrieve the most recent Gmail message as raw .eml bytes."""

    results = service.users().messages().list(
        userId="me",
        q="in:anywhere",
        maxResults=1,
        includeSpamTrash=True
    ).execute()

    messages = results.get("messages", [])

    if not messages:
        print("No messages found.")
        return None, None

    message_id = messages[0]["id"]

    message = service.users().messages().get(
        userId="me",
        id=message_id,
        format="raw"
    ).execute()

    raw_data = message["raw"]

    email_bytes = base64.urlsafe_b64decode(
        raw_data + "==="
    )

    return message_id, email_bytes


def test_gmail_raw_email():
    """Test retrieving a real Gmail email as raw .eml data."""

    try:
        service = get_gmail_service()

        message_id, email_bytes = get_recent_message_raw(service)

        if email_bytes is None:
            return

        print("\n===================================")
        print(" Gmail Raw Email Retrieved!")
        print("===================================")

        print(f"\nMessage ID: {message_id}")
        print(f"Email size: {len(email_bytes)} bytes")

        print("\nFirst 500 characters:\n")
        print(
            email_bytes.decode(
                "utf-8",
                errors="replace"
            )[:500]
        )

        print("\n===================================")

    except HttpError as error:
        print("\nGmail API error:")
        print(error)

    except Exception as error:
        print("\nError:")
        print(error)


if __name__ == "__main__":
    test_gmail_raw_email()