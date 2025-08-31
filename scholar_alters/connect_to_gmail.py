import os
import json
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.auth.exceptions import RefreshError
from google_auth_httplib2 import AuthorizedHttp
import httplib2
import logging
from .constants import *  # SCOPES, CLIENTSECRETS_LOCATION fallback if needed
from datetime import datetime, timedelta
from pathlib import Path

# Configure logging
LOG_DIR = "./logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    force=True,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "connect_to_gmail.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def get_service(data_folder='data'):
    """
    Connect to the Gmail API and return an authorized service instance.

    Behaviour:
      - Accepts credentials/token either via env vars (GOOGLE_CREDENTIALS_JSON / GOOGLE_TOKEN_JSON)
        or via files at {data_folder}/credentials.json and {data_folder}/token.json.
      - If running in CI (USE_GITHUB_SECRETS set), the function will NOT attempt interactive OAuth.
        In that case you must provide a valid token.json including a refresh_token.
      - If running locally (USE_GITHUB_SECRETS not set) and no token present, it will run the local
        InstalledAppFlow to obtain credentials interactively.

    Args:
        data_folder (str): Directory to store/read OAuth credentials/tokens.

    Returns:
        service: Authorized Gmail API service instance.
    """
    data_folder = Path(data_folder)
    data_folder.mkdir(parents=True, exist_ok=True)

    token_path = data_folder / "token.json"
    credentials_path = data_folder / "credentials.json"

    # If secrets are provided as env vars, prefer writing them to files (but only if file missing)
    env_token = os.environ.get("GOOGLE_TOKEN_JSON")
    env_creds = os.environ.get("GOOGLE_CREDENTIALS_JSON")
    use_github_secrets = bool(os.environ.get("USE_GITHUB_SECRETS"))

    if env_token and not token_path.exists():
        logger.info("Writing GOOGLE_TOKEN_JSON (from env) -> %s", token_path)
        # Expect env token to be raw JSON string (not base64). If you base64'd it in workflow, decode before setting env.
        token_path.write_text(env_token)

    if env_creds and not credentials_path.exists():
        logger.info("Writing GOOGLE_CREDENTIALS_JSON (from env) -> %s", credentials_path)
        credentials_path.write_text(env_creds)

    creds = None

    # Load existing token if present
    if token_path.exists():
        try:
            logger.info("Loading credentials from %s", token_path)
            creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        except Exception as e:
            logger.warning("Failed to load token.json: %s", e)
            creds = None

    # If token missing or invalid, try to refresh or create new depending on environment
    if not creds or not creds.valid:
        # If we have expired creds and a refresh token, try to refresh
        if creds and creds.expired and getattr(creds, "refresh_token", None):
            try:
                logger.info("Refreshing expired OAuth credentials.")
                creds.refresh(Request())
            except RefreshError as e:
                logger.error("RefreshError while refreshing credentials: %s", e)
                # On CI we cannot do interactive flow: instruct user
                if use_github_secrets:
                    raise ValueError(
                        "Refresh failed while running in CI. Provide a valid token.json containing a refresh_token "
                        "via the GOOGLE_TOKEN_JSON secret or regenerate token.json locally with offline scope."
                    ) from e
                else:
                    # try interactive flow as fallback for local dev
                    logger.warning("Attempting interactive flow as a fallback (local dev).")
                    creds = _run_local_flow(credentials_path)
        else:
            # No valid creds present (either no token.json or no refresh token)
            if use_github_secrets:
                # On CI we cannot run interactive OAuth. Require token.json to be provided.
                raise ValueError(
                    "No valid OAuth token found in CI. Ensure you supply a token.json (including a refresh_token) "
                    "via the secret GOOGLE_TOKEN_JSON or run the local flow to create token.json and store it as a secret."
                )
            else:
                # Local development: run interactive OAuth flow to create token.json
                logger.info("No valid OAuth credentials found. Starting local interactive OAuth flow.")
                creds = _run_local_flow(credentials_path)

        # Save token if we have credentials now
        if creds and creds.valid:
            try:
                with token_path.open("w") as tf:
                    json.dump(json.loads(creds.to_json()), tf)
                logger.info("Credentials saved to %s", token_path)
            except Exception as e:
                logger.warning("Failed to save credentials to %s: %s", token_path, e)

    # At this point creds should be set and valid
    if not creds or not creds.valid:
        raise ValueError("Failed to obtain valid Gmail credentials. Check logs and your secrets/files.")

    # Build and return the Gmail service with network timeout
    http = AuthorizedHttp(creds, http=httplib2.Http(timeout=30))
    service = build('gmail', 'v1', http=http)
    logger.info("Gmail service created successfully.")
    return service


def _run_local_flow(credentials_path):
    """
    Run interactive local OAuth flow and return credentials.
    credentials_path: Path to client secrets (or fallback to CLIENTSECRETS_LOCATION).
    """
    # prefer credentials_path if exists, otherwise try CLIENTSECRETS_LOCATION from constants
    client_secrets_file = None
    if credentials_path.exists():
        client_secrets_file = str(credentials_path)
    elif CLIENTSECRETS_LOCATION and Path(CLIENTSECRETS_LOCATION).exists():
        client_secrets_file = str(CLIENTSECRETS_LOCATION)
    else:
        raise ValueError(
            "Client secrets file not found. Place a credentials.json at the data folder or "
            "set CLIENTSECRETS_LOCATION in your constants.py."
        )

    logger.info("Starting InstalledAppFlow using client secrets: %s", client_secrets_file)
    flow = InstalledAppFlow.from_client_secrets_file(client_secrets_file, SCOPES)
    creds = flow.run_local_server(port=0, access_type='offline', prompt='consent')
    return creds


def list_messages_with_email_ids(service, user_id, email_ids=[]):
    """
    Retrieve a list of message objects from the user's mailbox using the specified email IDs.
    """
    try:
        messages = []
        for email_id in email_ids:
            message = service.users().messages().get(userId=user_id, id=email_id).execute()
            messages.append(message)
        return messages
    except Exception as error:
        logger.error(f'An error occurred while listing messages: {error}')
        return []


def get_emails_from_sender_within_day(service, user_id, sender_email='scholaralerts-noreply@google.com'):
    """
    Retrieve email IDs received within the last day from a specified sender.
    """
    try:
        now = datetime.utcnow()
        yesterday = now - timedelta(days=1)
        formatted_yesterday = yesterday.isoformat() + 'Z'
        logger.info("Querying emails since %s", formatted_yesterday)

        results = service.users().messages().list(
            userId=user_id,
            q=f'from:{sender_email} newer_than:1d'
        ).execute()
        logger.debug("Gmail API list result: %s", results)

        messages = results.get('messages', [])
        email_ids = [message['id'] for message in messages]
        logger.info("Found email ids: %s", email_ids)

        return email_ids
    except Exception as error:
        logger.error(f'An error occurred while retrieving emails: {error}')
        return []


def get_message(service, user_id, msg_id):
    """
    Retrieve the full message using the given message ID.
    """
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id).execute()
        return message
    except Exception as error:
        logger.error(f'An error occurred while retrieving message {msg_id}: {error}')
        return None