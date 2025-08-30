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
from .constants import *
from datetime import datetime, timedelta

# Configure logging
if not os.path.exists("./logs"):
    os.makedirs("./logs")
logging.basicConfig(
    force=True,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler("./logs/connect_to_gmail.log"),
        logging.StreamHandler()
    ]
)

def get_service(data_folder='.'):
    """
    Connect to the Gmail API and return an authorized service instance.
    Supports OAuth flow (local and CI with GitHub Secrets).
    
    Args:
        data_folder (str): Directory to store OAuth tokens.
    
    Returns:
        service: Authorized Gmail API service instance.
    """
    creds = None
    token_filename = os.path.join(data_folder, 'token.json')

    # Load token from GOOGLE_TOKEN_JSON if it exists and token_filename doesn't
    if not os.path.exists(token_filename) and os.environ.get('GOOGLE_TOKEN_JSON'):
        with open(token_filename, 'w') as token_file:
            token_file.write(os.environ.get('GOOGLE_TOKEN_JSON'))
            logging.info(f"Token loaded from GOOGLE_TOKEN_JSON to {token_filename}")

    if os.environ.get('USE_GITHUB_SECRETS'):
        logging.info("Using GitHub Secrets for authentication (OAuth).")
        credentials_json = os.environ.get('GOOGLE_CREDENTIALS_JSON')
        if not credentials_json:
            logging.error("GOOGLE_CREDENTIALS_JSON environment variable not set.")
            raise ValueError("Missing GitHub secret for credentials.")

        temp_credentials_file = os.path.join(data_folder, 'temp_credentials.json')
        with open(temp_credentials_file, 'w') as f:
            f.write(credentials_json)

        try:
            # Use the temporary credentials file for OAuth flow
            flow = InstalledAppFlow.from_client_secrets_file(temp_credentials_file, SCOPES)
            creds = flow.run_local_server(port=0, access_type='offline', prompt='consent')

            # Save the credentials for future use
            with open(token_filename, 'w') as token_file:
                json.dump(json.loads(creds.to_json()), token_file)
                logging.info(f"OAuth credentials saved to {token_filename}")
        except Exception as e:
            logging.error(f"Error during OAuth flow with GitHub Secrets: {e}")
            raise
        finally:
            if os.path.exists(temp_credentials_file):
                os.remove(temp_credentials_file)
    else:
        # Use OAuth flow for local development
        logging.info("Using OAuth flow for local development.")
        if os.path.exists(token_filename):
            logging.info(f"Loading credentials from {token_filename}")
            creds = Credentials.from_authorized_user_file(token_filename, SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                logging.info("Refreshing expired OAuth credentials.")
                try:
                    creds.refresh(Request())
                except RefreshError as e:
                    logging.warning(f"Refresh token failed: {e}. Initiating new local server flow.")
                    flow = InstalledAppFlow.from_client_secrets_file(CLIENTSECRETS_LOCATION, SCOPES)
                    creds = flow.run_local_server(port=0, access_type='offline', prompt='consent')
            else:
                logging.info("No valid OAuth credentials found. Initiating new local server flow.")
                flow = InstalledAppFlow.from_client_secrets_file(CLIENTSECRETS_LOCATION, SCOPES)
                creds = flow.run_local_server(port=0, access_type='offline', prompt='consent')

            with open(token_filename, 'w') as token_file:
                json.dump(json.loads(creds.to_json()), token_file)
                logging.info(f"OAuth credentials saved to {token_filename}")

    # Build and return the Gmail service with network timeout
    http = AuthorizedHttp(creds, http=httplib2.Http(timeout=30))
    service = build('gmail', 'v1', http=http)
    return service

def list_messages_with_email_ids(service, user_id, email_ids=[]):
    """
    Retrieve a list of message objects from the user's mailbox using the specified email IDs.

    Args:
        service: Authorized Gmail API service instance.
        user_id (str): User's email address. Use "me" to indicate the authenticated user.
        email_ids (list): List of email IDs to retrieve messages.

    Returns:
        messages (list): List of message objects, each containing the details of the message.
    """
    try:
        messages = []

        # Fetch messages based on the provided email IDs
        for email_id in email_ids:
            message = service.users().messages().get(userId=user_id, id=email_id).execute()
            messages.append(message)  # Append the full message object to the list

        return messages

    except Exception as error:
        logging.error(f'An error occurred while listing messages: {error}')
        return []


def get_emails_from_sender_within_day(service, user_id, sender_email='scholaralerts-noreply@google.com'):
    """
    Retrieve email IDs received within the last day from a specified sender.

    Args:
        service: Authorized Gmail API service instance.
        user_id (str): User's email address. Use "me" to indicate the authenticated user.
        sender_email (str): Email address of the sender to filter messages.

    Returns:
        email_ids (list): List of email IDs received within the last day from the specified sender.
    """
    try:
        # Calculate the timestamp for 24 hours ago
        now = datetime.utcnow()
        yesterday = now - timedelta(days=1)
        formatted_yesterday = yesterday.isoformat() + 'Z'  # 'Z' indicates UTC time
        logging.info(formatted_yesterday)

        # Call the Gmail API to fetch the emails
        results = service.users().messages().list(
            userId=user_id,
            q=f'from:{sender_email} newer_than:1d'
        ).execute()
        logging.info(results)

        messages = results.get('messages', [])
        email_ids = [message['id'] for message in messages]  # Extract email IDs
        logging.info(email_ids)

        return email_ids
    except Exception as error:
        logging.error(f'An error occurred while retrieving emails: {error}')
        return []


def get_message(service, user_id, msg_id):
    """
    Retrieve the full message using the given message ID.

    Args:
        service: Authorized Gmail API service instance.
        user_id (str): User's email address. Use "me" to indicate the authenticated user.
        msg_id (str): The ID of the message to retrieve.

    Returns:
        message (dict): The full message object.
    """
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id).execute()
        return message
    except Exception as error:
        logging.error(f'An error occurred while retrieving message {msg_id}: {error}')
