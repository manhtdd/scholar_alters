import base64
import json
from html.parser import HTMLParser
from os import path as ospath, makedirs
import logging
import time
import argparse
from .constants import *  # Contains constants like DATA_FOLDER, PAPERS_LABEL, etc.
from .connect_to_gmail import *  # Contains Gmail API functions

# Set up logging to both a file and the console
# Ensure data folder exists
if not os.path.exists("./logs"):
    os.makedirs("./logs")
logging.basicConfig(
    force=True,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler("./logs/parse_gmail_message.log"),  # Logs to file
        logging.StreamHandler()  # Logs to console
    ]
)

def clean_title(st):
    """
    Cleans and formats the title text by removing unwanted characters.
    """
    if st[0] == '[':
        st = st[st.find(']') + 1:]
    st = st.replace('\\xe2\\x80\\x8f', '')
    return st.strip()

class Paper:
    """
    Represents a research paper extracted from an email.
    """
    def __init__(self, ref):
        self.title = ''
        self.first_labels = []
        self.second_labels = []
        self.data = ''
        self.link = ''
        self.idx = ''
        self.ref = [ref]  # Email subjects (reference) where the paper was found
        
    def __str__(self):
        return f"Title: {self.title}\n" \
               f"Data: {self.data}\n" \
               f"Link: {self.link}\n" \
               f"References: {', '.join(self.ref)}\n"
               
    def add_label(self, label):
        """
        Adds the label of the paper after processing.
        """
        if label in FIRST_LEVEL_KEYWORDS and label not in self.first_labels:
            self.first_labels.append(label)
        
        if label in SECOND_LEVEL_KEYWORDS  and label not in self.second_labels:
            self.second_labels.append(label)
               
    def _generate_label(self):
        title = self.title.lower()
            # Check first-level keywords
        for first_label, patterns in FIRST_LEVEL_KEYWORDS.items():
            for pattern in patterns:
                if pattern.lower() in title:
                    self.add_label(first_label)
        
        # Check second-level keywords
        for second_label, patterns in SECOND_LEVEL_KEYWORDS.items():
            for pattern in patterns:
                if pattern.lower() in title:
                    self.add_label(second_label)
    
    def add_title(self, data):
        """
        Adds the title of the paper after cleaning.
        """
        self.title += clean_title(data) + " "
        self.idx = self.title.strip().upper()
        self._generate_label()
        
    def add_data(self, data):
        """
        Adds metadata or content of the paper.
        """
        self.data += data + "\n"
        
    def add_ref(self, ref):
        """
        Adds a reference to the paper.
        """
        self.ref.append(ref)
        
    def to_dict(self):
        """
        Converts the paper object to a dictionary format for JSONL export.
        """
        return {
            "title": self.title.strip(),
            "first_label": self.first_labels,
            "second_label": self.second_labels,
            "data": self.data.strip(),
            "link": self.link,
            "ref": self.ref
        }

class PapersHTMLParser(HTMLParser):
    """
    Parses the HTML content of an email to extract paper details.
    """
    def __init__(self, author_ref):
        super().__init__()
        self.is_title = False
        self.papers = []
        self.ref = author_ref
        
    def handle_starttag(self, tag, attrs):
        """
        Handles the start of an HTML tag and checks for paper titles and links.
        """
        if tag == 'h3':  # h3 tag is assumed to indicate a new paper
            self.papers.append(Paper(self.ref))
            self.is_title = True
        if tag == 'a' and self.is_title:
            for attr in attrs:
                if attr[0].lower() == 'href':
                    self.papers[-1].link = attr[1]  # Set paper's link

    def handle_endtag(self, tag):
        """
        Handles the end of an HTML tag.
        """
        if tag == 'h3':
            self.is_title = False  # End of title section

    def handle_data(self, data):
        """
        Handles the raw text data within HTML tags.
        """
        if len(self.papers) > 0:
            if self.is_title:
                self.papers[-1].add_title(data)  # Add title
            else:
                self.papers[-1].add_data(data)  # Add other content

class PaperAggregator:
    """
    Aggregates and manages papers, ensuring no duplicates.
    """
    def __init__(self):
        self.paper_list = []
        
    def add(self, paper):
        """
        Adds a paper to the list, combining references for duplicates.
        """
        idx = self.exists_by_title(paper.title)
        
        if idx >= 0:
            self.paper_list[idx].add_ref(paper.ref[0])
        else:
            if len(paper.title) != 0:
                self.paper_list.append(paper)
            
    def remove(self, paper):
        """
        Removes a paper from the list.
        """
        try:
            idx = self.paper_list.index(paper)
            self.paper_list.pop(idx)
        except ValueError:
            pass

    def exists_by_title(self, title):
        """
        Checks if a paper with the given title exists in the paper_list.

        Args:
            title (str): The title of the paper to search for.

        Returns:
            bool: True if a paper with the title exists, False otherwise.
        """
        index = 0
        for paper in self.paper_list:
            if paper.title == title:
                return index
            index += 1
        return -1

def process_once():
    # Ensure data folder exists
    if not ospath.exists(DATA_FOLDER):
        makedirs(DATA_FOLDER)

    # Connect to Gmail API
    service = get_service(DATA_FOLDER)

    # Get all messages with specific labels
    emails = get_emails_from_sender_within_day(service, 'me')
    messages = list_messages_with_email_ids(service, "me", emails)
    if messages:
        logging.info('Found %d messages', len(messages))
    else:
        logging.info('No messages found')
        return False

    # Initialize Paper Aggregator
    pa = PaperAggregator()

    # Prepare a list to store metadata about processed emails
    email_metadata = []

    # Parse emails for papers
    msg_count = 0
    for msg in messages:
        msg_count += 1
        logging.info(f"{msg_count}/{len(messages)}")
        msg_content = get_message(service, "me", msg['id'])
        logging.info(msg_content)

        try:
            msg_str = base64.urlsafe_b64decode(msg_content['payload']['body']['data'].encode('ASCII'))
        except KeyError:
            logging.warning("No body data")
            continue  # Skip if email has no body data

        # Extract email subject
        msg_title = ''
        for h in msg_content['payload']['headers']:
            if h['name'] == 'Subject':
                msg_title = h['value']
                logging.info(msg_title)

        if len(msg_title) == 0:
            logging.warning("No title")
            continue

        # Parse the HTML content of the email
        parser = PapersHTMLParser(msg_title)
        parser.feed(str(msg_str))

        # Add parsed papers to the aggregator
        for paper in parser.papers:
            logging.info(paper)
            pa.add(paper)

        # Store metadata about this processed email
        email_metadata.append({
            "message_id": msg['id'],
            "subject": msg_title,
            "date": next(h['value'] for h in msg_content['payload']['headers'] if h['name'] == 'Date'),
            "processed": True
        })

    # Export papers to JSONL file
    papers_jsonl_path = ospath.join(DATA_FOLDER, 'papers.jsonl')
    with open(papers_jsonl_path, 'w', encoding='utf-8') as jsonl_file:
        for paper in pa.paper_list:
            json.dump(paper.to_dict(), jsonl_file)
            jsonl_file.write('\n')

    # Export email metadata to JSONL file
    emails_jsonl_path = ospath.join(DATA_FOLDER, 'processed_emails.jsonl')
    with open(emails_jsonl_path, 'w', encoding='utf-8') as jsonl_file:
        for email_data in email_metadata:
            json.dump(email_data, jsonl_file)
            jsonl_file.write('\n')

    logging.info("Export completed: Papers and email metadata have been written to JSONL files.")
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse Gmail messages for papers.')
    parser.add_argument('--watch', action='store_true', help='Run continuously and poll at a fixed interval.')
    parser.add_argument('--interval', type=int, default=900, help='Polling interval in seconds when running with --watch (default: 900).')
    args = parser.parse_args()

    if not args.watch:
        process_once()
    else:
        logging.info(f"Starting watch mode with interval={args.interval}s")
        while True:
            try:
                process_once()
            except Exception as error:
                logging.error(f'Unhandled error during watch loop: {error}')
            time.sleep(max(1, args.interval))