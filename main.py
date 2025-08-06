import os
import pickle
import base64
import re
import json
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

class PhishingDetector:
    def __init__(self):
        # Gmail API scope
        self.SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 
                       'https://www.googleapis.com/auth/gmail.modify']
        self.service = None
        self.threat_log = []
        
        # Phishing indicators
        self.suspicious_keywords = [
            'urgent', 'immediate action', 'verify account', 'suspended account',
            'click here now', 'limited time', 'act now', 'congratulations',
            'you have won', 'claim your prize', 'confirm your identity',
            'update payment', 'security alert', 'unauthorized access',
            'your account will be closed', 'verify your information'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            # Add more suspicious domains as needed
        ]
        
        self.legitimate_domains = [
            'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
            'apple.com', 'microsoft.com', 'google.com', 'amazon.com',
            'paypal.com', 'ebay.com'
        ]

    def authenticate_gmail(self):
        """Authenticate and create Gmail API service"""
        creds = None
        
        # Check if token.pickle exists (stored credentials)
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        # If no valid credentials, get new ones
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', self.SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save credentials for next run
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        
        self.service = build('gmail', 'v1', credentials=creds)
        print("Gmail API authenticated successfully!")

    def get_recent_emails(self, max_results=50):
        """Fetch recent emails from Gmail"""
        try:
            results = self.service.users().messages().list(
                userId='me', maxResults=max_results).execute()
            messages = results.get('messages', [])
            return messages
        except HttpError as error:
            print(f'An error occurred: {error}')
            return []

    def get_email_content(self, message_id):
        """Extract email content and metadata"""
        try:
            message = self.service.users().messages().get(
                userId='me', id=message_id, format='full').execute()
            
            # Extract headers
            headers = message['payload'].get('headers', [])
            email_data = {
                'id': message_id,
                'subject': '',
                'sender': '',
                'body': '',
                'date': ''
            }
            
            for header in headers:
                if header['name'] == 'Subject':
                    email_data['subject'] = header['value']
                elif header['name'] == 'From':
                    email_data['sender'] = header['value']
                elif header['name'] == 'Date':
                    email_data['date'] = header['value']
            
            # Extract body
            email_data['body'] = self.extract_body(message['payload'])
            
            return email_data
            
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def extract_body(self, payload):
        """Extract email body from payload"""
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
                    break
                elif part['mimeType'] == 'text/html':
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
        else:
            if payload['body'].get('data'):
                body = base64.urlsafe_b64decode(
                    payload['body']['data']).decode('utf-8')
        
        return body

    def analyze_email(self, email_data):
        """Analyze email for phishing indicators"""
        threat_score = 0
        threat_indicators = []
        
        # Check sender domain
        sender_domain = self.extract_domain(email_data['sender'])
        if sender_domain and sender_domain not in self.legitimate_domains:
            threat_score += 2
            threat_indicators.append(f"Unknown sender domain: {sender_domain}")
        
        # Check for suspicious keywords in subject and body
        text_to_check = (email_data['subject'] + ' ' + email_data['body']).lower()
        
        for keyword in self.suspicious_keywords:
            if keyword in text_to_check:
                threat_score += 3
                threat_indicators.append(f"Suspicious keyword: '{keyword}'")
        
        # Check for suspicious URLs
        urls = self.extract_urls(email_data['body'])
        for url in urls:
            domain = self.extract_domain_from_url(url)
            if domain in self.suspicious_domains:
                threat_score += 5
                threat_indicators.append(f"Suspicious URL: {url}")
        
        # Check for urgency indicators
        urgency_patterns = [
            r'act now', r'immediate(ly)?', r'urgent(ly)?', 
            r'expires? (today|soon|in \d+ hours?)',
            r'limited time', r'don\'t delay'
        ]
        
        for pattern in urgency_patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                threat_score += 2
                threat_indicators.append(f"Urgency indicator found")
                break
        
        # Determine threat level
        if threat_score >= 8:
            threat_level = "HIGH"
        elif threat_score >= 5:
            threat_level = "MEDIUM"
        elif threat_score >= 2:
            threat_level = "LOW"
        else:
            threat_level = "SAFE"
        
        return {
            'threat_level': threat_level,
            'threat_score': threat_score,
            'indicators': threat_indicators
        }

    def extract_domain(self, email_address):
        """Extract domain from email address"""
        try:
            return email_address.split('@')[-1].split('>')[0].strip()
        except:
            return None

    def extract_urls(self, text):
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)

    def extract_domain_from_url(self, url):
        """Extract domain from URL"""
        try:
            # Simple domain extraction
            domain = url.split('/')[2]
            return domain
        except:
            return None

    def quarantine_email(self, message_id):
        """Add label to suspicious email (simulating quarantine)"""
        try:
            # Create or get quarantine label
            quarantine_label = self.get_or_create_label("PHISHING_QUARANTINE")
            
            # Add label to email
            self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body={'addLabelIds': [quarantine_label]}
            ).execute()
            
            print(f"Email {message_id} quarantined successfully!")
            
        except HttpError as error:
            print(f'Error quarantining email: {error}')

    def get_or_create_label(self, label_name):
        """Get existing label or create new one"""
        try:
            # Get all labels
            results = self.service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            
            # Check if label exists
            for label in labels:
                if label['name'] == label_name:
                    return label['id']
            
            # Create new label
            label_object = {
                'name': label_name,
                'messageListVisibility': 'show',
                'labelListVisibility': 'labelShow'
            }
            
            created_label = self.service.users().labels().create(
                userId='me', body=label_object).execute()
            
            return created_label['id']
            
        except HttpError as error:
            print(f'Error with labels: {error}')
            return None

    def log_threat(self, email_data, analysis):
        """Log detected threat"""
        threat_entry = {
            'timestamp': datetime.now().isoformat(),
            'email_id': email_data['id'],
            'sender': email_data['sender'],
            'subject': email_data['subject'],
            'threat_level': analysis['threat_level'],
            'threat_score': analysis['threat_score'],
            'indicators': analysis['indicators']
        }
        
        self.threat_log.append(threat_entry)

    def save_threat_report(self):
        """Save threat report to JSON file"""
        report_filename = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_filename, 'w') as f:
            json.dump(self.threat_log, f, indent=2)
        
        print(f"Threat report saved to {report_filename}")

    def run_scan(self):
        """Main scanning function"""
        print("Starting phishing email scan...")
        
        # Authenticate
        self.authenticate_gmail()
        
        # Get recent emails
        messages = self.get_recent_emails()
        print(f"Scanning {len(messages)} recent emails...")
        
        threats_found = 0
        
        for message in messages:
            # Get email content
            email_data = self.get_email_content(message['id'])
            if not email_data:
                continue
            
            # Analyze for threats
            analysis = self.analyze_email(email_data)
            
            # If threat detected, take action
            if analysis['threat_level'] in ['HIGH', 'MEDIUM']:
                threats_found += 1
                print(f"\n🚨 THREAT DETECTED:")
                print(f"From: {email_data['sender']}")
                print(f"Subject: {email_data['subject']}")
                print(f"Threat Level: {analysis['threat_level']}")
                print(f"Threat Score: {analysis['threat_score']}")
                print("Indicators:")
                for indicator in analysis['indicators']:
                    print(f"  - {indicator}")
                
                # Log the threat
                self.log_threat(email_data, analysis)
                
                # Quarantine high-risk emails
                if analysis['threat_level'] == 'HIGH':
                    self.quarantine_email(email_data['id'])
        
        print(f"\n✅ Scan complete! Found {threats_found} potential threats.")
        
        # Save report
        if self.threat_log:
            self.save_threat_report()

if __name__ == "__main__":
    detector = PhishingDetector()
    detector.run_scan()