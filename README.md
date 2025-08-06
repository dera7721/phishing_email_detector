🛡️ Phishing Email Detection System

An automated email security solution that integrates with Gmail API to detect and quarantine potential phishing attempts using advanced threat detection algorithms.

🎯 Project Overview

This system automatically scans Gmail inboxes, analyzes emails for phishing indicators, and takes protective action against suspicious messages. Built with Python and Google's Gmail API, it demonstrates cybersecurity principles and automated threat response.

✨ Key Features



🔍 Multi-Layer Threat Detection: Analyzes sender domains, keywords, URL patterns, and urgency indicators

⚡ Real-Time Processing: Scans 50+ emails per execution with detailed threat scoring

🛡️ Automated Quarantine: Flags and isolates high-risk emails automatically

📊 Comprehensive Reporting: Generates JSON reports with timestamps and threat analysis

🔐 Secure Authentication: Uses OAuth2 for secure Gmail API integration

🎚️ Configurable Sensitivity: Adjustable threat thresholds and detection rules



🛠️ Technical Implementation

Core Technologies



Python 3.7+: Primary development language

Gmail API: Email access and manipulation

OAuth2: Secure authentication protocol

JSON: Structured data logging and reporting

Regular Expressions: Pattern matching for threat detection



Detection Algorithms



Domain Analysis: Validates sender domains against whitelist/blacklist

Keyword Detection: Identifies common phishing terminology

URL Inspection: Analyzes embedded links for suspicious patterns

Urgency Scoring: Detects pressure tactics and time-sensitive language

Multi-Factor Scoring: Combines indicators for accurate threat assessment



📋 Prerequisites



Python 3.7 or higher

Google Cloud Console account

Gmail account for testing



🚀 Installation \& Setup

1\. Clone the Repository

bashgit clone https://github.com/yourusername/phishing-email-detector.git

cd phishing-email-detector

2\. Install Dependencies

bashpip install -r requirements.txt

3\. Google Cloud Console Setup



Create a new project at Google Cloud Console

Enable the Gmail API

Create OAuth2 credentials

Download credentials.json and place in project root

Add yourself as a test user in OAuth consent screen



4\. Run the Application

bash# Test the detection logic (no API required)

python demo\_phishing\_detection.py



\# Full Gmail integration

python main.py

📊 Sample Output

🚨 THREAT DETECTED:

From: urgent-security@suspicious-bank.net

Subject: URGENT: Your Account Will Be Suspended!

Threat Level: HIGH

Threat Score: 13

Indicators:

  • Unknown sender domain: suspicious-bank.net

  • Suspicious keyword: 'urgent'

  • Suspicious keyword: 'immediate action'

  • Suspicious URL domain: bit.ly

🛡️ ACTION: Email quarantined successfully

🔧 Configuration

Adjusting Sensitivity

Modify threat scoring in main.py:



HIGH: Score ≥ 8 (Quarantined)

MEDIUM: Score ≥ 5 (Flagged)

LOW: Score ≥ 2 (Logged)

SAFE: Score < 2



Adding Custom Keywords

Edit the suspicious\_keywords list to include domain-specific terms:

pythonself.suspicious\_keywords = \[

    'urgent', 'immediate action', 'verify account',

    # Add your custom keywords here

]

📈 Performance Metrics



Scan Speed: ~50 emails in <30 seconds

Detection Rate: Successfully identifies common phishing patterns

False Positive Management: Configurable sensitivity reduces unwanted alerts

Scalability: Processes thousands of emails efficiently



🛡️ Security Features



OAuth2 Authentication: Secure, token-based Gmail access

Local Processing: Email content analyzed locally for privacy

Encrypted Storage: Authentication tokens securely cached

No Data Retention: Emails processed in memory only



🎓 Learning Outcomes

This project demonstrates:



API Integration: Working with external APIs and authentication

Cybersecurity Principles: Threat detection and automated response

Data Processing: Email parsing and content analysis

Security Best Practices: Secure credential management

Professional Development: Code organization and documentation



📝 Future Enhancements



 Machine learning model integration for advanced detection

 Web dashboard for monitoring and management

 Database integration for historical analysis

 Multi-email provider support (Outlook, Yahoo)

 Real-time notification system

 Whitelist management interface



🤝 Contributing



Fork the repository

Create a feature branch (git checkout -b feature/enhancement)

Commit your changes (git commit -am 'Add new feature')

Push to the branch (git push origin feature/enhancement)

Create a Pull Request



⚠️ Important Notes



Never commit credentials.json - This contains sensitive API keys

Test thoroughly before deploying in production environment

Review quarantined emails regularly to prevent false positives

Keep dependencies updated for security patches



📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

👤 Author

Dera Egbumokei



LinkedIn: www.linkedin.com/in/dera-egbumokei-6a1689340

Email: degbumokie@gmail.com







⭐ Star this repository if you found it helpful!hishing Email Detection System

An automated email security solution that integrates with Gmail API to detect and quarantine potential phishing attempts using advanced threat detection algorithms.

🎯 Project Overview

This system automatically scans Gmail inboxes, analyzes emails for phishing indicators, and takes protective action against suspicious messages. Built with Python and Google's Gmail API, it demonstrates cybersecurity principles and automated threat response.

✨ Key Features



🔍 Multi-Layer Threat Detection: Analyzes sender domains, keywords, URL patterns, and urgency indicators

⚡ Real-Time Processing: Scans 50+ emails per execution with detailed threat scoring

🛡️ Automated Quarantine: Flags and isolates high-risk emails automatically

📊 Comprehensive Reporting: Generates JSON reports with timestamps and threat analysis

🔐 Secure Authentication: Uses OAuth2 for secure Gmail API integration

🎚️ Configurable Sensitivity: Adjustable threat thresholds and detection rules



🛠️ Technical Implementation

Core Technologies



Python 3.7+: Primary development language

Gmail API: Email access and manipulation

OAuth2: Secure authentication protocol

JSON: Structured data logging and reporting

Regular Expressions: Pattern matching for threat detection



Detection Algorithms



Domain Analysis: Validates sender domains against whitelist/blacklist

Keyword Detection: Identifies common phishing terminology

URL Inspection: Analyzes embedded links for suspicious patterns

Urgency Scoring: Detects pressure tactics and time-sensitive language

Multi-Factor Scoring: Combines indicators for accurate threat assessment



📋 Prerequisites



Python 3.7 or higher

Google Cloud Console account

Gmail account for testing



🚀 Installation \& Setup

1\. Clone the Repository

bashgit clone https://github.com/yourusername/phishing-email-detector.git

cd phishing-email-detector

2\. Install Dependencies

bashpip install -r requirements.txt

3\. Google Cloud Console Setup



Create a new project at Google Cloud Console

Enable the Gmail API

Create OAuth2 credentials

Download credentials.json and place in project root

Add yourself as a test user in OAuth consent screen



4\. Run the Application

bash# Test the detection logic (no API required)

python demo\_phishing\_detection.py



\# Full Gmail integration

python main.py

📊 Sample Output

🚨 THREAT DETECTED:

From: urgent-security@suspicious-bank.net

Subject: URGENT: Your Account Will Be Suspended!

Threat Level: HIGH

Threat Score: 13

Indicators:

  • Unknown sender domain: suspicious-bank.net

  • Suspicious keyword: 'urgent'

  • Suspicious keyword: 'immediate action'

  • Suspicious URL domain: bit.ly

🛡️ ACTION: Email quarantined successfully

🔧 Configuration

Adjusting Sensitivity

Modify threat scoring in main.py:



HIGH: Score ≥ 8 (Quarantined)

MEDIUM: Score ≥ 5 (Flagged)

LOW: Score ≥ 2 (Logged)

SAFE: Score < 2



Adding Custom Keywords

Edit the suspicious\_keywords list to include domain-specific terms:

pythonself.suspicious\_keywords = \[

    'urgent', 'immediate action', 'verify account',

    # Add your custom keywords here

]

📈 Performance Metrics



Scan Speed: ~50 emails in <30 seconds

Detection Rate: Successfully identifies common phishing patterns

False Positive Management: Configurable sensitivity reduces unwanted alerts

Scalability: Processes thousands of emails efficiently



🛡️ Security Features



OAuth2 Authentication: Secure, token-based Gmail access

Local Processing: Email content analyzed locally for privacy

Encrypted Storage: Authentication tokens securely cached

No Data Retention: Emails processed in memory only



🎓 Learning Outcomes

This project demonstrates:



API Integration: Working with external APIs and authentication

Cybersecurity Principles: Threat detection and automated response

Data Processing: Email parsing and content analysis

Security Best Practices: Secure credential management

Professional Development: Code organization and documentation



📝 Future Enhancements



 Machine learning model integration for advanced detection

 Web dashboard for monitoring and management

 Database integration for historical analysis

 Multi-email provider support (Outlook, Yahoo)

 Real-time notification system

 Whitelist management interface



🤝 Contributing



Fork the repository

Create a feature branch (git checkout -b feature/enhancement)

Commit your changes (git commit -am 'Add new feature')

Push to the branch (git push origin feature/enhancement)

Create a Pull Request



⚠️ Important Notes



Never commit credentials.json - This contains sensitive API keys

Test thoroughly before deploying in production environment

Review quarantined emails regularly to prevent false positives

Keep dependencies updated for security patches



📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

👤 Author

Dera Egbumokei



LinkedIn: www.linkedin.com/in/dera-egbumokei-6a1689340

Email: degbumokie@gmail.com







⭐ Star this repository if you found it helpful!

