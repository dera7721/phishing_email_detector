# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Gmail phishing email detection system that uses the Gmail API to scan emails for phishing indicators and automatically quarantine suspicious messages. The system analyzes emails for suspicious keywords, domains, URLs, and urgency patterns to identify potential threats.

## Architecture

The project consists of two main Python scripts:

- **main.py**: Full Gmail integration with authentication, email scanning, threat detection, and quarantine functionality
- **demo_phishing_detection.py**: Standalone demo script that demonstrates the detection logic on sample emails without requiring Gmail API setup

### Core Components

**PhishingDetector Class (main.py:16)**:
- Gmail API authentication and service setup
- Email fetching and content extraction  
- Threat analysis with scoring system
- Email quarantine via Gmail labels
- Threat logging and reporting

**PhishingDetectorDemo Class (demo_phishing_detection.py:7)**:
- Simplified version for testing detection logic
- Sample email analysis without API dependencies

### Detection Logic

The threat scoring system uses:
- Suspicious keywords (3 points each)
- Unknown sender domains (2 points)
- Suspicious URL domains (5 points each)
- Urgency indicators (2 points)

Threat levels: SAFE (0-1), LOW (2-4), MEDIUM (5-7), HIGH (8+)

## Development Commands

### Running the Application

```bash
# Run full Gmail scanning (requires Gmail API setup)
python main.py

# Run demo with sample emails (no API required)
python demo_phishing_detection.py
```

### Dependencies

Install required packages:
```bash
pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
```

## Gmail API Setup

Before running main.py, you need:
1. Google Cloud Console project with Gmail API enabled
2. OAuth 2.0 credentials saved as `credentials.json`
3. First run will generate `token.pickle` for subsequent authentications

## Files Generated

- `threat_report_YYYYMMDD_HHMMSS.json`: Detailed threat analysis reports
- `token.pickle`: Stored Gmail API credentials (auto-generated)

## Security Considerations

This is a defensive security tool designed to detect and quarantine phishing emails. The detection patterns and scoring system help identify suspicious email characteristics commonly used in phishing attacks.