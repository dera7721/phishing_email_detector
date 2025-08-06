# demo_phishing_detection.py
# This script demonstrates the phishing detection logic without needing Gmail API

import json
from datetime import datetime

class PhishingDetectorDemo:
    def __init__(self):
        # Same detection logic as main script
        self.suspicious_keywords = [
            'urgent', 'immediate action', 'verify account', 'suspended account',
            'click here now', 'limited time', 'act now', 'congratulations',
            'you have won', 'claim your prize', 'confirm your identity',
            'update payment', 'security alert', 'unauthorized access',
            'your account will be closed', 'verify your information'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'
        ]
        
        self.legitimate_domains = [
            'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
            'apple.com', 'microsoft.com', 'google.com', 'amazon.com'
        ]

    def analyze_sample_email(self, email_data):
        """Same analysis logic as main script"""
        threat_score = 0
        threat_indicators = []
        
        # Check sender domain
        sender_domain = self.extract_domain(email_data['sender'])
        if sender_domain and sender_domain not in self.legitimate_domains:
            threat_score += 2
            threat_indicators.append(f"Unknown sender domain: {sender_domain}")
        
        # Check for suspicious keywords
        text_to_check = (email_data['subject'] + ' ' + email_data['body']).lower()
        
        for keyword in self.suspicious_keywords:
            if keyword in text_to_check:
                threat_score += 3
                threat_indicators.append(f"Suspicious keyword: '{keyword}'")
        
        # Check for suspicious URLs
        if 'http' in email_data['body']:
            for domain in self.suspicious_domains:
                if domain in email_data['body']:
                    threat_score += 5
                    threat_indicators.append(f"Suspicious URL domain: {domain}")
        
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

    def run_demo(self):
        """Demonstrate detection on sample emails"""
        print("🔍 PHISHING EMAIL DETECTION SYSTEM DEMO")
        print("=" * 50)
        
        # Sample emails for testing
        sample_emails = [
            {
                'sender': 'security@legitimate-bank.com',
                'subject': 'Monthly Statement Available',
                'body': 'Your monthly statement is now available. Please log in to view it.'
            },
            {
                'sender': 'urgent-security@suspicious-bank.net',
                'subject': 'URGENT: Your Account Will Be Suspended!',
                'body': 'Immediate action required! Your account will be closed in 24 hours. Click here now to verify your information: http://bit.ly/fake-bank-login'
            },
            {
                'sender': 'noreply@paypal.com',
                'subject': 'Payment Confirmation',
                'body': 'Thank you for your recent payment. Transaction ID: 12345'
            },
            {
                'sender': 'winner@lottery-scam.biz',
                'subject': 'Congratulations! You Have Won $1,000,000!',
                'body': 'You have won our international lottery! Act now to claim your prize. Limited time offer expires today!'
            },
            {
                'sender': 'support@fake-microsoft.org',
                'subject': 'Security Alert: Unauthorized Access Detected',
                'body': 'We detected unauthorized access to your account. Verify your identity immediately by clicking: http://tinyurl.com/fake-ms-login'
            }
        ]
        
        threats_detected = 0
        
        for i, email in enumerate(sample_emails, 1):
            print(f"\n📧 EMAIL #{i}")
            print(f"From: {email['sender']}")
            print(f"Subject: {email['subject']}")
            
            # Analyze email
            analysis = self.analyze_sample_email(email)
            
            print(f"🔍 Analysis Result:")
            print(f"   Threat Level: {analysis['threat_level']}")
            print(f"   Threat Score: {analysis['threat_score']}")
            
            if analysis['indicators']:
                print(f"   🚨 Warning Indicators:")
                for indicator in analysis['indicators']:
                    print(f"     • {indicator}")
                threats_detected += 1
            else:
                print(f"   ✅ No threats detected")
            
            # Show action taken
            if analysis['threat_level'] == 'HIGH':
                print(f"   🛡️ ACTION: Email would be QUARANTINED")
            elif analysis['threat_level'] in ['MEDIUM', 'LOW']:
                print(f"   ⚠️ ACTION: Email flagged for review")
            
            print("-" * 40)
        
        # Summary
        print(f"\n📊 SCAN SUMMARY:")
        print(f"Total emails scanned: {len(sample_emails)}")
        print(f"Threats detected: {threats_detected}")
        print(f"Safe emails: {len(sample_emails) - threats_detected}")
        
        # Create sample report
        report = {
            'scan_date': datetime.now().isoformat(),
            'total_scanned': len(sample_emails),
            'threats_found': threats_detected,
            'detection_rate': f"{(threats_detected/len(sample_emails)*100):.1f}%"
        }
        
        print(f"\n📋 DETECTION STATISTICS:")
        for key, value in report.items():
            print(f"   {key.replace('_', ' ').title()}: {value}")

if __name__ == "__main__":
    demo = PhishingDetectorDemo()
    demo.run_demo()