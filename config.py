# ========================================
# File: config.py
# ========================================
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME", "gpt-4o-mini")
    
    # Phishing indicators
    SUSPICIOUS_KEYWORDS = [
        # Account & Identity
        'verify', 'verify identity', 'identity verification', 'account review',
        'authentication required', 'multi-factor', '2fa', 'otp', 'one-time password',

        # Finance
        'billing issue', 'payment declined', 'failed payment',
        'outstanding balance', 'refund pending', 'invoice attached',
        'transaction alert', 'wire transfer',

        # Delivery / Logistics
        'package delivery', 'delivery attempt', 'shipment on hold',
        'customs clearance', 'track your package',
        'dhl', 'fedex', 'ups',

        # Corporate IT
        'mailbox full', 'password expiration', 'security update required',
        'email quarantine', 'admin request', 'it support', 'helpdesk',

        # Urgency
        'urgent', 'immediate action', 'action required',
        'attention needed', 'final notice', 'within 24 hours',

        # Interaction triggers
        'click here', 'click below', 'download attachment',
        'open document', 'scan qr code', 'confirm your account'
    ]
    
    SUSPICIOUS_TLDS = [
        # Free / high abuse
        '.tk', '.ml', '.ga', '.cf', '.gq',

        # Cheap / disposable
        '.xyz', '.top', '.online', '.site',
        '.store', '.live', '.stream',

        # Clickbait / action-based
        '.click', '.link', '.work', '.zip', '.mov',

        # Fake business
        '.support', '.help', '.services',
        '.company', '.business', '.center',

        # Geo-risk
        '.ru', '.cn'
    ]
    
    RESERVED_TLDS = [
        '.example',
        '.test',
        '.invalid',
        '.localhost'
    ]
    
    LEGITIMATE_DOMAINS = {
        # Payments
        'paypal': 'paypal.com',
        'stripe': 'stripe.com',
        'visa': 'visa.com',
        'mastercard': 'mastercard.com',

        # Big Tech
        'google': 'google.com',
        'microsoft': 'microsoft.com',
        'apple': 'apple.com',
        'amazon': 'amazon.com',
        'meta': 'meta.com',

        # Cloud & Identity
        'aws': 'aws.amazon.com',
        'azure': 'azure.microsoft.com',
        'office365': 'office.com',
        'outlook': 'outlook.com',
        'gmail': 'mail.google.com',

        # Logistics
        'dhl': 'dhl.com',
        'fedex': 'fedex.com',
        'ups': 'ups.com',
        'usps': 'usps.com',

        # Banks
        'bank': [
            'bankofamerica.com',
            'chase.com',
            'wellsfargo.com',
            'citibank.com',
            'hsbc.com'
        ]
    }
