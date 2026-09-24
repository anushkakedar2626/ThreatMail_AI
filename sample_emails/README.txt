ThreatMail AI - Final Four Demo Emails
======================================

Primary final demonstration fixtures:

01_safe_maintenance.eml       Scheduled Maintenance Notice       -> LOW
02_invoice_review_suspicious.eml Invoice Review Reminder         -> SUSPICIOUS
03_executive_gift_card.eml    Confidential: urgent gift card purchase -> HIGH
04_credential_theft.eml      Urgent: Verify your account within 24 hours -> CRITICAL

All four fixtures intentionally use the same RFC 5737 documentation IP:
192.0.2.60

Synthetic location displayed by ThreatMail AI:
Pune, Maharashtra, India

IMPORTANT:
- The IP and location are controlled synthetic demonstration data.
- They do not represent the actual sender's location.
- HIGH and CRITICAL are quarantined from the Gmail Inbox and labeled "ThreatMail AI".
- LOW and SUSPICIOUS remain in the Inbox.
- SPF/DKIM/DMARC pass for LOW and SUSPICIOUS; all three fail for HIGH and CRITICAL.
