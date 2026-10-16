"""
Curated sample emails with full RFC822 headers and bodies
for one-click demonstration in the UI.
"""

SAMPLE_EMAILS = {
    "1. High Risk: Spoofed PayPal Security Suspension (Full Headers)": """Received: from mail-relay.fake-host.net ([185.193.125.10])
    by mx.customer-domain.com with ESMTPS id 4Zx8Lp19
    for <victim.user@targetcorp.in>; Wed, 15 Oct 2026 14:22:10 +0530
From: "PayPal Security Team" <security-alerts@paypal-update-center.net>
To: <victim.user@targetcorp.in>
Reply-To: <disputes-resolution@secure-banking-alert.xyz>
Subject: URGENT: Your PayPal Account Has Been Suspended - Action Required Within 24 Hours
Date: Wed, 15 Oct 2026 14:21:45 +0530
Message-ID: <20261015142145.98234@paypal-update-center.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Dear Verified Customer,

We detected unauthorized access to your account from an unrecognized IP address. For your security, your account privileges have been temporarily suspended.

You are required to verify your password, billing address, and debit card credentials immediately. If you fail to verify your account within 24 hours, your account will be permanently deactivated and remaining balances will be frozen.

Please click the secure resolution link below to unlock your account:
http://paypal-update-center.net/login?token=89234710

Thank you for your prompt cooperation,
PayPal Global Fraud Prevention Department
""",

    "2. High Risk: CEO Wire Transfer & Gift Card Fraud": """Received: from mail-wm1-f67.google.com ([198.51.100.42])
    by mail.enterprise.com with SMTP id 9Kx12a;
    Thu, 16 Oct 2026 09:15:00 +0530
From: "Dr. Rajesh Sharma (Director)" <exec.director.office2026@gmail.com>
To: <accounts.payable@enterprise.com>
Subject: QUICK ASSISTANCE: Urgent Wire Transfer & Gift Cards
Date: Thu, 16 Oct 2026 09:14:10 +0530

Hi Accounts Team,

I am currently tied up in an urgent high-level board meeting with university trustees and cannot take phone calls right now. 

I need you to process an immediate wire transfer for an overdue consulting invoice of $4,850. In addition, please purchase 5 Apple Store gift cards ($100 denomination each) promptly for keynote speakers. 

Do not discuss this on open channels. Reply directly to this email with the confirmation codes as soon as possible.

Best regards,
Dr. Rajesh Sharma
Executive Director & Chancellor Office
""",

    "3. Medium Risk: IT Helpdesk Password Expiry with Shortener Link": """From: "IT Support Helpdesk" <support@enterprise-portal.top>
To: <all-staff@university.edu>
Subject: Action Required: Mandatory Network Password Expiration Notice
Date: Wed, 15 Oct 2026 18:30:00 +0530

Attention Staff and Faculty,

Your institutional email credentials are scheduled to expire in 48 hours. In accordance with university cybersecurity policy, all users must renew their network password prior to the deadline.

Failure to re-authenticate will prevent access to university email, LMS portals, and VPN networks.

Renew your network credentials here:
http://bit.ly/urgent-verify-2026

IT Help Desk & Systems Administration
""",

    "4. Low Risk: Safe Hackathon Project Sync & Sprint Schedule": """Received: from mail.manipal.edu ([142.250.190.46])
    by mx.google.com with ESMTPS id abc123xyz;
    Fri, 17 Oct 2026 11:00:00 +0530
From: "Priya Nair" <priya.nair@manipal.edu>
To: <team-hypnexis@manipal.edu>
Subject: SIH 2026: Team Sprint Sync and Architecture Review
Date: Fri, 17 Oct 2026 10:58:30 +0530

Hi Team Hypnexis,

Great work on finalizing the presentation slides for problem statement SIH26106! 

Our architecture sync is scheduled for today at 3:30 PM via Microsoft Teams. We will review:
1. Streamlit frontend layout and interactive threat metrics
2. TF-IDF classifier integration and feature weights
3. Hop-by-hop IP geolocation mapping and forensic disclosures

Please review the repository updates beforehand. See you all this afternoon!

Warm regards,
Priya Nair
Team Lead - Hypnexis '26
Manipal University Jaipur
"""
}
