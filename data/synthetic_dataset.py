"""
Curated synthetic dataset for training the email threat text classifier.
Includes diverse phishing lures (credentials, payments, scareware, spoofing)
and diverse benign workplace / personal emails.
"""

TRAINING_DATA = [
    # --- PHISHING EXAMPLES (Label: 1) ---
    {
        "text": "URGENT: Your PayPal account has been temporarily restricted due to unauthorized login activity. Click here to verify your identity and update payment information within 24 hours to prevent permanent account suspension: http://paypal-update-center.net/login",
        "label": 1
    },
    {
        "text": "Microsoft 365 Security Alert: Your password will expire today. To retain access to your mailbox and cloud files, please confirm your credentials immediately at http://microsoft-365-verify.top/auth. Failure to do so will result in email termination.",
        "label": 1
    },
    {
        "text": "ATTENTION: Unpaid invoice #98234 is past due. We have initiated legal action and penalty fees. Please review the attached banking details and send wire transfer immediately to avoid court summons.",
        "label": 1
    },
    {
        "text": "Apple Support Notice: Someone attempted to access your Apple ID from an unknown device in Moscow, Russia. If this was not you, verify your passcode and credit card details right away at http://login-apple-security.com",
        "label": 1
    },
    {
        "text": "Dear Employee, Our Human Resources and Payroll department is updating direct deposit accounts. Submit your banking account number, routing code, and SSN via this urgent link: http://bit.ly/urgent-verify-2026",
        "label": 1
    },
    {
        "text": "Final warning: Your mailbox storage quota has exceeded 99%. Incoming messages are being blocked. Re-activate your email storage immediately by verifying your password here: http://account-verification-support.online",
        "label": 1
    },
    {
        "text": "Internal Revenue Service (IRS): You have an unclaimed tax refund of $1,420.50 waiting for disbursement. Claim your refund instantly by providing your debit card CVV and banking PIN: http://secure-banking-alert.xyz/tax",
        "label": 1
    },
    {
        "text": "Urgent request from CEO: I am currently in an executive meeting and cannot take calls. I need you to purchase 5 Apple gift cards ($100 each) right away for a client presentation. Email the codes to me ASAP.",
        "label": 1
    },
    {
        "text": "DHL Express: Your package delivery has been put on hold due to incorrect address information and an unpaid customs fee of $2.50. Confirm your shipment details now: http://dhl-express-tracking-package.click",
        "label": 1
    },
    {
        "text": "Metamask Security Alert: Urgent validation required for your Ethereum wallet seed phrase. Unverified accounts will be permanently frozen under network compliance rules. Confirm recovery phrase at http://185.193.125.10/wallet",
        "label": 1
    },
    {
        "text": "Wells Fargo Alert: Suspicious debit card transaction of $850.00 detected at Target. If you did not authorize this, click here immediately to lock your card and verify account numbers: http://secure-banking-alert.xyz/wellsfargo",
        "label": 1
    },
    {
        "text": "Netflix Membership Suspended: We were unable to process your monthly subscription billing. Update your credit card credentials within 12 hours to continue streaming without interruption.",
        "label": 1
    },
    {
        "text": "IT Helpdesk: Mandatory security upgrade in progress. All staff members must re-authenticate their domain credentials at the internal portal link below. Non-compliant accounts will be disabled tonight.",
        "label": 1
    },
    {
        "text": "You won the international lottery sweepstakes! An amount of 2,500,000 USD has been approved for transfer. Send your passport copy, home address, and initial processing fee via Western Union.",
        "label": 1
    },

    # --- LEGITIMATE EXAMPLES (Label: 0) ---
    {
        "text": "Hi Team, attached is the revised agenda for tomorrow's engineering sprint planning meeting at 10:00 AM. Please review the backlog items beforehand and add any discussion topics to the shared document.",
        "label": 0
    },
    {
        "text": "Good afternoon, thank you for your order #40921. Your package has shipped via FedEx and is scheduled for delivery on Thursday. You can track your shipment through your official account dashboard.",
        "label": 0
    },
    {
        "text": "Hi Alex, please find the quarterly financial performance summary attached for review. Let me know if you have any questions before the board meeting next Tuesday afternoon.",
        "label": 0
    },
    {
        "text": "Reminder: The annual company picnic will take place this Saturday at Central Park from 12:00 PM to 4:00 PM. Family and friends are welcome. Please RSVP by Wednesday so we can finalize catering numbers.",
        "label": 0
    },
    {
        "text": "GitHub notification: Pull request #145 'Refactor authentication middleware' has been approved by senior reviewers and merged into the main development branch.",
        "label": 0
    },
    {
        "text": "Hi everyone, a quick heads-up that scheduled IT maintenance on our staging database cluster will occur this Friday between 11:00 PM and 1:00 AM UTC. Production services will remain completely unaffected.",
        "label": 0
    },
    {
        "text": "Welcome to the Python Software Foundation newsletter! In this monthly issue, we highlight the latest release features in Python 3.14, community grants, and upcoming PyCon conference schedules.",
        "label": 0
    },
    {
        "text": "Hi Sarah, can you please review the updated slide deck for the client presentation? I added the case study metrics and adjusted the design formatting as requested during our sync call.",
        "label": 0
    },
    {
        "text": "Receipt for your recent purchase at City Bookstore. Total: $24.50 paid via Apple Pay. Thank you for shopping with us! View your itemized receipt in your digital library.",
        "label": 0
    },
    {
        "text": "Good morning team, the open enrollment window for healthcare benefits will begin on November 1st. HR will host two informational Q&A sessions next week to answer questions regarding plan options.",
        "label": 0
    },
    {
        "text": "Hi John, thanks for reaching out. I would be happy to connect for a coffee chat regarding mentorship in cybersecurity next week. Let me know what time slots work best for your schedule.",
        "label": 0
    },
    {
        "text": "Your flight reservation with Delta Airlines is confirmed. Confirmation code: KF82NM. Flight 148 departs JFK at 8:30 AM. Online check-in opens 24 hours prior to departure.",
        "label": 0
    },
    {
        "text": "Weekly project recap: The mobile application beta testing reached 500 active users with zero critical crash reports. Kudos to the quality assurance team for exceptional test coverage.",
        "label": 0
    },
    {
        "text": "Hi David, I have updated the documentation wiki with instructions on setting up local environment variables for the new microservices architecture. Let me know if any steps need clarification.",
        "label": 0
    }
]
