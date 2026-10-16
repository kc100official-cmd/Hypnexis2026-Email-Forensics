import re
from urllib.parse import urlparse
from typing import Dict, List, Any

# Trusted brands commonly impersonated in phishing attacks
WELL_KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "netflix": ["netflix.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com"],
    "bank": [], # Generic bank
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "it support": [],
    "helpdesk": [],
    "human resources": [],
    "payroll": [],
    "ceo": [],
    "director": [],
    "executive": [],
    "chancellor": [],
    "president": []
}

FREE_MAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "mail.com", "yandex.com"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".buzz",
    ".gq", ".ml", ".cf", ".ga", ".tk", ".ru", ".cn", ".stream", ".icu"
]

URGENCY_PATTERNS = [
    (r"(?i)\b(immediately|urgent|right away|promptly|asap|at once)\b", "Demands immediate compliance"),
    (r"(?i)\b(within (?:24|48|12|1|2|6) hours?|today only|limited time)\b", "Imposes artificial countdown/deadline"),
    (r"(?i)\b(suspended|deactivated|terminated|closed|restricted|blocked)\b", "Threatens account suspension or penalty"),
    (r"(?i)\b(unauthorized (?:activity|access|transaction|login)|security alert)\b", "Fabricates alarming security breach"),
    (r"(?i)\b(action required|verify your identity|confirm immediately)\b", "Directs urgent user action"),
    (r"(?i)\b(legal action|lawsuit|warrant|penalty|arrest)\b", "Uses intimidating legal threats")
]

FINANCIAL_CREDENTIAL_PATTERNS = [
    (r"(?i)\b(password|passcode|pin|credentials|login details|seed phrase)\b", "Solicits login credentials"),
    (r"(?i)\b(credit card|cvv|bank account|routing number|debit card)\b", "Requests sensitive banking or card numbers"),
    (r"(?i)\b(wire transfer|cryptocurrency|bitcoin|gift card|western union)\b", "Requests untraceable payment method"),
    (r"(?i)\b(invoice|unpaid balance|past due|overdue payment)\b", "Presents unexpected invoice pressure"),
    (r"(?i)\b(tax refund|lottery|inheritance|cash prize|bonus payment)\b", "Entices with unexpected financial windfall")
]

def analyze_sender_threats(parsed_email: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    sender_name = parsed_email.get("sender_name", "").lower()
    sender_email = parsed_email.get("sender_email", "").lower()
    sender_domain = parsed_email.get("sender_domain", "").lower()
    reply_to = parsed_email.get("reply_to", "").lower()
    reply_to_domain = parsed_email.get("reply_to_domain", "").lower()

    # Check 1: Brand Impersonation via Display Name
    for brand, legitimate_domains in WELL_KNOWN_BRANDS.items():
        if brand in sender_name:
            if legitimate_domains:
                is_legit = any(sender_domain == legit or sender_domain.endswith("." + legit) for legit in legitimate_domains)
                if not is_legit:
                    findings.append({
                        "category": "Sender Spoofing",
                        "severity": "HIGH",
                        "score": 35,
                        "description": f"Display name claims to be '{brand.title()}' but sender domain '{sender_domain}' is not an authorized official domain."
                    })
            else:
                # Corporate role impersonation (e.g. IT Support, HR) from a free email provider
                if sender_domain in FREE_MAIL_PROVIDERS:
                    findings.append({
                        "category": "Sender Spoofing",
                        "severity": "HIGH",
                        "score": 30,
                        "description": f"Display name poses as '{brand.title()}' while sending from generic public webmail ({sender_domain})."
                    })

    # Check 2: Reply-To Address Mismatch
    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        findings.append({
            "category": "Reply-To Divergence",
            "severity": "MEDIUM",
            "score": 25,
            "description": f"Replies are routed to a different domain ('{reply_to_domain}') than the apparent sender ('{sender_domain}')."
        })

    # Check 3: Suspicious TLD on sender domain
    for tld in SUSPICIOUS_TLDS:
        if sender_domain.endswith(tld):
            findings.append({
                "category": "Suspicious TLD",
                "severity": "MEDIUM",
                "score": 20,
                "description": f"Sender domain uses high-abuse top-level domain: '{tld}'."
            })
            break

    return findings

def analyze_wording_heuristics(text: str) -> List[Dict[str, Any]]:
    findings = []
    urgency_matches = []
    financial_matches = []

    for pattern, label in URGENCY_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            urgency_matches.append(f"{label} (e.g., '{matches[0]}')")

    for pattern, label in FINANCIAL_CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            financial_matches.append(f"{label} (e.g., '{matches[0]}')")

    if urgency_matches:
        severity = "HIGH" if len(urgency_matches) >= 2 else "MEDIUM"
        findings.append({
            "category": "Psychological Urgency",
            "severity": severity,
            "score": min(15 * len(urgency_matches), 35),
            "description": f"Urgency & pressure indicators detected: {', '.join(urgency_matches[:3])}."
        })

    if financial_matches:
        severity = "HIGH" if len(financial_matches) >= 2 else "MEDIUM"
        findings.append({
            "category": "Credential / Financial Solicitation",
            "severity": severity,
            "score": min(20 * len(financial_matches), 40),
            "description": f"Credential or payment traps identified: {', '.join(financial_matches[:3])}."
        })

    return findings

def evaluate_all_rules(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """Combines all heuristic checks into a comprehensive rule score & evidence list."""
    sender_findings = analyze_sender_threats(parsed_email)
    
    body_text = f"{parsed_email.get('subject', '')} {parsed_email.get('body', '')}"
    wording_findings = analyze_wording_heuristics(body_text)

    all_findings = sender_findings + wording_findings
    total_rule_score = sum(f["score"] for f in all_findings)

    return {
        "rule_score": min(total_rule_score, 100),
        "findings": all_findings,
        "urgency_detected": any(f["category"] == "Psychological Urgency" for f in all_findings),
        "spoofing_detected": any(f["category"] == "Sender Spoofing" for f in all_findings),
        "credential_harvesting": any(f["category"] == "Credential / Financial Solicitation" for f in all_findings)
    }
