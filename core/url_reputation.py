import re
from urllib.parse import urlparse
from typing import Dict, List, Any

# Curated list of high-risk / known-malicious simulation indicators
KNOWN_PHISHING_DOMAINS = {
    "login-apple-security.com": "Impersonates Apple ID authentication portal",
    "secure-banking-alert.xyz": "Simulated banking credential theft domain",
    "paypal-update-center.net": "Known counterfeit PayPal dispute resolution page",
    "microsoft-365-verify.top": "Fabricated Microsoft 365 credential harvester",
    "account-verification-support.online": "Generic phishing credential stealer",
    "bit.ly/urgent-verify-2026": "Obfuscated shortened phishing redirect",
    "dhl-express-tracking-package.click": "Deceptive courier invoice malware dropper"
}

SUSPICIOUS_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl", "rebrand.ly"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".buzz",
    ".gq", ".ml", ".cf", ".ga", ".tk", ".ru", ".stream", ".icu"
]

IP_HOST_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def inspect_url(url: str) -> Dict[str, Any]:
    """Examines a single URL for phishing attributes."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
    except Exception:
        hostname = ""
        path = ""

    flags = []
    risk_score = 0

    # 1. Check known malicious domains (PhishTank cache simulation)
    full_url_clean = url.rstrip('/')
    domain_match = None
    for bad_domain, reason in KNOWN_PHISHING_DOMAINS.items():
        if bad_domain in full_url_clean or bad_domain in hostname:
            domain_match = reason
            break

    if domain_match:
        flags.append(f"Flagged in PhishTank/Threat Intel database: {domain_match}")
        risk_score += 60

    # 2. Check for naked IP address as host
    if IP_HOST_REGEX.match(hostname):
        flags.append("Host is a raw numerical IP address instead of a recognized domain name")
        risk_score += 40

    # 3. Check for URL shorteners
    if hostname in SUSPICIOUS_SHORTENERS:
        flags.append(f"URL shortener '{hostname}' conceals the final target address")
        risk_score += 25

    # 4. Check for high-risk TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append(f"Host uses high-abuse top level domain '{tld}'")
            risk_score += 25
            break

    # 5. Check for deceptive brand in subdomain (e.g. paypal.com.attacker.com)
    for brand in ["paypal", "microsoft", "google", "apple", "netflix", "chase"]:
        if brand in hostname and not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
            flags.append(f"Subdomain or path mimics '{brand}' to deceive viewers")
            risk_score += 35
            break

    # 6. Deep subdomain nesting
    subdomain_parts = hostname.split('.')
    if len(subdomain_parts) > 3 and not hostname.startswith("www."):
        flags.append(f"Unusually deeply nested subdomains ({len(subdomain_parts)} parts)")
        risk_score += 15

    status = "SAFE"
    if risk_score >= 50:
        status = "MALICIOUS"
    elif risk_score >= 20:
        status = "SUSPICIOUS"

    return {
        "url": url,
        "hostname": hostname,
        "status": status,
        "risk_score": min(risk_score, 100),
        "flags": flags
    }

def analyze_all_urls(urls: List[str]) -> Dict[str, Any]:
    """Analyzes all extracted URLs and summarizes aggregate risk."""
    results = [inspect_url(u) for u in urls]
    max_score = max([r["risk_score"] for r in results], default=0)
    has_malicious = any(r["status"] == "MALICIOUS" for r in results)
    has_suspicious = any(r["status"] == "SUSPICIOUS" for r in results)

    return {
        "total_urls": len(urls),
        "url_details": results,
        "max_risk_score": max_score,
        "has_malicious": has_malicious,
        "has_suspicious": has_suspicious
    }
