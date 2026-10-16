from typing import Dict, Any, List
from core.email_parser import parse_email_content
from core.threat_rules import evaluate_all_rules
from core.ml_classifier import get_classifier
from core.url_reputation import analyze_all_urls
from core.geolocation import lookup_ip_geolocation

def analyze_email_threat(raw_text: str) -> Dict[str, Any]:
    """
    Orchestrates end-to-end email threat analysis:
    Parses -> Applies Heuristics -> ML Classification -> URL Reputation -> IP Geo -> Aggregated Triage.
    """
    # 1. Parse Email Content
    parsed = parse_email_content(raw_text)

    # 2. Evaluate Rule-based Heuristics
    rule_results = evaluate_all_rules(parsed)

    # 3. Machine Learning Classification
    text_to_classify = f"{parsed.get('subject', '')} {parsed.get('body', '')}"
    ml_results = get_classifier().predict(text_to_classify)

    # 4. URL Threat Intelligence
    url_results = analyze_all_urls(parsed.get("urls", []))

    # 5. Geolocation & Forensic Header Relay
    geo_results = None
    if parsed.get("origin_ip"):
        geo_results = lookup_ip_geolocation(parsed["origin_ip"])

    # 6. Composite Threat Score Calculation (0 - 100)
    rule_weight = 0.35
    ml_weight = 0.35
    url_weight = 0.30

    rule_score = rule_results["rule_score"]
    ml_score = ml_results["ml_score"]
    url_score = url_results["max_risk_score"]

    composite_score = int(round(
        (rule_score * rule_weight) +
        (ml_score * ml_weight) +
        (url_score * url_weight)
    ))

    # Safety overrides for explicit malicious signatures
    if url_results["has_malicious"]:
        composite_score = max(composite_score, 80)
    if rule_results["spoofing_detected"] and (rule_results["urgency_detected"] or rule_results["credential_harvesting"]):
        composite_score = max(composite_score, 75)

    final_score = min(max(composite_score, 0), 100)

    # Determine Review Priority
    if final_score >= 60:
        priority = "HIGH"
        priority_label = "HIGH REVIEW PRIORITY — Suspicious / Potentially Malicious"
        priority_color = "#E53E3E" # Red
    elif final_score >= 30:
        priority = "MEDIUM"
        priority_label = "MEDIUM REVIEW PRIORITY — Caution / Needs Human Inspection"
        priority_color = "#DD6B20" # Orange
    else:
        priority = "LOW"
        priority_label = "LOW REVIEW PRIORITY — Appears Normal / Low Threat Risk"
        priority_color = "#38A169" # Green

    # Compile Plain-Language Evidence Behind The Assessment
    evidence = []

    # Sender clues
    if rule_results["findings"]:
        for finding in rule_results["findings"]:
            evidence.append({
                "source": finding["category"],
                "severity": finding["severity"],
                "detail": finding["description"]
            })

    # ML linguistic clues
    if ml_results["phishing_probability"] >= 0.50:
        keywords = [kw[0] for kw in ml_results["top_keywords"][:4]]
        kw_str = f" (Influential keywords: {', '.join(keywords)})" if keywords else ""
        evidence.append({
            "source": "AI Text Classifier",
            "severity": "HIGH" if ml_results["phishing_probability"] >= 0.75 else "MEDIUM",
            "detail": f"Model identified characteristic phishing vocabulary patterns with {int(ml_results['phishing_probability']*100)}% confidence.{kw_str}"
        })
    elif ml_results["ml_score"] <= 20:
        evidence.append({
            "source": "AI Text Classifier",
            "severity": "LOW",
            "detail": "Linguistic structure aligns with standard benign communication patterns."
        })

    # URL clues
    if url_results["total_urls"] > 0:
        for u in url_results["url_details"]:
            if u["flags"]:
                evidence.append({
                    "source": "URL Intelligence",
                    "severity": u["status"],
                    "detail": f"Target link '{u['url'][:55]}...': {'; '.join(u['flags'])}"
                })
    else:
        evidence.append({
            "source": "URL Inspection",
            "severity": "INFO",
            "detail": "No external hyperlinks detected in message text."
        })

    # IP Geolocation observation
    if geo_results and geo_results.get("status") in ("success", "approximate"):
        country = geo_results.get("country", "Unknown")
        isp = geo_results.get("isp", "Unknown")
        evidence.append({
            "source": "Header Relay Forensics",
            "severity": "INFO",
            "detail": f"Originating relay IP {geo_results.get('ip')} geolocates to {country} (ISP: {isp}). Note: Geolocation represents relay infrastructure, not proof of sender identity."
        })

    # Recommended Safe Next Steps
    safe_steps = []
    if priority == "HIGH":
        safe_steps = [
            "DO NOT click any embedded links or download attachments.",
            "DO NOT reply with passwords, bank info, or verification codes.",
            "Verify the request through an established alternate communication channel (phone call, official portal).",
            "Quarantine this message and notify your organization's IT / SOC security team."
        ]
    elif priority == "MEDIUM":
        safe_steps = [
            "Inspect the sender's full email address and domain name carefully for subtle typosquatting.",
            "Hover over links to verify destination URLs match known official corporate domains.",
            "Do not provide credentials or financial authorizations without second-person confirmation.",
            "Flag for internal security review if origin remains ambiguous."
        ]
    else:
        safe_steps = [
            "Standard security hygiene applies.",
            "Ensure sender address corresponds to regular business contacts.",
            "Report immediately if unexpected financial requests or attachments arise later."
        ]

    return {
        "priority": priority,
        "priority_label": priority_label,
        "priority_color": priority_color,
        "threat_score": final_score,
        "score_breakdown": {
            "ml_score": ml_score,
            "rule_score": rule_score,
            "url_score": url_score
        },
        "parsed": parsed,
        "ml_results": ml_results,
        "rule_results": rule_results,
        "url_results": url_results,
        "geo_results": geo_results,
        "evidence": evidence,
        "safe_steps": safe_steps
    }
