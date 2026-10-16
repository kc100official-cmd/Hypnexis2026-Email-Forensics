import sys
from core.triage_engine import analyze_email_threat
from data.sample_emails import SAMPLE_EMAILS

print("="*60)
print("TESTING SIH26106 EMAIL THREAT FORENSICS ENGINE")
print("="*60)

for name, content in SAMPLE_EMAILS.items():
    print(f"\n--- Testing Scenario: {name} ---")
    result = analyze_email_threat(content)
    print(f"Priority Verdict: {result['priority']} (Score: {result['threat_score']}/100)")
    print(f"ML Probability  : {result['ml_results']['phishing_probability']}")
    print(f"Origin Relay IP : {result['parsed'].get('origin_ip')}")
    if result.get("geo_results"):
        print(f"Geo Country     : {result['geo_results'].get('country')}")
    print(f"Evidence Count  : {len(result['evidence'])}")
    for ev in result['evidence'][:2]:
        print(f"  * [{ev['source']}] {ev['detail'][:70]}...")

print("\nAll 4 test scenarios executed cleanly with zero errors!")
