import re
import email
from email import policy
from email.parser import Parser
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional

URL_REGEX = re.compile(
    r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:\'\".,<>?«»“”‘’]))'
)

IP_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

PRIVATE_IP_PREFIXES = (
    '10.',
    '127.',
    '192.168.',
    '169.254.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
    '0.', '224.', '240.'
)

def is_public_ip(ip: str) -> bool:
    if not ip:
        return False
    return not any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)

def extract_urls(text: str) -> List[str]:
    """Extract unique URLs from text or HTML."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    urls = []
    for match in matches:
        raw_url = match[0]
        if not raw_url.startswith(('http://', 'https://')):
            raw_url = 'http://' + raw_url
        if raw_url not in urls:
            urls.append(raw_url)
    return urls

def parse_email_content(raw_text: str) -> Dict[str, Any]:
    """
    Parses pasted email input.
    Can handle full RFC822 formatted message (with headers) or raw plain text.
    """
    raw_text = raw_text.strip()
    result: Dict[str, Any] = {
        "headers": {},
        "sender_name": "",
        "sender_email": "",
        "sender_domain": "",
        "reply_to": "",
        "reply_to_domain": "",
        "subject": "",
        "date": "",
        "received_hops": [],
        "origin_ip": None,
        "body": "",
        "urls": [],
        "has_headers": False
    }

    # Attempt parsing with standard email library
    parsed_msg = Parser(policy=policy.default).parsestr(raw_text)

    # Check if standard headers exist
    from_header = parsed_msg.get('From', '')
    subject_header = parsed_msg.get('Subject', '')
    received_headers = parsed_msg.get_all('Received', [])

    if from_header or subject_header or received_headers:
        result["has_headers"] = True
        result["subject"] = str(subject_header) or "(No Subject)"
        result["date"] = str(parsed_msg.get('Date', ''))
        
        # From header parsing
        from_str = str(from_header)
        email_match = re.search(r'<([^>]+)>', from_str)
        if email_match:
            result["sender_email"] = email_match.group(1).strip()
            name_part = from_str.replace(f"<{result['sender_email']}>", "").strip(' "\'')
            result["sender_name"] = name_part
        else:
            simple_email = re.search(r'[\w\.-]+@[\w\.-]+', from_str)
            if simple_email:
                result["sender_email"] = simple_email.group(0).strip()
            result["sender_name"] = from_str.replace(result["sender_email"], "").strip(' "\'')

        if result["sender_email"] and "@" in result["sender_email"]:
            result["sender_domain"] = result["sender_email"].split("@")[-1].lower()

        # Reply-To parsing
        reply_to = str(parsed_msg.get('Reply-To', ''))
        result["reply_to"] = reply_to
        if "@" in reply_to:
            match = re.search(r'[\w\.-]+@[\w\.-]+', reply_to)
            if match:
                result["reply_to_domain"] = match.group(0).split("@")[-1].lower()

        # Received headers parsing (Hop trace)
        hops = []
        for recv in received_headers:
            recv_str = str(recv)
            ips = IP_REGEX.findall(recv_str)
            public_ips = [ip for ip in ips if is_public_ip(ip)]
            hops.append({
                "raw": recv_str[:120] + "..." if len(recv_str) > 120 else recv_str,
                "all_ips": ips,
                "public_ips": public_ips
            })

        result["received_hops"] = hops

        # The origin IP (sender's first hop) is typically the last in Received chain
        origin_ip = None
        for hop in reversed(hops):
            if hop["public_ips"]:
                origin_ip = hop["public_ips"][0]
                break
        
        result["origin_ip"] = origin_ip

        # Body extraction
        body_parts = []
        if parsed_msg.is_multipart():
            for part in parsed_msg.walk():
                content_type = part.get_content_type()
                if content_type in ('text/plain', 'text/html'):
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body_parts.append(payload.decode('utf-8', errors='ignore'))
                        except Exception:
                            body_parts.append(str(payload))
        else:
            payload = parsed_msg.get_payload(decode=True)
            if payload:
                try:
                    body_parts.append(payload.decode('utf-8', errors='ignore'))
                except Exception:
                    body_parts.append(str(payload))
            else:
                body_parts.append(parsed_msg.get_payload() or "")

        full_body = "\n".join(body_parts).strip()
        # If payload was empty or raw text didn't separate neatly
        if not full_body:
            full_body = raw_text

        result["body"] = full_body
    else:
        # Fallback for plain pasted text without headers
        result["body"] = raw_text
        # Try extracting emails from first few lines if available
        first_lines = raw_text.splitlines()[:5]
        for line in first_lines:
            if re.match(r'(?i)^from:\s*', line):
                val = re.sub(r'(?i)^from:\s*', '', line).strip()
                email_match = re.search(r'[\w\.-]+@[\w\.-]+', val)
                if email_match:
                    result["sender_email"] = email_match.group(0)
                    result["sender_domain"] = result["sender_email"].split("@")[-1].lower()
                result["sender_name"] = val.replace(result["sender_email"], "").strip(' <>"\'')
            elif re.match(r'(?i)^subject:\s*', line):
                result["subject"] = re.sub(r'(?i)^subject:\s*', '', line).strip()

    # Extract URLs from body & subject
    combined_text = f"{result['subject']} {result['body']}"
    result["urls"] = extract_urls(combined_text)

    # If no origin IP yet, check for any public IP mentioned in headers or text
    if not result["origin_ip"]:
        all_ips = [ip for ip in IP_REGEX.findall(raw_text) if is_public_ip(ip)]
        if all_ips:
            result["origin_ip"] = all_ips[0]

    return result
