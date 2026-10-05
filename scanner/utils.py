"""
CyberShield AI — Detection Utilities
=====================================
Core logic for scanning URLs, messages, and passwords.
All detection functions return a consistent dict:

    {
        'risk_score': int (0–100),
        'risk_level': 'safe' | 'suspicious' | 'dangerous',
        'verdict':    'safe' | 'suspicious' | 'dangerous',   # alias for templates
        'reasons':    [str, ...],
        'recommendations': str,
        'details':    dict,   # optional extra info
    }
"""

import re
import socket
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlparse
from datetime import datetime


# ============================================================
# 1. URL SCANNER
# ============================================================

# Common phishing/shortener patterns
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq',       # free TLDs often used in phishing
    '.xyz', '.top', '.click', '.zip',        # frequent abuse
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'shorturl.at', 'rebrand.ly', 'cutt.ly',
]

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'secure',
    'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'netflix',
    'password', 'confirm', 'suspended', 'locked', 'urgent',
    'wallet', 'crypto', 'prize', 'winner', 'gift', 'claim',
    'free', 'bonus', 'recover',
]

SUSPICIOUS_PATH_PATTERNS = [
    r'login[-_]?verify',
    r'account[-_]?update',
    r'secure[-_]?signin',
    r'confirm[-_]?identity',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',   # raw IP in URL
]


def scan_url(url: str) -> dict:
    """
    Analyze a URL for phishing / unsafe patterns.
    """
    reasons = []
    score = 0
    details = {}

    # ---- Normalize ----
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        return _result(100, 'dangerous', [f'Invalid URL: {e}'], 'Do not open this link.')

    hostname = parsed.hostname or ''
    scheme = parsed.scheme
    path = parsed.path or ''
    query = parsed.query or ''

    details['url'] = url
    details['hostname'] = hostname
    details['scheme'] = scheme

    # ---- 1. HTTPS check ----
    if scheme != 'https':
        score += 25
        reasons.append('Uses HTTP instead of HTTPS — data is not encrypted.')

    # ---- 2. IP address as host ----
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        score += 30
        reasons.append('URL uses a raw IP address instead of a domain name.')

    # ---- 3. Suspicious TLD ----
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 20
            reasons.append(f'Domain uses a high-risk TLD: {tld}')
            break

    # ---- 4. URL shortener ----
    for short in URL_SHORTENERS:
        if short in hostname:
            score += 15
            reasons.append(f'Shortened URL detected ({short}) — real destination hidden.')
            break

    # ---- 5. Many subdomains ----
    subdomain_count = hostname.count('.')
    if subdomain_count >= 4:
        score += 15
        reasons.append(f'Unusually many subdomains ({subdomain_count}).')

    # ---- 6. Phishing keywords in URL ----
    url_lower = url.lower()
    hits = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if hits:
        score += min(len(hits) * 5, 25)
        reasons.append(f'Suspicious keywords in URL: {", ".join(hits[:5])}')

    # ---- 7. Suspicious path patterns ----
    for pattern in SUSPICIOUS_PATH_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            score += 15
            reasons.append(f'Suspicious path pattern: {pattern}')
            break

    # ---- 8. "@" in URL (common trick) ----
    if '@' in url:
        score += 20
        reasons.append('URL contains "@" — real destination may be hidden after it.')

    # ---- 9. Excessive hyphens in domain ----
    if hostname.count('-') >= 3:
        score += 10
        reasons.append('Domain name has many hyphens — often seen in phishing.')

    # ---- 10. Very long URL ----
    if len(url) > 120:
        score += 10
        reasons.append(f'URL is unusually long ({len(url)} characters).')

    # ---- 11. Punycode (homograph attack) ----
    if 'xn--' in hostname:
        score += 25
        reasons.append('Punycode in domain — may imitate a trusted brand.')

    # ---- 12. SSL certificate check ----
    if scheme == 'https':
        ssl_ok, ssl_msg = check_ssl(hostname)
        details['ssl'] = ssl_msg
        if not ssl_ok:
            score += 20
            reasons.append(f'SSL issue: {ssl_msg}')

    # ---- Cap ----
    score = min(score, 100)
    level = _score_to_level(score)

    recommendation = _url_recommendation(level)

    return _result(score, level, reasons, recommendation, details)


def check_ssl(hostname: str):
    """Verify the SSL certificate of a host. Returns (ok: bool, message: str)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return True, f'Valid SSL, expires {cert.get("notAfter", "unknown")}'
    except ssl.SSLCertVerificationError as e:
        return False, f'Certificate verification failed: {e}'
    except socket.timeout:
        return False, 'Connection timed out'
    except Exception as e:
        return False, f'Could not verify: {e}'


# ============================================================
# 2. MESSAGE SCANNER
# ============================================================

URGENCY_PHRASES = [
    'act now', 'urgent', 'immediately', 'expires', 'last chance',
    'within 24 hours', 'verify now', 'limited time', 'final warning',
    'account suspended', 'unusual activity', 'click here', 'act fast',
]

FRAUD_PHRASES = [
    'you have won', 'you won', 'congratulations', 'claim your prize',
    'free gift', 'lottery', 'inheritance', 'wire transfer', 'bitcoin',
    'crypto', 'investment opportunity', 'double your money',
    'send money', 'western union', 'money gram', 'gift card',
    'social security', 'ssn', 'tax refund', 'irs', 'refund',
]

SENSITIVE_REQUESTS = [
    'password', 'otp', 'pin', 'cvv', 'credit card', 'debit card',
    'bank account', 'social security', 'ssn', 'aadhaar', 'pan',
    'verification code', 'one-time password', 'one time password',
]


def scan_message(message: str) -> dict:
    """
    Analyze an SMS / email / WhatsApp message for phishing and fraud.
    """
    reasons = []
    score = 0
    details = {}

    if not message or not message.strip():
        return _result(0, 'safe', [], 'No message provided.', details)

    text = message.strip()
    text_lower = text.lower()

    details['length'] = len(text)

    # ---- 1. Urgency language ----
    urgency_hits = [p for p in URGENCY_PHRASES if p in text_lower]
    if urgency_hits:
        score += min(len(urgency_hits) * 8, 25)
        reasons.append(f'Urgency language detected: {", ".join(urgency_hits[:3])}')

    # ---- 2. Fraud / prize language ----
    fraud_hits = [p for p in FRAUD_PHRASES if p in text_lower]
    if fraud_hits:
        score += min(len(fraud_hits) * 12, 35)
        reasons.append(f'Common fraud phrases: {", ".join(fraud_hits[:3])}')

    # ---- 3. Requests for sensitive information ----
    sensitive_hits = [p for p in SENSITIVE_REQUESTS if p in text_lower]
    if sensitive_hits:
        score += min(len(sensitive_hits) * 15, 40)
        reasons.append(f'Asks for sensitive info: {", ".join(sensitive_hits[:3])}')

    # ---- 4. Embedded links ----
    links = re.findall(r'https?://\S+', text)
    if links:
        score += 15
        reasons.append(f'Contains {len(links)} link(s) — do not click without verifying.')
        # Sub-scan the first link
        first_link_result = scan_url(links[0])
        if first_link_result['risk_score'] >= 50:
            score += 20
            reasons.append(f'The link inside the message looks unsafe (score {first_link_result["risk_score"]}).')
        details['first_link'] = links[0]

    # ---- 5. ALL CAPS shouting ----
    if len(text) > 20:
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
        if caps_ratio > 0.4:
            score += 10
            reasons.append('Excessive capitalization — often used to create panic.')

    # ---- 6. Money amounts ----
    if re.search(r'(\$|₹|€|£)\s?\d+', text) or re.search(r'\b\d+\s?(usd|inr|eur|gbp)\b', text_lower):
        score += 15
        reasons.append('Mentions a specific amount of money.')

    # ---- 7. Grammar / typo hints ----
    typo_hints = ['kindly', 'revert back', 'do the needful', 'dear customer', 'dear user']
    typo_hits = [t for t in typo_hints if t in text_lower]
    if typo_hits:
        score += 10
        reasons.append(f'Formal/bot-like phrasing: {", ".join(typo_hits)}')

    # ---- 8. Impersonation of known brands ----
    brands = ['paypal', 'amazon', 'apple', 'microsoft', 'netflix', 'google',
              'facebook', 'instagram', 'whatsapp', 'bank', 'sbi', 'hdfc', 'icici']
    brand_hits = [b for b in brands if b in text_lower]
    if brand_hits:
        score += 10
        reasons.append(f'Mentions a well-known brand: {", ".join(brand_hits)}')

    # ---- 9. Phone numbers ----
    if re.search(r'\+?\d[\d\s\-]{8,}\d', text):
        score += 10
        reasons.append('Contains a phone number — verify the sender before calling.')

    # ---- Cap ----
    score = min(score, 100)
    level = _score_to_level(score)

    details['message_preview'] = text[:200]

    recommendation = (
        'Do NOT click links, call numbers, or share any personal information. '
        'Report this message to your email/SMS provider and delete it.'
        if level == 'dangerous' else
        'Be cautious. Verify the sender through an official channel before acting.'
        if level == 'suspicious' else
        'This message looks safe based on our checks — but always stay alert.'
    )

    return _result(score, level, reasons, recommendation, details)


# ============================================================
# 3. PASSWORD STRENGTH CHECKER
# ============================================================

COMMON_PASSWORDS = {
    '123456', 'password', '12345678', 'qwerty', '123456789', '12345',
    '1234', '111111', '1234567', 'dragon', '123123', 'baseball',
    'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master',
    '666666', 'qwertyuiop', '123321', 'mustang', '1234567890',
    'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212',
    '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan',
    'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer',
    'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou',
    '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger',
    'daniel', 'starwars', 'klaster', '112233', 'george', 'asshole',
    'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn',
    '555555', '11111111', '131313', 'freedom', '777777', 'pass',
    'fuckyou', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess',
    'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley',
}


def check_password_strength(password: str) -> dict:
    """
    Evaluate password strength and give actionable suggestions.
    Never logs, stores, or transmits the password.
    """
    reasons = []
    suggestions = []
    score = 0
    details = {}

    if not password:
        return _result(0, 'safe', [], 'Enter a password to check.', details)

    length = len(password)
    details['length'] = length

    # ---- 1. Length ----
    if length < 6:
        reasons.append('Too short (under 6 characters).')
    elif length < 8:
        score += 5
        suggestions.append('Increase length to at least 8 characters.')
    elif length < 12:
        score += 15
        suggestions.append('Aim for 12+ characters for stronger security.')
    elif length < 16:
        score += 25
    else:
        score += 30
        suggestions.append('Great length!')

    # ---- 2. Character variety ----
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 8

    if not has_upper:
        suggestions.append('Add uppercase letters (A–Z).')
    if not has_lower:
        suggestions.append('Add lowercase letters (a–z).')
    if not has_digit:
        suggestions.append('Add numbers (0–9).')
    if not has_symbol:
        suggestions.append('Add symbols (!@#$%^&*).')

    # ---- 3. Common password ----
    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 40)
        reasons.append('This password appears in the top-100 most common list.')

    # ---- 4. Repeated characters ----
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        reasons.append('Contains repeated characters (e.g., "aaa", "111").')

    # ---- 5. Sequential characters ----
    sequences = ['abc', 'bcd', '123', '234', '345', '456', '567',
                 '678', '789', 'qwerty', 'asdf', 'zxcv']
    for seq in sequences:
        if seq in password.lower():
            score -= 10
            reasons.append(f'Contains a common sequence ("{seq}").')
            break

    # ---- 6. Only digits or only letters ----
    if password.isdigit():
        score -= 20
        reasons.append('Numbers only — very easy to crack.')
    elif password.isalpha():
        score -= 10
        reasons.append('Letters only — add numbers and symbols.')

    # ---- 7. Keyboard patterns ----
    keyboard_patterns = ['qwerty', 'asdf', 'zxcv', 'qaz', 'wsx', 'edc']
    for kp in keyboard_patterns:
        if kp in password.lower():
            score -= 10
            reasons.append('Contains a keyboard pattern.')
            break

    # ---- 8. Contains "password" or user hints ----
    if 'password' in password.lower() or 'admin' in password.lower():
        score -= 20
        reasons.append('Contains the word "password" or "admin".')

    # ---- Cap & floor ----
    score = max(0, min(score, 100))
    level = _score_to_level(score)

    if not suggestions:
        suggestions.append('Excellent! Keep using a unique password for every account.')

    recommendation = ' '.join(suggestions)
    details['suggestions'] = suggestions

    return _result(score, level, reasons, recommendation, details)


# ============================================================
# 4. HELPERS
# ============================================================

def _score_to_level(score: int) -> str:
    """Convert numeric score to a verdict string."""
    if score >= 70:
        return 'dangerous'
    if score >= 35:
        return 'suspicious'
    return 'safe'


def _url_recommendation(level: str) -> str:
    if level == 'dangerous':
        return ('Do NOT open this URL. It shows strong signs of phishing or malware. '
                'If you already opened it, disconnect from the internet and run a malware scan.')
    if level == 'suspicious':
        return ('Be cautious. Verify the site through official channels before entering any information. '
                'Check the domain spelling carefully.')
    return 'This URL appears safe based on our checks — but always stay alert.'


def _result(score: int, level: str, reasons: list, recommendation: str, details: dict = None) -> dict:
    """Standardize the return shape across all scanners."""
    return {
        'risk_score': int(score),
        'risk_level': level,
        'verdict': level,             # alias used by templates
        'reasons': reasons,
        'recommendations': recommendation,
        'details': details or {},
        'scanned_at': datetime.now().isoformat(),
    }