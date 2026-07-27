"""
analyzer.py

Core phishing-detection engine for PhishGuard - v2, context-aware scoring.

The v1 engine scored ANY message containing words like "verify", "otp",
"limited time", or "click here" as suspicious - which meant ordinary
marketing emails and ordinary one-time-password / verification emails got
flagged right alongside real phishing. This version separates two
questions that were previously conflated into one keyword count:

  1. What KIND of message is this - Marketing, a Security/Verification
     notice, a Transactional receipt, a Newsletter, or personal
     correspondence?  (see classify_category)

  2. Given that kind of message, does the actual EVIDENCE - the sender
     domain, the links, and how it asks for sensitive information - look
     like an attack impersonating that kind of message?  (see
     analyze_email)

Marketing language ("limited time", "30% off") and routine security
language ("your OTP is 482913", "this code expires in 10 minutes") are
now treated as normal content that only counts as risk when it is paired
with hard evidence: a spoofed sender, a lookalike/insecure link, or an
explicit request to send credentials back over email. Everything still
runs locally on the pasted text - no external services are called.
"""

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Reference data - brands, providers, domains
# ---------------------------------------------------------------------------

TRUSTED_BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com", "icloud.com"],
    "facebook": ["facebook.com", "meta.com"],
    "github": ["github.com"],
    "netflix": ["netflix.com"],
    "bankofamerica": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "linkedin": ["linkedin.com"],
    "instagram": ["instagram.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
}

# Providers not owned by any brand above - a brand name in the LOCAL part
# of an address at one of these is a classic impersonation pattern
# (e.g. "amazon-support@hotmail.com").
FREE_EMAIL_PROVIDERS = [
    "hotmail.com", "yahoo.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "zoho.com",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".ru", ".info", ".top", ".click", ".gq", ".tk",
    ".cf", ".ml", ".work", ".loan", ".men", ".support",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
]

# Common character-substitution tricks, e.g. "paypa1" -> "paypal",
# "micr0soft" -> "microsoft". No duplicate keys - each digit maps one way.
LOOKALIKE_SUBSTITUTIONS = {
    "0": "o", "1": "l", "5": "s", "3": "e", "4": "a", "7": "t", "@": "a", "$": "s",
}

# ---------------------------------------------------------------------------
# Reference data - content patterns, split by what they actually prove
# ---------------------------------------------------------------------------

# Tier A: phrases that are near-unambiguous account-attack language and
# rarely appear in routine legitimate mail. Counted unconditionally.
PHISHING_PHRASES = [
    "account suspended", "account will be suspended", "temporarily suspended",
    "permanent suspension", "unauthorized access", "suspicious activity",
    "suspicious login activity", "unusual login activity", "unusual activity",
    "security alert", "final notice", "account has been locked",
    "failure to verify", "failure to login", "will be permanently deleted",
    "will be permanently disabled", "reactivate your account",
    "unlock your account now",
]

# Tier B: promotional / generic pressure language. Extremely common in
# ordinary marketing email. Only counted as RISK when hard evidence (a bad
# sender or a bad link) already exists elsewhere - otherwise it is simply
# used to help identify the message as Marketing, nothing more.
MARKETING_PHRASES = [
    "limited time", "act now", "act immediately", "don't miss out",
    "today only", "hours left", "sale ends", "exclusive offer",
    "special offer", "% off", "free shipping", "claim now", "winner",
    "congratulations", "prize", "lottery",
]

SECURITY_NOTICE_PHRASES = [
    "otp", "one-time password", "one time password", "verification code",
    "security code", "verify your email", "confirm your email",
    "two-factor", "2fa", "sign-in code", "login code", "confirm your account",
    "new login", "new sign-in", "signed in from", "new device",
    "login attempt", "security notice", "reset your password",
    "password reset",
]

TRANSACTIONAL_PHRASES = [
    "order confirmation", "order number", "tracking number", "has shipped",
    "your order", "invoice", "receipt", "payment received",
    "booking confirmed", "reservation confirmed", "estimated delivery",
    "delivery scheduled",
]

NEWSLETTER_PHRASES = [
    "unsubscribe", "newsletter", "you are receiving this email because",
    "manage your email preferences", "view this email in your browser",
]

# Explicit requests to send/enter sensitive data back via the email itself -
# the strongest content-only phishing signal, regardless of category.
# Note the gap allows newlines (bulleted "Please provide: / - Password"
# lists are a very common real-world phishing layout).
SOLICITATION_PATTERNS = [
    re.compile(
        r'\b(?:please\s+)?(?:provide|send|reply\s+with|enter|re-?enter|type|share|confirm)\b'
        r'[^.]{0,100}\b(?:your\s+)?(?:username\s+and\s+)?(?:password|otp|pin|cvv|ssn|'
        r'social security|account number|card number)\b',
        re.IGNORECASE,
    ),
    re.compile(r'^\s*(?:username|password|pin|otp|card number)\s*:\s*$', re.IGNORECASE | re.MULTILINE),
]

# A code being DELIVERED to the reader, not solicited FROM them - a
# routine, legitimate pattern. Never treated as risk; informational only.
DELIVERY_PATTERNS = [
    re.compile(r'\byour\s+(?:otp|one-time password|verification code|security code|'
               r'login code|pin)\s+is[:\s]', re.IGNORECASE),
    re.compile(r'\b(?:otp|code|pin)\s*(?:is)?\s*:\s*\d{4,8}\b', re.IGNORECASE),
]

# Reassurance / good-hygiene language legitimate senders use, and that
# attackers rarely bother including. Each reduces the score a little.
POSITIVE_SIGNAL_PATTERNS = [
    (re.compile(r"if you did(?:n't| not) (?:request|make|initiate|attempt)\b", re.IGNORECASE),
     "Explains what to do if you didn't request this"),
    (re.compile(r"you can (?:safely )?ignore this (?:email|message)", re.IGNORECASE),
     "Tells you it's safe to ignore if unexpected"),
    (re.compile(r"never share (?:this|your) (?:otp|pin|password|code|cvv)", re.IGNORECASE),
     "Reminds you never to share this code or password"),
    (re.compile(r"do not share this (?:code|otp|pin)", re.IGNORECASE),
     "Reminds you not to share this code"),
    (re.compile(r"\bunsubscribe\b", re.IGNORECASE),
     "Includes an unsubscribe link, typical of legitimate bulk mail"),
]

# Threats specifically tied to the ACCOUNT itself - the real manipulation
# tactic - as opposed to a routine "this code expires in 10 minutes"
# notice, which is normal and is deliberately NOT matched here.
ACCOUNT_THREAT_PATTERN = re.compile(
    r'\b(?:account|access)\b.{0,35}\b(?:suspen\w*|delet\w*|disabl\w*|lock\w*|terminat\w*|clos\w*|restrict\w*)\b'
    r'|\b(?:suspen\w*|delet\w*|disabl\w*|lock\w*|terminat\w*|clos\w*|restrict\w*)\w*\b.{0,35}\b(?:account|access)\b'
    r'|\bpermanent(?:ly)?\b.{0,25}\b(?:suspen\w*|delet\w*|disabl\w*|lock\w*|clos\w*)\b',
    re.IGNORECASE,
)

GENERIC_GREETING_REGEX = re.compile(
    r'\bdear\s+(?:customer|user|valued\s+customer|account\s+holder|member)\b',
    re.IGNORECASE,
)

URL_REGEX = re.compile(r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+)', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'[\w.+-]+@[\w-]+\.[a-zA-Z.]{2,}')
FROM_LINE_REGEX = re.compile(r'from\s*:?\s*([\w.+-]+@[\w-]+\.[a-zA-Z.]{2,})', re.IGNORECASE)
IP_HOST_REGEX = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _char_substitution_lookalike(domain: str, brand: str) -> bool:
    """Detect look-alike tricks such as 'paypa1' for 'paypal' or 'micr0soft' for 'microsoft'."""
    normalized = domain.lower()
    for digit, letter in LOOKALIKE_SUBSTITUTIONS.items():
        normalized = normalized.replace(digit, letter)
    return brand in normalized and brand not in domain.lower()


def _registrable_matches_brand(netloc: str, real_domains) -> bool:
    return any(netloc == d or netloc.endswith("." + d) for d in real_domains)


def extract_urls(text: str) -> list:
    """Extract and de-duplicate URLs from raw text, trimming trailing punctuation."""
    seen = set()
    cleaned = []
    for match in URL_REGEX.findall(text):
        trimmed = match.rstrip('.,;:!?)\'"')
        if trimmed and trimmed not in seen:
            seen.add(trimmed)
            cleaned.append(trimmed)
    return cleaned


def extract_sender(text: str):
    """Best-effort extraction of a sender address from raw pasted email text."""
    match = FROM_LINE_REGEX.search(text)
    if match:
        return match.group(1)
    generic = EMAIL_REGEX.search(text)
    return generic.group(0) if generic else None


# ---------------------------------------------------------------------------
# Category classification - "what kind of message is this?"
# ---------------------------------------------------------------------------

def classify_category(lowered_text: str) -> str:
    """
    Identify what KIND of message this claims to be, independent of
    whether it turns out to be genuine. This is what lets the report say
    "this looks like a Marketing email" or "this looks like a Security /
    Account Notice" instead of only ever saying phishing / not phishing.
    A phishing email can (and often does) impersonate any of these -
    the category and the verdict are deliberately answered separately.
    """
    scores = {
        "Security / Account Notice": sum(1 for p in SECURITY_NOTICE_PHRASES if p in lowered_text),
        "Transactional / Order Update": sum(1 for p in TRANSACTIONAL_PHRASES if p in lowered_text),
        "Marketing / Promotional": sum(1 for p in MARKETING_PHRASES if p in lowered_text),
        "Newsletter": sum(1 for p in NEWSLETTER_PHRASES if p in lowered_text),
    }

    best_category = max(scores, key=scores.get)
    if scores[best_category] == 0:
        return "Personal / General Correspondence"
    return best_category


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_url(url: str):
    """Analyze a single URL. Returns (list of (flag_text, severity), matched_official_brand)."""
    flags = []
    candidate = url if "://" in url else f"http://{url}"
    parsed = urlparse(candidate)
    netloc = parsed.netloc.lower()

    if parsed.scheme == "http":
        flags.append(("Link uses insecure HTTP instead of HTTPS", "high"))

    matched_tld = next((tld for tld in SUSPICIOUS_TLDS if netloc.endswith(tld)), None)
    if matched_tld:
        flags.append((f"Link uses an untrusted top-level domain ({matched_tld})", "high"))

    if any(shortener in netloc for shortener in URL_SHORTENERS):
        flags.append(("Link uses a URL shortener that hides its real destination", "medium"))

    matched_official_brand = None
    for brand, real_domains in TRUSTED_BRAND_DOMAINS.items():
        is_official = _registrable_matches_brand(netloc, real_domains)

        if brand in netloc and not is_official:
            flags.append((f"Link domain resembles '{brand}' but is not an official {brand} domain", "high"))

        if _char_substitution_lookalike(netloc, brand):
            flags.append((f"Link domain imitates '{brand}' using look-alike characters", "high"))

        if is_official:
            matched_official_brand = brand

    if netloc.count("-") >= 2:
        flags.append(("Link domain contains multiple hyphens, a common phishing pattern", "low"))

    if IP_HOST_REGEX.search(netloc):
        flags.append(("Link uses a raw IP address instead of a domain name", "high"))

    return flags, matched_official_brand


def analyze_sender(sender):
    """Analyze the sender address. Returns (flags, positive_signals, matched_official_brand)."""
    flags = []
    positives = []
    if not sender or "@" not in sender:
        return flags, positives, None

    local_part, _, domain = sender.lower().partition("@")
    matched_official_brand = None

    for brand, real_domains in TRUSTED_BRAND_DOMAINS.items():
        is_official = _registrable_matches_brand(domain, real_domains)

        if brand in domain and not is_official:
            flags.append((f"Sender domain resembles '{brand}' but is not an official {brand} domain", "high"))

        if _char_substitution_lookalike(domain, brand):
            flags.append((f"Sender domain imitates '{brand}' using look-alike characters", "high"))

        if brand in local_part and domain in FREE_EMAIL_PROVIDERS:
            flags.append((f"Claims to be from '{brand}' but sends from a free email provider ({domain})", "high"))

        if is_official:
            matched_official_brand = brand

    if matched_official_brand:
        positives.append(f"Sender domain matches the official {matched_official_brand} domain")

    return flags, positives, matched_official_brand


def analyze_text(body: str, hard_evidence_present: bool):
    """
    Analyze body/subject text for content-based signals.

    `hard_evidence_present` indicates whether the sender or a link already
    looks bad. Marketing-style pressure language is only counted as risk
    when it is corroborating existing evidence - on its own, it's just
    marketing copy.
    """
    flags = []
    positives = []
    lowered = body.lower()

    matched_phishing_phrases = sorted({p for p in PHISHING_PHRASES if p in lowered})
    if matched_phishing_phrases:
        preview = ", ".join(matched_phishing_phrases[:4])
        flags.append((f"Contains phishing-associated phrasing: {preview}", "medium"))

    if ACCOUNT_THREAT_PATTERN.search(lowered):
        flags.append(("Threatens account suspension, deletion, or lockout", "medium"))

    if any(pattern.search(body) for pattern in SOLICITATION_PATTERNS):
        flags.append(("Directly asks you to send or enter sensitive credentials", "high"))

    if GENERIC_GREETING_REGEX.search(lowered):
        flags.append(("Uses a generic greeting instead of your name", "low"))

    if hard_evidence_present:
        matched_marketing_phrases = sorted({p for p in MARKETING_PHRASES if p in lowered})
        if matched_marketing_phrases:
            preview = ", ".join(matched_marketing_phrases[:4])
            flags.append((f"Uses promotional pressure language alongside other red flags: {preview}", "low"))

    for pattern, description in POSITIVE_SIGNAL_PATTERNS:
        if pattern.search(body):
            positives.append(description)

    category = classify_category(lowered)

    return flags, positives, category


def calculate_risk_score(all_flags, positive_count: int) -> int:
    """Convert weighted flags into a 0-100 risk score, tempered by positive signals."""
    weights = {"high": 25, "medium": 12, "low": 5}
    score = sum(weights.get(severity, 5) for _, severity in all_flags)
    score -= min(positive_count, 3) * 8  # each positive signal helps, capped so it can't launder hard evidence
    return max(0, min(100, score))


def get_verdict(score: int):
    """Map a risk score to a verdict label and a CSS-friendly class name."""
    if score >= 50:
        return "Phishing", "danger"
    if score >= 20:
        return "Suspicious", "warning"
    return "Legitimate", "success"


def get_recommendations(verdict: str, category: str) -> list:
    """Return an ordered list of recommended actions for the given verdict."""
    recommendations = [
        "Verify the sender's full email address, not just the display name.",
        "Hover over links to preview the real destination before clicking.",
        "Never share passwords or one-time passcodes over email.",
        "Enable Multi-Factor Authentication (MFA) on all important accounts.",
    ]

    if verdict == "Phishing":
        recommendations.insert(0, "Do not click any links or reply. Delete or report this message immediately.")
        recommendations.append("Report this message to your IT/security team or the impersonated organization.")
    elif verdict == "Suspicious":
        recommendations.insert(0, "Treat this message with caution and verify the sender through an official channel.")
    else:
        recommendations.insert(
            0,
            f"No major red flags found for this {category.lower()} message - "
            "still verify anything unexpected through a trusted channel.",
        )

    return recommendations


def analyze_email(raw_text: str) -> dict:
    """
    Main entry point. Takes sanitized, raw pasted email text and returns a
    structured analysis dictionary consumed by the result template.
    """
    raw_text = raw_text.strip()

    urls = extract_urls(raw_text)
    sender = extract_sender(raw_text)

    all_flags = []
    all_positives = []

    sender_flags, sender_positives, _ = analyze_sender(sender)
    all_flags.extend(sender_flags)
    all_positives.extend(sender_positives)

    url_analysis = []
    any_url_flagged = False
    for url in urls:
        url_flags, official_brand = analyze_url(url)
        all_flags.extend(url_flags)
        if url_flags:
            any_url_flagged = True
        elif official_brand:
            all_positives.append(f"Link domain matches the official {official_brand} domain")
        url_analysis.append({"url": url, "flags": [text for text, _ in url_flags]})

    hard_evidence_present = bool(sender_flags) or any_url_flagged

    text_flags, text_positives, category = analyze_text(raw_text, hard_evidence_present)
    all_flags.extend(text_flags)
    all_positives.extend(text_positives)

    score = calculate_risk_score(all_flags, len(all_positives))
    verdict, verdict_class = get_verdict(score)

    return {
        "sender": sender or "Not detected",
        "category": category,
        "urls": url_analysis,
        "url_count": len(urls),
        "flag_details": [{"text": text, "severity": severity} for text, severity in all_flags],
        "positive_signals": all_positives,
        "recommendations": get_recommendations(verdict, category),
        "score": score,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "char_count": len(raw_text),
    }
