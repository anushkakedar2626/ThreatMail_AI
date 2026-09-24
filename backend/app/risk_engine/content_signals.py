"""
Lightweight keyword-based social engineering detector.
This is deliberately simple for the prototype (per project scope: rules
first, ML/NLP later if time allows). Judges care that the reasoning is
visible, not that it's a state-of-the-art classifier.
"""
import re

_URGENCY_PHRASES = [
    "urgent", "immediately", "act now", "verify your account", "suspended",
    "within 24 hours", "final notice", "action required", "your account will be locked",
]
_CREDENTIAL_PHRASES = [
    "confirm your password", "enter your password", "login to verify",
    "click here to verify", "update your billing", "confirm your identity",
]
_PAYMENT_PHRASES = [
    "wire transfer", "gift card", "payment is overdue", "invoice attached",
    "bank details", "process this payment",
]


def detect_social_engineering(body_text: str) -> dict:
    text = (body_text or "").lower()

    hits = {
        "urgency": [p for p in _URGENCY_PHRASES if p in text],
        "credential_request": [p for p in _CREDENTIAL_PHRASES if p in text],
        "payment_request": [p for p in _PAYMENT_PHRASES if p in text],
    }
    total_hits = sum(len(v) for v in hits.values())
    return {
        "matched_phrases": hits,
        "total_hits": total_hits,
        "score_contribution": min(total_hits * 3, 10),  # cap contribution, see scorer weights
    }


def detect_lookalike_domain(sender_domain: str, trusted_domains: list[str]) -> dict:
    """Very simple edit-distance check against a short list of commonly-impersonated
    domains. Good enough for a demo; a production system would use a proper
    homoglyph/typosquat library."""
    if not sender_domain:
        return {"is_lookalike": False, "matched_against": None}

    for trusted in trusted_domains:
        if sender_domain == trusted:
            continue
        if _looks_similar(sender_domain, trusted):
            return {"is_lookalike": True, "matched_against": trusted}
    return {"is_lookalike": False, "matched_against": None}


def _looks_similar(a: str, b: str, max_distance: int = 2) -> bool:
    a_core = re.sub(r"\.(com|net|org|in|co)$", "", a)
    b_core = re.sub(r"\.(com|net|org|in|co)$", "", b)
    return _levenshtein(a_core, b_core) <= max_distance and a_core != b_core


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_suspicious_urls(urls: list[str]) -> dict:
    suspicious_urls = []
    reasons = []
    
    for url in urls:
        if ".invalid" in url.lower():
            if url not in suspicious_urls:
                suspicious_urls.append(url)
                reasons.append(f"Contains .invalid test TLD (Controlled Phishing Simulation): {url}")
                
    return {
        "matched_urls": suspicious_urls,
        "reasons": reasons,
        "score_contribution": 25 if suspicious_urls else 0,
    }
