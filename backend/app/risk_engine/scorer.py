"""
Weighted risk scoring engine.
Weights below mirror the project brief:
  Authentication Risk: 20 | Domain Risk: 20 | URL Risk: 25
  IP Reputation: 15 | Social Engineering: 10 | Header Anomaly: 10
These are PROTOTYPE/DEMO weights, not scientifically validated probabilities.
"""

WEIGHTS = {
    "authentication": 20,
    "domain": 20,
    "url": 25,
    "ip_reputation": 15,
    "social_engineering": 10,
    "header_anomaly": 10,
}


def score_authentication(auth_results: dict) -> tuple[int, list[str]]:
    reasons = []
    score = 0
    if auth_results["spf"] == "fail":
        score += 10
        reasons.append("SPF check failed")
    elif auth_results["spf"] == "softfail":
        score += 5
        reasons.append("SPF softfail (partial authentication failure)")
    if auth_results["dkim"] == "fail":
        score += 5
        reasons.append("DKIM signature failed")
    if auth_results["dmarc"] == "fail":
        score += 5
        reasons.append("DMARC alignment failed")
    return min(score, WEIGHTS["authentication"]), reasons


def score_domain(lookalike_result: dict, domain_reputation: dict) -> tuple[int, list[str]]:
    reasons = []
    score = 0
    if lookalike_result.get("is_lookalike"):
        score += 12
        reasons.append(f"Sender domain closely resembles trusted domain '{lookalike_result['matched_against']}' (possible lookalike)")
    if domain_reputation.get("flagged"):
        score += 8
        reasons.append("Sender domain flagged by threat intelligence")
    return min(score, WEIGHTS["domain"]), reasons


def score_urls(url_reputations: list[dict], suspicious_urls: dict = None) -> tuple[int, list[str]]:
    reasons = []
    score = 0
    for rep in url_reputations:
        if rep.get("flagged") or rep.get("engines_flagged", 0) > 0:
            score += 12
            reasons.append(f"URL flagged by threat intelligence: {rep.get('url')}")
            
    if suspicious_urls and suspicious_urls.get("matched_urls"):
        score += suspicious_urls.get("score_contribution", 0)
        reasons.extend(suspicious_urls.get("reasons", []))
        
    return min(score, WEIGHTS["url"]), reasons


def score_ip_reputation(ip_reputation: dict) -> tuple[int, list[str]]:
    reasons = []
    score = 0
    abuse_score = ip_reputation.get("abuse_confidence_score", 0)
    if isinstance(abuse_score, (int, float)) and abuse_score >= 50:
        score += 15
        reasons.append(f"Sending IP has high abuse confidence score ({abuse_score})")
    elif isinstance(abuse_score, (int, float)) and abuse_score >= 20:
        score += 7
        reasons.append(f"Sending IP has moderate abuse confidence score ({abuse_score})")
    return min(score, WEIGHTS["ip_reputation"]), reasons


def score_social_engineering(content_signals: dict) -> tuple[int, list[str]]:
    reasons = []
    contribution = content_signals.get("score_contribution", 0)
    for category, phrases in content_signals.get("matched_phrases", {}).items():
        if phrases:
            reasons.append(f"{category.replace('_', ' ').title()} language detected: {', '.join(phrases[:3])}")
    return min(contribution, WEIGHTS["social_engineering"]), reasons


def score_header_anomalies(reply_to_mismatch: bool) -> tuple[int, list[str]]:
    reasons = []
    score = 0
    if reply_to_mismatch:
        score += 10
        reasons.append("Reply-To domain differs from From domain (possible redirect/BEC pattern)")
    return min(score, WEIGHTS["header_anomaly"]), reasons


def classify(total_score: int) -> str:
    if total_score >= 80:
        return "CRITICAL"
    if total_score >= 60:
        return "HIGH"
    if total_score >= 30:
        return "SUSPICIOUS"
    return "LOW"


def compute_risk_score(signals: dict) -> dict:
    """
    `signals` is a dict assembled by main.py containing all the intermediate
    analysis results. Returns the final score, classification, and a flat
    list of human-readable reasons for the "Why Flagged?" screen.
    """
    auth_score, auth_reasons = score_authentication(signals["auth_results"])
    domain_score, domain_reasons = score_domain(signals["lookalike_result"], signals["domain_reputation"])
    url_score, url_reasons = score_urls(signals["url_reputations"], signals.get("suspicious_urls"))
    ip_score, ip_reasons = score_ip_reputation(signals["ip_reputation"])
    se_score, se_reasons = score_social_engineering(signals["content_signals"])
    header_score, header_reasons = score_header_anomalies(signals["reply_to_mismatch"])

    total = auth_score + domain_score + url_score + ip_score + se_score + header_score
    all_reasons = auth_reasons + domain_reasons + url_reasons + ip_reasons + se_reasons + header_reasons

    return {
        "total_score": total,
        "classification": classify(total),
        "breakdown": {
            "authentication": auth_score,
            "domain": domain_score,
            "url": url_score,
            "ip_reputation": ip_score,
            "social_engineering": se_score,
            "header_anomaly": header_score,
        },
        "max_possible": sum(WEIGHTS.values()),
        "reasons": all_reasons if all_reasons else ["No significant risk indicators detected."],
    }
