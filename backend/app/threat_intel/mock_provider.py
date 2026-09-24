"""
MOCK threat intelligence provider.

All intelligence returned here is explicitly demo data. The IPs used by the
sample emails are RFC 5737 documentation addresses, and are mapped to synthetic
cities/countries so the ThreatMail AI demo can exercise its geolocation UI
without implying a real attacker location.
"""

_KNOWN_BAD_DOMAINS = {
    "paypa1-secure.com",
    "login-verify-update.net",
    "secure-appleid-confirm.com",
    "microsoft-verify-session.com",
    "amaz0n-billing-alert.example",
}

# Synthetic geolocation for documentation-only IPs used in demo .eml files.
# These are NOT real geolocation results.
_DEMO_GEO = {
    "192.0.2.10": {"country": "India", "city": "Mumbai"},
    "192.0.2.20": {"country": "Germany", "city": "Frankfurt"},
    "192.0.2.30": {"country": "Singapore", "city": "Singapore"},
    "192.0.2.40": {"country": "United Kingdom", "city": "London"},
    "192.0.2.50": {"country": "Australia", "city": "Sydney"},
    "192.0.2.60": {"country": "India", "state": "Maharashtra", "city": "Pune"},
}
_KNOWN_BAD_IPS = set(_DEMO_GEO) - {"192.0.2.60"}


def check_domain_reputation(domain: str) -> dict:
    is_flagged = domain in _KNOWN_BAD_DOMAINS
    return {
        "mock_mode": True,
        "domain": domain,
        "flagged": is_flagged,
        "verdict": "malicious (demo data)" if is_flagged else "no reputation hits (demo data)",
    }


def check_ip_reputation(ip: str) -> dict:
    is_flagged = ip in _KNOWN_BAD_IPS
    return {
        "mock_mode": True,
        "ip": ip,
        "abuse_confidence_score": 92 if is_flagged else 3,
        "verdict": "high abuse reports (demo data)" if is_flagged else "clean (demo data)",
    }


def check_url_reputation(url: str) -> dict:
    is_flagged = any(bad in url for bad in _KNOWN_BAD_DOMAINS)
    return {
        "mock_mode": True,
        "url": url,
        "engines_flagged": 14 if is_flagged else 0,
        "verdict": "malicious (demo data)" if is_flagged else "clean (demo data)",
    }


def geolocate_ip(ip: str) -> dict:
    location = _DEMO_GEO.get(ip)
    if location:
        return {
            "mock_mode": True,
            "demo_location": True,
            "ip": ip,
            "country": location["country"],
            "city": location["city"],
            "state": location.get("state"),
            "synthetic_demo_data": True,
            "isp": "Synthetic Demo Network",
            "asn": "AS00000 (demo)",
            "vpn_or_proxy_suspected": True,
            "note": "SYNTHETIC DEMO DATA; not a real-world IP location and not the actual sender location.",
        }
    return {
        "mock_mode": True,
        "demo_location": False,
        "ip": ip,
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unavailable in demo mode",
        "asn": "Unavailable",
        "vpn_or_proxy_suspected": False,
    }
