"""
REAL threat intelligence provider - calls IPinfo, AbuseIPDB, VirusTotal.
Only used when the corresponding API key is present in the environment.
If a call fails or the key is missing, we return an explicit
"unavailable" result rather than fabricating data (project rule #9).
"""
import os
import httpx

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")

_TIMEOUT = 6.0


def _unavailable(reason: str) -> dict:
    return {"mock_mode": False, "available": False, "reason": reason}


def geolocate_ip(ip: str) -> dict:
    if not IPINFO_TOKEN:
        return _unavailable("IPINFO_TOKEN not configured")
    try:
        resp = httpx.get(f"https://ipinfo.io/{ip}/json", params={"token": IPINFO_TOKEN}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return {
            "mock_mode": False,
            "available": True,
            "ip": ip,
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("org", "Unknown"),
            "asn": data.get("org", "Unknown").split(" ")[0] if data.get("org") else "Unknown",
        }
    except Exception as e:
        return _unavailable(f"IPinfo request failed: {e}")


def check_ip_reputation(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return _unavailable("ABUSEIPDB_KEY not configured")
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "mock_mode": False,
            "available": True,
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
        }
    except Exception as e:
        return _unavailable(f"AbuseIPDB request failed: {e}")


def check_domain_reputation(domain: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return _unavailable("VIRUSTOTAL_KEY not configured")
    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return {"mock_mode": False, "available": True, "domain": domain, "flagged": False, "note": "not previously scanned"}
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        flagged = (stats.get("malicious", 0) + stats.get("suspicious", 0)) > 0
        return {"mock_mode": False, "available": True, "domain": domain, "flagged": flagged}
    except Exception as e:
        return _unavailable(f"VirusTotal domain lookup failed: {e}")


def check_url_reputation(url: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return _unavailable("VIRUSTOTAL_KEY not configured")
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return {"mock_mode": False, "available": True, "url": url, "engines_flagged": 0, "note": "not previously scanned"}
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "mock_mode": False,
            "available": True,
            "url": url,
            "engines_flagged": stats.get("malicious", 0) + stats.get("suspicious", 0),
        }
    except Exception as e:
        return _unavailable(f"VirusTotal request failed: {e}")
