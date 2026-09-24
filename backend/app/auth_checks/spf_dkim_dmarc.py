"""
Parses the Authentication-Results header for SPF/DKIM/DMARC verdicts.
This reads what the RECEIVING mail server already decided - it does not
re-run DNS checks itself. That's a reasonable simplification for a prototype:
re-implementing SPF/DKIM verification from scratch is a large, error-prone
undertaking and the receiving server's verdict is what real security tools
rely on too.
"""
import re


def parse_authentication_results(auth_headers: list[str]) -> dict:
    combined = " ".join(auth_headers) if auth_headers else ""

    return {
        "spf": _extract_verdict(combined, "spf"),
        "dkim": _extract_verdict(combined, "dkim"),
        "dmarc": _extract_verdict(combined, "dmarc"),
        "raw_header_present": bool(auth_headers),
    }


def _extract_verdict(text: str, mechanism: str) -> str:
    """Looks for patterns like 'spf=pass', 'dkim=fail', 'dmarc=none'."""
    match = re.search(rf"{mechanism}=(\w+)", text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return "not_found"


def check_reply_to_mismatch(from_domain: str | None, reply_to_domain: str | None) -> bool:
    """Flags a classic BEC pattern: reply-to silently redirects to a different domain."""
    if not from_domain or not reply_to_domain:
        return False
    return from_domain != reply_to_domain
