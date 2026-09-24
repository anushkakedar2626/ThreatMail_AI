"""
Regex-based IOC extraction: IPs, URLs, domains from body + headers.
This is intentionally simple regex logic for a prototype - not a full
threat-intel-grade parser. Good enough to demonstrate the concept.
"""
import ipaddress
import re

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>\[\]\)]+")

# Private/reserved ranges we skip when looking for the "earliest reliable public IP"
_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
]


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # RFC 5737 documentation IPs are normally rejected, but these six controlled
    # addresses are explicitly allowed for the local mock-intelligence demo so
    # location processing can be exercised without using real public infrastructure.
    if ip_str in {
        "192.0.2.10",  # Mumbai
        "192.0.2.20",  # Frankfurt
        "192.0.2.30",  # Singapore
        "192.0.2.40",  # London
        "192.0.2.50",  # Sydney
        "192.0.2.60",  # Pune
    }:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return False
    return not any(ip in net for net in _PRIVATE_NETS)


def extract_ips_from_received_headers(received_headers: list[str]) -> list[str]:
    """Received headers are listed newest-first. We reverse to read oldest-first,
    since the oldest hop is closest to the true origin."""
    ips_in_order = []
    for header in reversed(received_headers):
        matches = IPV4_PATTERN.findall(header)
        for ip in matches:
            if ip not in ips_in_order:
                ips_in_order.append(ip)
    return ips_in_order


def find_earliest_reliable_public_ip(received_headers: list[str]) -> dict:
    """
    Returns the earliest public IP found while walking the relay chain oldest->newest.
    NOTE: this is a heuristic, not a guarantee - intermediary relays and privacy
    services can still sit before this point. Always report this with a confidence
    caveat, never as a confirmed attacker location.
    """
    ordered_ips = extract_ips_from_received_headers(received_headers)
    for ip in ordered_ips:
        if is_public_ip(ip):
            return {
                "ip": ip,
                "note": "Earliest reliable public IP found in the relay chain. "
                        "This reflects observed sending infrastructure, not "
                        "necessarily the attacker's physical location.",
            }
    return {
        "ip": None,
        "note": "No public IP could be reliably determined from the available headers.",
    }


def extract_urls(text: str) -> list[str]:
    return list(dict.fromkeys(URL_PATTERN.findall(text or "")))


def extract_domains_from_urls(urls: list[str]) -> list[str]:
    domains = []
    for url in urls:
        match = re.match(r"https?://([^/]+)", url)
        if match:
            domain = match.group(1).split(":")[0].lower()
            if domain not in domains:
                domains.append(domain)
    return domains
