"""
Parses a raw .eml file into a structured dict: headers, body, auth-results.
Uses Python's built-in email library only - no external dependencies needed.
"""
from email import message_from_bytes
from email.message import Message
from email.utils import getaddresses
from typing import Optional


def parse_eml(raw_bytes: bytes) -> dict:
    msg: Message = message_from_bytes(raw_bytes)

    return {
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "date": msg.get("Date", ""),
        "received_headers": msg.get_all("Received", []) or [],
        "authentication_results": msg.get_all("Authentication-Results", []) or [],
        "body_text": _extract_body(msg),
        "sender_domain": _extract_domain(msg.get("From", "")),
        "reply_to_domain": _extract_domain(msg.get("Reply-To", "")) if msg.get("Reply-To") else None,
    }


def _extract_body(msg: Message) -> str:
    """Pulls plain-text body; falls back to stripped HTML if no text/plain part exists."""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/plain" and "attachment" not in disposition:
                return _decode_part(part)
        # fallback: no plain text part found, try html
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                return _decode_part(part)
        return ""
    else:
        return _decode_part(msg)


def _decode_part(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace") if payload else ""
    except Exception:
        return ""


def _extract_domain(address_header: str) -> Optional[str]:
    if not address_header:
        return None
    addresses = getaddresses([address_header])
    if not addresses:
        return None
    email_addr = addresses[0][1]
    if "@" not in email_addr:
        return None
    return email_addr.split("@")[-1].lower()
