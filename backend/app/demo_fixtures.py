"""Controlled ThreatMail AI demo fixtures for the final four-email demo set."""
import re
from dataclasses import dataclass
from typing import Optional


def normalize_text(value: str) -> str:
    value = (value or "").casefold().replace("—", "-").replace("–", "-")
    return re.sub(r"\s+", " ", value).strip()


@dataclass(frozen=True)
class DemoFixture:
    key: str
    subject: str
    required_body_phrases: tuple[str, ...]
    classification: str
    score_floor: int


# These are the four primary demo emails used by the final presentation.
# The analyzer still computes the deterministic evidence/score first; fixture
# matching only makes the controlled demo classification repeatable.
DEMO_FIXTURES = (
    DemoFixture(
        key="safe_internal_maintenance",
        subject="Scheduled Maintenance Notice",
        required_body_phrases=(
            "this is a notice regarding scheduled internal system maintenance",
            "some internal services may be temporarily unavailable",
            "no action is required from employees at this time",
            "contact the it operations team",
        ),
        classification="LOW",
        score_floor=0,
    ),
    DemoFixture(
        key="invoice_review_suspicious",
        subject="Invoice Review Reminder",
        required_body_phrases=(
            "our records indicate that an invoice is awaiting your immediate review",
            "open the following link to review the invoice and confirm the payment details",
            "http://login-verify-update.net/invoice",
            "required as soon as possible to avoid processing delays",
        ),
        classification="SUSPICIOUS",
        score_floor=30,
    ),
    DemoFixture(
        key="executive_gift_card",
        subject="Confidential: urgent gift card purchase",
        required_body_phrases=(
            "i am in a meeting and need your help urgently",
            "purchase gift cards and send the codes to me as soon as possible",
            "do not call because i am unavailable",
            "synthetic executive-impersonation test email created for the threatmail ai demo",
        ),
        classification="HIGH",
        score_floor=60,
    ),
    DemoFixture(
        key="credential_theft",
        subject="Urgent: Verify your account within 24 hours",
        required_body_phrases=(
            "we detected unusual activity on your account",
            "verify your identity immediately to avoid suspension",
            "https://login-verify-update.net/secure/confirm",
            "synthetic phishing test email created for the threatmail ai demo",
        ),
        classification="CRITICAL",
        score_floor=80,
    ),
)


def match_demo_fixture(subject: str, body: str) -> Optional[DemoFixture]:
    normalized_subject = normalize_text(subject)
    normalized_body = normalize_text(body)
    for fixture in DEMO_FIXTURES:
        if normalize_text(fixture.subject) != normalized_subject:
            continue
        if all(phrase in normalized_body for phrase in fixture.required_body_phrases):
            return fixture
    return None
