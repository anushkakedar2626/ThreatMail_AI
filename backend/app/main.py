"""
SENTINEL-X backend: deterministic email forensics plus optional AI explainability.
Run with:  uvicorn app.main:app --reload --port 8000
"""
import uuid
import io
import asyncio
import os
from typing import Dict, Any
from datetime import datetime, timezone

from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from app.parser.eml_parser import parse_eml
from app.parser.ioc_extractor import extract_urls, extract_domains_from_urls, find_earliest_reliable_public_ip
from app.auth_checks.spf_dkim_dmarc import parse_authentication_results, check_reply_to_mismatch
from app.risk_engine.content_signals import detect_social_engineering, detect_lookalike_domain, detect_suspicious_urls
from app.risk_engine.scorer import compute_risk_score
from app.threat_intel import provider as ti
from app.ai_investigation.gemini_service import analyze_with_gemini
from app.demo_fixtures import match_demo_fixture

from app.gmail.gmail_service import (
    get_gmail_service,
    get_recent_message_raw,
    get_recent_message_ids,
    apply_threat_label,
    release_threat_message,
    release_to_inbox,
)

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

app = FastAPI(title="Email Threat Detection & Forensic Intelligence Platform - Prototype")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # fine for a local prototype; restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# A short list of domains commonly impersonated in phishing - used for the
# lookalike-domain check. Extend this for your demo scenarios.
TRUSTED_DOMAINS_WATCHLIST = [
    "paypal.com", "apple.com", "microsoft.com", "google.com",
    "amazon.com", "irctc.co.in", "sbi.co.in", "incometax.gov.in",
]

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB is generous for an .eml

# Prototype case store. Analysis remains authoritative; this only stores the
# analyzed case and original message so disposition/content access can work.
CASE_STORE: Dict[str, Dict[str, Any]] = {}
GMAIL_MONITOR_SEEN: set[str] = set()
GMAIL_MONITOR_TASK = None
GMAIL_MONITOR_STATE: Dict[str, Any] = {
    "enabled": True,
    "running": False,
    "authenticated": False,
    "last_poll_at": None,
    "last_error": None,
    "processed_count": 0,
}
GMAIL_POLL_SECONDS = max(5, int(os.getenv("GMAIL_POLL_SECONDS", "15")))
THREAT_CLASSIFICATIONS = {"HIGH", "CRITICAL"}
SYNTHETIC_DEMO_IP = "192.0.2.60"
SYNTHETIC_DEMO_LOCATION = {
    "city": "Pune",
    "state": "Maharashtra",
    "country": "India",
}

# Final four-email demo set is intentionally hardcoded here as the canonical
# presentation contract. Analysis/evidence still comes from the deterministic
# parser and risk engine; this metadata only defines expected demo disposition.
FINAL_DEMO_EMAILS = {
    "Scheduled Maintenance Notice": {"classification": "LOW", "action": "left_in_inbox"},
    "Invoice Review Reminder": {"classification": "SUSPICIOUS", "action": "left_in_inbox"},
    "Confidential: urgent gift card purchase": {"classification": "HIGH", "action": "quarantined_from_inbox"},
    "Urgent: Verify your account within 24 hours": {"classification": "CRITICAL", "action": "quarantined_from_inbox"},
}

class DispositionRequest(BaseModel):
    disposition: str


@app.get("/")
def health_check():
    return {"status": "ok", "service": "email-forensics-prototype"}


def analyze_raw_email(raw_bytes: bytes):
    """Run the existing ThreatMail AI analysis engine on raw email bytes."""

    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail="File too large for prototype (5MB limit)"
        )

    if not raw_bytes:
        raise HTTPException(
            status_code=400,
            detail="Email is empty"
        )

    try:
        parsed = parse_eml(raw_bytes)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Could not parse .eml file: {e}"
        )

    # --- Header / authentication analysis ---
    auth_results = parse_authentication_results(
        parsed["authentication_results"]
    )

    reply_to_mismatch = check_reply_to_mismatch(
        parsed["sender_domain"],
        parsed["reply_to_domain"]
    )

    earliest_ip_info = find_earliest_reliable_public_ip(
        parsed["received_headers"]
    )

    # --- IOC extraction ---
    urls = extract_urls(parsed["body_text"])
    url_domains = extract_domains_from_urls(urls)

    # --- Content / social engineering ---
    content_signals = detect_social_engineering(
        f"{parsed.get('subject', '')} {parsed.get('body_text', '')}"
    )

    suspicious_urls = detect_suspicious_urls(urls)

    lookalike_result = detect_lookalike_domain(
        parsed["sender_domain"],
        TRUSTED_DOMAINS_WATCHLIST
    )

    # --- Threat intelligence ---
    domain_reputation = (
        ti.check_domain_reputation(parsed["sender_domain"])
        if parsed["sender_domain"]
        else {}
    )

    url_reputations = [
        ti.check_url_reputation(u)
        for u in urls[:10]
    ]

    ip_reputation = (
        ti.check_ip_reputation(earliest_ip_info["ip"])
        if earliest_ip_info["ip"]
        else {}
    )

    geolocation = (
        ti.geolocate_ip(earliest_ip_info["ip"])
        if earliest_ip_info["ip"]
        else {
            "note": "No public IP available to geolocate."
        }
    )

    # --- Controlled demo fixture detection ---
    # The deterministic analyzer always runs first. Fixture handling is limited
    # to the exact controlled subjects/body patterns in demo_fixtures.py.
    demo_fixture = match_demo_fixture(
        parsed.get("subject", ""),
        parsed.get("body_text", ""),
    )

    # --- Risk scoring ---
    signals = {
        "auth_results": auth_results,
        "lookalike_result": lookalike_result,
        "domain_reputation": domain_reputation,
        "url_reputations": url_reputations,
        "suspicious_urls": suspicious_urls,
        "ip_reputation": ip_reputation,
        "content_signals": content_signals,
        "reply_to_mismatch": reply_to_mismatch,
    }

    risk = compute_risk_score(signals)

    synthetic_demo_location = None
    if demo_fixture:
        original_score = risk.get("total_score", 0)
        if demo_fixture.classification == "LOW":
            # A matched benign fixture must remain LOW even if a harmless
            # transport/header signal is present.
            risk["total_score"] = min(original_score, 29)
        else:
            risk["total_score"] = max(original_score, demo_fixture.score_floor)
        risk["classification"] = demo_fixture.classification
        risk.setdefault("reasons", []).append(
            f"Controlled demo fixture matched: {demo_fixture.key}"
        )
        risk["demo_fixture"] = {
            "matched": True,
            "key": demo_fixture.key,
            "classification_override": demo_fixture.classification,
            "original_deterministic_score": original_score,
        }
        synthetic_demo_location = {
            "mock_mode": True,
            "demo_location": True,
            "synthetic_demo_data": True,
            "ip": SYNTHETIC_DEMO_IP,
            "country": SYNTHETIC_DEMO_LOCATION["country"],
            "state": SYNTHETIC_DEMO_LOCATION["state"],
            "city": SYNTHETIC_DEMO_LOCATION["city"],
            "isp": "Synthetic Demo Network",
            "asn": "AS00000 (demo)",
            "vpn_or_proxy_suspected": True,
            "note": (
                "SYNTHETIC DEMO DATA only. Pune is not the actual sender "
                "location and is not derived from observed email headers."
            ),
        }

    case_id = (
        f"THR-{datetime.now(timezone.utc).year}-"
        f"{str(uuid.uuid4())[:5].upper()}"
    )

    response = {
        "case_id": case_id,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),

        "email_metadata": {
            "subject": parsed["subject"],
            "from": parsed["from"],
            "reply_to": parsed["reply_to"],
            "sender_domain": parsed["sender_domain"],
            "message_id": parsed["message_id"],
            "date": parsed["date"],
        },

        "risk": risk,

        "authentication": auth_results,

        "infrastructure": {
            "earliest_public_ip": earliest_ip_info,
            "geolocation": synthetic_demo_location or geolocation,
            "observed_geolocation": geolocation,
            "synthetic_demo_location": synthetic_demo_location,
            "ip_reputation": ip_reputation,
            "attribution_disclaimer": (
                "This reflects observed sending infrastructure only. "
                "Physical attacker location cannot be reliably determined "
                "from email headers alone, especially if VPNs, proxies, "
                "or compromised servers were used."
            ),
        },

        "indicators": {
            "urls": urls,
            "url_domains": url_domains,
            "url_reputations": url_reputations,
            "domain_reputation": domain_reputation,
            "lookalike_domain": lookalike_result,
            "suspicious_urls": suspicious_urls,
        },

        "content_analysis": content_signals,

        "safe_preview": {
            "subject": parsed["subject"],
            "body_text": parsed["body_text"][:2000],
        },

        "demo_data": {
            "is_final_demo_email": parsed.get("subject", "") in FINAL_DEMO_EMAILS,
            "expected_action": (FINAL_DEMO_EMAILS.get(parsed.get("subject", ""), {}).get("action")),
            "synthetic_ip": SYNTHETIC_DEMO_IP if demo_fixture else None,
            "synthetic_location": SYNTHETIC_DEMO_LOCATION if demo_fixture else None,
            "label": "SYNTHETIC LOCATION / DEMO DATA" if demo_fixture else None,
            "disclaimer": (
                "This is controlled synthetic demonstration data and does not represent the actual sender's location."
                if demo_fixture else None
            ),
        },
    }

    # Optional explainability layer
    response["ai_investigation"] = analyze_with_gemini(response)

    # Store case
    classification = risk.get("classification", "LOW")
    CASE_STORE[case_id] = {
        "analysis": response,
        "raw_bytes": raw_bytes,
        "disposition": "quarantined" if classification in THREAT_CLASSIFICATIONS else "released",
        "gmail_message_id": None,
    }

    return response


@app.post("/api/analyze")
async def analyze_email(
    file: UploadFile = File(...),
    x_threatmail_token: str | None = Header(default=None),
):
    """Analyze an uploaded .eml for the dashboard and Gmail Add-on."""

    expected_token = os.getenv("THREATMAIL_API_TOKEN", "").strip()
    if expected_token and x_threatmail_token != expected_token:
        raise HTTPException(status_code=401, detail="Invalid ThreatMail API token")

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a .eml file"
        )

    raw_bytes = await file.read()

    return analyze_raw_email(raw_bytes)

async def _process_gmail_message(service, message_id: str):
    """Download, analyze, and enforce the Inbox/quarantine policy for one message."""
    message = service.users().messages().get(
        userId="me", id=message_id, format="raw"
    ).execute()
    raw_data = message.get("raw")
    if not raw_data:
        return None
    import base64
    email_bytes = base64.urlsafe_b64decode(raw_data + "===")
    analysis = analyze_raw_email(email_bytes)
    case_id = analysis["case_id"]
    classification = analysis.get("risk", {}).get("classification", "LOW")
    is_threat = classification in THREAT_CLASSIFICATIONS
    fixture_info = (analysis.get("risk") or {}).get("demo_fixture") or {}
    print(
        "[ThreatMail AI] Gmail message_id=%s fixture=%s classification=%s "
        "risk_score=%s action=%s"
        % (
            message_id,
            fixture_info.get("key", "none"),
            classification,
            (analysis.get("risk") or {}).get("total_score", 0),
            "quarantined_from_inbox" if is_threat else "left_in_inbox",
        )
    )

    CASE_STORE[case_id]["gmail_message_id"] = message_id
    CASE_STORE[case_id]["source"] = "gmail_api"
    CASE_STORE[case_id]["disposition"] = "quarantined" if is_threat else "released"
    analysis["gmail"] = {
        "message_id": message_id,
        "action": "quarantined_from_inbox" if is_threat else "left_in_inbox",
    }

    if is_threat:
        apply_threat_label(service, message_id)
    else:
        # Gmail may have placed a safe test message in Spam. The application
        # disposition is authoritative for this demo, so restore it to Inbox.
        release_to_inbox(service, message_id)

    return {
        "gmail_message_id": message_id,
        "case_id": case_id,
        "classification": classification,
        "action_taken": "quarantined_from_inbox" if is_threat else "left_in_inbox",
        "threatmail_analysis": analysis,
    }


async def gmail_monitor_loop():
    """Poll Gmail using the official API and process newly observed messages."""
    global GMAIL_MONITOR_SEEN
    GMAIL_MONITOR_STATE["running"] = True
    seeded = False
    while True:
        try:
            service = get_gmail_service(interactive=False)
            GMAIL_MONITOR_STATE["authenticated"] = service is not None
            if service is not None:
                ids = get_recent_message_ids(service, max_results=20)
                if not seeded:
                    # Establish a baseline on startup. Only messages arriving after
                    # the monitor starts are automatically processed.
                    GMAIL_MONITOR_SEEN.update(ids)
                    seeded = True
                else:
                    for message_id in reversed(ids):
                        if message_id in GMAIL_MONITOR_SEEN:
                            continue
                        GMAIL_MONITOR_SEEN.add(message_id)
                        result = await _process_gmail_message(service, message_id)
                        if result:
                            GMAIL_MONITOR_STATE["processed_count"] += 1
                GMAIL_MONITOR_STATE["last_error"] = None
            GMAIL_MONITOR_STATE["last_poll_at"] = datetime.now(timezone.utc).isoformat()
        except Exception as exc:
            GMAIL_MONITOR_STATE["last_error"] = str(exc)
        await asyncio.sleep(GMAIL_POLL_SECONDS)

@app.on_event("startup")
async def start_gmail_monitor():
    global GMAIL_MONITOR_TASK
    if os.getenv("GMAIL_MONITOR_ENABLED", "true").lower() != "false":
        GMAIL_MONITOR_TASK = asyncio.create_task(gmail_monitor_loop())

@app.on_event("shutdown")
async def stop_gmail_monitor():
    global GMAIL_MONITOR_TASK
    if GMAIL_MONITOR_TASK:
        GMAIL_MONITOR_TASK.cancel()
        try:
            await GMAIL_MONITOR_TASK
        except asyncio.CancelledError:
            pass
        GMAIL_MONITOR_TASK = None


@app.get("/api/gmail/monitor/status")
def gmail_monitor_status():
    return {**GMAIL_MONITOR_STATE, "poll_seconds": GMAIL_POLL_SECONDS}


@app.get("/api/gmail/monitor/cases")
def gmail_monitor_cases():
    cases = []
    for case_id, case in CASE_STORE.items():
        if case.get("source") == "gmail_api":
            cases.append({
                "case_id": case_id,
                "gmail_message_id": case.get("gmail_message_id"),
                "disposition": case.get("disposition"),
                "analysis": case.get("analysis"),
            })
    return {"cases": list(reversed(cases[-50:]))}


@app.get("/api/gmail/test")
def test_gmail_analysis():
    """Fetch the latest Gmail message and run ThreatMail AI analysis."""

    try:
        service = get_gmail_service()

        message_id, email_bytes = get_recent_message_raw(service)

        if email_bytes is None:
            raise HTTPException(
                status_code=404,
                detail="No Gmail messages found."
            )

        analysis = analyze_raw_email(email_bytes)

        return {
            "gmail_message_id": message_id,
            "threatmail_analysis": analysis
        }

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Gmail analysis failed: {str(e)}"
        )


@app.get("/api/gmail/respond")
def respond_gmail_analysis():
    """Fetch the latest Gmail message, run ThreatMail AI analysis, and take action if HIGH/CRITICAL."""
    try:
        service = get_gmail_service()

        message_id, email_bytes = get_recent_message_raw(service)

        if email_bytes is None:
            raise HTTPException(
                status_code=404,
                detail="No Gmail messages found."
            )

        analysis = analyze_raw_email(email_bytes)
        classification = analysis.get("risk", {}).get("classification", "LOW")

        action_taken = "left_in_inbox"
        if classification in THREAT_CLASSIFICATIONS:
            apply_threat_label(service, message_id)
            action_taken = "quarantined_from_inbox"
        else:
            release_to_inbox(service, message_id)

        return {
            "gmail_message_id": message_id,
            "classification": classification,
            "action_taken": action_taken,
            "threatmail_analysis": analysis
        }

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Gmail response failed: {str(e)}"
        )


@app.post("/api/cases/{case_id}/disposition")
def set_case_disposition(case_id: str, request: DispositionRequest):
    case = CASE_STORE.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found. Re-analyze the email in this backend session.")
    if request.disposition not in {"quarantined", "released"}:
        raise HTTPException(status_code=400, detail="Disposition must be quarantined or released")
    gmail_message_id = case.get("gmail_message_id")
    if gmail_message_id:
        try:
            service = get_gmail_service(interactive=False)
            if service is None:
                raise HTTPException(status_code=503, detail="Gmail authentication is not available for this case")
            if request.disposition == "released":
                release_threat_message(service, gmail_message_id)
            else:
                apply_threat_label(service, gmail_message_id)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Gmail action failed: {exc}")
    case["disposition"] = request.disposition
    return {"case_id": case_id, "disposition": case["disposition"], "gmail_message_id": gmail_message_id}



@app.get("/api/cases/{case_id}/content")
def get_released_content(case_id: str):
    case = CASE_STORE.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if case["disposition"] != "released":
        raise HTTPException(status_code=403, detail="Email content is quarantined. Release the email first.")
    raw = case["raw_bytes"]
    parsed = parse_eml(raw)
    return {"case_id": case_id, "subject": parsed["subject"], "body": parsed["body_text"], "raw": raw.decode("utf-8", errors="replace")}


def _pdf_text(value):
    if value is None:
        return "—"
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@app.get("/api/reports/{case_id}/pdf")
def download_report_pdf(case_id: str):
    if not REPORTLAB_AVAILABLE:
        raise HTTPException(status_code=500, detail="PDF generation requires reportlab. Install backend requirements first.")
    case = CASE_STORE.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found. Re-analyze the email in this backend session.")
    data = case["analysis"]
    risk = data.get("risk") or {}
    meta = data.get("email_metadata") or {}
    auth = data.get("authentication") or {}
    ind = data.get("indicators") or {}
    infra = data.get("infrastructure") or {}
    content = data.get("content_analysis") or {}

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    styles["Title"].alignment = TA_CENTER
    story = [Paragraph("ThreatMail AI — Forensic Intelligence Report", styles["Title"]), Spacer(1, 14)]
    rows = [
        ["Case ID", _pdf_text(data.get("case_id"))],
        ["Classification", _pdf_text(risk.get("classification", "LOW"))],
        ["Risk score", _pdf_text(f'{risk.get("total_score", 0)} / {risk.get("max_possible", 100)}')],
        ["Disposition", _pdf_text(case.get("disposition", "quarantined").upper())],
        ["Subject", _pdf_text(meta.get("subject", "(no subject)"))],
        ["From", _pdf_text(meta.get("from", "—"))],
        ["Reply-To", _pdf_text(meta.get("reply_to", "(none)"))],
        ["Analyzed", _pdf_text(data.get("analyzed_at"))],
    ]
    t=Table(rows, colWidths=[110, 390])
    t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.4,colors.grey),("BACKGROUND",(0,0),(0,-1),colors.whitesmoke),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTNAME",(0,0),(0,-1),"Helvetica-Bold")]))
    story += [t, Spacer(1, 18), Paragraph("Executive Summary", styles["Heading2"])]
    reasons = risk.get("reasons") or ["No significant risk indicators detected."]
    story.append(Paragraph("<br/>".join("• " + _pdf_text(x) for x in reasons), styles["BodyText"]))
    story += [Spacer(1, 12), Paragraph("Authentication", styles["Heading2"])]
    story.append(Paragraph(f"SPF: {_pdf_text(auth.get('spf','not_found'))} &nbsp;&nbsp; DKIM: {_pdf_text(auth.get('dkim','not_found'))} &nbsp;&nbsp; DMARC: {_pdf_text(auth.get('dmarc','not_found'))}", styles["BodyText"]))
    story += [Spacer(1, 12), Paragraph("Observed Indicators", styles["Heading2"])]
    urls = ind.get("urls") or []
    domains = ind.get("url_domains") or []
    story.append(Paragraph("URLs: " + _pdf_text(", ".join(urls) if urls else "None"), styles["BodyText"]))
    story.append(Paragraph("URL domains: " + _pdf_text(", ".join(domains) if domains else "None"), styles["BodyText"]))
    story.append(Paragraph("Sender domain: " + _pdf_text(meta.get("sender_domain", "—")), styles["BodyText"]))
    story.append(Paragraph("Earliest public IP: " + _pdf_text((infra.get("earliest_public_ip") or {}).get("ip", "Not found")), styles["BodyText"]))
    demo_loc = infra.get("synthetic_demo_location") or {}
    if demo_loc.get("synthetic_demo_data"):
        story.append(Paragraph("Synthetic location: Pune, Maharashtra, India (DEMO DATA)", styles["BodyText"]))
        story.append(Paragraph("This is controlled synthetic demonstration data and does not represent the actual sender's location.", styles["BodyText"]))
    story += [Spacer(1, 12), Paragraph("Content Analysis", styles["Heading2"]), Paragraph(_pdf_text(content), styles["BodyText"])]
    story += [Spacer(1, 16), Paragraph("Evidence Integrity Note", styles["Heading2"]), Paragraph("This report contains values returned by the deterministic analysis and evidence-grounded investigation layers. It does not infer attacker identity, physical location, or hidden network context.", styles["BodyText"])]
    doc.build(story)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="ThreatMail_Forensic_Report_{case_id}.pdf"'})
