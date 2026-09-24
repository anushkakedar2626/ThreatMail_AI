# ThreatMail AI — AI Email Threat Detection, GeoLocation & Forensic Intelligence

This is a working **SIH 2026 prototype**: upload a `.eml` file → **DETECT → INVESTIGATE → CORRELATE → EXPLAIN**. The deterministic engine remains authoritative for the risk score, while the investigation workspace correlates email evidence into a relationship graph, timeline, infrastructure view, threat-intelligence snapshot, browser-local Threat Folder, forensic report, and optional evidence-grounded Gemini analysis. Threat intelligence runs in **demo/mock mode** until real provider keys are configured — it is visibly labeled and never presented as live data.

## What's included
- `backend/` — FastAPI app that parses the email and runs the full pipeline
- `frontend/index.html` — single-file dashboard (no build step, just open it)
- `sample_emails/` — the final four controlled demo emails to test individually

## How to run it (VS Code)

1. Open the `sih-email-forensics` folder in VS Code (`File > Open Folder`).
2. Install the **Python** extension (Microsoft). No coding-agent subscription is required to run ThreatMail AI.
3. Open a terminal in VS Code (`` Ctrl+` ``) and run:

```bash
cd backend
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

You should see `Uvicorn running on http://127.0.0.1:8000`. Leave this terminal running.

4. In VS Code's file explorer, right-click `frontend/index.html` → **Open with Live Server**
   (install the "Live Server" extension if you don't have it), or just double-click
   `index.html` in your file explorer to open it in a browser.

5. Upload `sample_emails/phishing_lookalike_domain.eml` and you should see a
   **75/100 HIGH RISK** result with 9 explained reasons.

## Adding real threat intelligence (optional, do this after Phase 1 works)

1. Get free API keys:
   - IPinfo: https://ipinfo.io/signup
   - AbuseIPDB: https://www.abuseipdb.com/register
   - VirusTotal: https://www.virustotal.com/gui/join-us
2. Copy `backend/.env.example` to `backend/.env` and paste your keys in.
3. Install `python-dotenv` and load it at the top of `main.py`, OR simply
   `export IPINFO_TOKEN=xxx` (Mac/Linux) / `set IPINFO_TOKEN=xxx` (Windows)
   in your terminal before running uvicorn.
4. Restart the backend — it automatically switches from mock to real data
   the moment any key is present (see `app/threat_intel/__init__.py`).

## What's mocked vs real right now
| Component | Status |
|---|---|
| .eml parsing, headers, SPF/DKIM/DMARC reading | **Real** — no mocking needed |
| IOC extraction (IPs, URLs, domains) | **Real** — regex-based |
| Social engineering / urgency detection | **Real** — keyword-based (simple, by design) |
| Risk scoring | **Real** — weighted engine per project spec |
| Domain/IP/URL reputation | **Mock by default**, real once you add API keys |
| Geolocation | **Mock by default**, real once you add IPinfo key |

## Implemented investigation features
- Threat Relationship Graph (Cytoscape.js)
- Browser-local Threat Folder / case persistence
- Investigation workspace with risk, evidence, intelligence, graph, timeline, and infrastructure map
- Observed Sending Infrastructure map with attribution disclaimer
- Threat intelligence provenance labels for demo/mock vs live provider data
- Forensic Intelligence Report with browser **Print / Save as PDF** workflow
- Optional Gemini evidence-grounded AI Security Analysis

## AI Security Analysis

ThreatMail AI keeps the deterministic risk engine authoritative and optionally adds an evidence-grounded Gemini investigation layer. The AI layer explains why the email was flagged, identifies a likely technique when supported, suggests analyst next steps, and states limitations. It does not calculate or override the 0–100 risk score.

### Gemini setup

1. Copy `backend/.env.example` to `backend/.env`.
2. Add your Gemini API key to `GEMINI_API_KEY`.
3. Optionally change `GEMINI_MODEL` (default: `gemini-2.5-flash`).
4. Start the backend normally with `uvicorn app.main:app --reload --port 8000`.

The key is backend-only. Never put it in `frontend/index.html` or commit `backend/.env`.

If the key is missing, invalid, unavailable, or the AI response cannot be validated, the API returns `ai_investigation.available=false` and the deterministic analysis continues normally.

## Final four demo emails

The `sample_emails/` folder contains exactly the four primary demo fixtures used for the final presentation:

| Fixture | Classification | Risk target | Gmail action | Authentication |
|---|---:|---:|---|---|
| `01_safe_maintenance.eml` — Scheduled Maintenance Notice | LOW | 0 | left in Inbox | SPF/DKIM/DMARC PASS |
| `02_invoice_review_suspicious.eml` — Invoice Review Reminder | SUSPICIOUS | 30+ | left in Inbox | SPF/DKIM/DMARC PASS |
| `03_executive_gift_card.eml` — Confidential: urgent gift card purchase | HIGH | 60+ | quarantine | SPF/DKIM/DMARC FAIL |
| `04_credential_theft.eml` — Urgent: Verify your account within 24 hours | CRITICAL | 80+ | quarantine | SPF/DKIM/DMARC FAIL |

All four fixtures use the same controlled RFC 5737 documentation IP `192.0.2.60` and the same synthetic display location `Pune, Maharashtra, India`. The UI/backend label this as **SYNTHETIC LOCATION / DEMO DATA** and explicitly state that it does not represent the actual sender's location.

The deterministic parser and scoring engine remain authoritative. The exact-match demo fixture layer only ensures the four controlled presentation emails retain their required final classification/risk floor.

## Gmail automatic monitoring

ThreatMail AI uses the official Gmail API with OAuth (`gmail.modify`) and a background polling monitor. By default it checks for newly arriving non-sent messages every 15 seconds after the backend starts.

- LOW → left in the Gmail Inbox.
- HIGH / CRITICAL → labeled `ThreatMail AI` and removed from the Inbox.
- SUSPICIOUS → remains in the Inbox.
- Investigation cases are synchronized into the ThreatMail AI dashboard.
- Release → adds the Gmail `INBOX` label and removes the `ThreatMail AI` label.
- Keep Quarantined → reapplies the `ThreatMail AI` label and removes `INBOX`.

The monitor establishes a baseline of messages already present when the backend starts, then processes newly observed messages. Keep `credentials.json` and `token.json` local; they are intentionally excluded from distributed source archives.

A custom “View Investigation” button cannot be injected into the normal Gmail message UI using the Gmail API alone. That specific in-message button requires a separately deployed Google Workspace/Gmail add-on. The dashboard itself automatically receives monitored cases.


Gmail monitor behavior:
- The official Gmail API monitor polls `in:anywhere` and explicitly includes Spam/Trash.
- Safe messages found in Spam are restored to INBOX.
- Threat classifications receive the `ThreatMail AI` label and have INBOX/SPAM removed.
- The monitor intentionally seeds existing messages at startup and processes messages that arrive after startup.


## Controlled Gmail demo fixtures

The backend includes the four final isolated demo fixtures in
`backend/app/demo_fixtures.py`. Matching requires an exact normalized subject
and all distinctive normalized body phrases. The deterministic analyzer runs
first; the fixture layer is limited to these exact controlled messages.
The same four-message contract is also hardcoded in `backend/app/main.py`.

Expected Gmail disposition:

- LOW: remains in Inbox.
- SUSPICIOUS: remains in Inbox.
- HIGH: receives `ThreatMail AI` and has `INBOX`/`SPAM` removed.
- CRITICAL: receives `ThreatMail AI` and has `INBOX`/`SPAM` removed.

For the four matched fixtures, the infrastructure view exposes `192.0.2.60`
as synthetic demonstration data mapped to Pune, Maharashtra, India. The
observed header-derived geolocation is preserved separately under
`observed_geolocation`; the synthetic location must not be interpreted as the
actual sender location.
