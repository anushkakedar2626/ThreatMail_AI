# ThreatMail AI Gmail Add-on

The add-on now sends the **current Gmail message's raw MIME content** to the same `/api/analyze` FastAPI endpoint used by the ThreatMail AI dashboard.

## Configure the backend URL

In Apps Script:

1. Open **Project Settings**.
2. Add a **Script Property**:
   - Name: `THREATMAIL_BACKEND_URL`
   - Value: your deployed HTTPS backend URL, for example `https://threatmail.example.com`
3. Optional: add `THREATMAIL_API_TOKEN` if your deployment protects the endpoint with `X-ThreatMail-Token`.
4. Deploy/redeploy the Gmail Add-on and authorize the new external-request scope.

Do not use `http://localhost:8000` for a deployed Gmail Add-on. Google's Apps Script runtime cannot reach your laptop's localhost. Use a publicly reachable HTTPS deployment of the backend.

## Behavior

Opening an email triggers `onGmailMessage()`. The add-on reads the current message with the Gmail contextual-message access token, obtains the raw MIME message, posts it as `gmail-message.eml` to `/api/analyze`, and renders the backend response.

The add-on does **not** calculate its own risk score or classification. The backend remains authoritative.

For the four controlled demo fixtures, the response can include:

- classification and risk score
- SPF / DKIM / DMARC
- suspicious URLs and deterministic reasons
- synthetic `192.0.2.60` / Pune demo location
- demo-data disclaimer
- Gmail action where supplied by the backend
- evidence-grounded AI explanation when Gemini is configured

## Current limitation

The repository can validate the Apps Script source and backend contract, but it cannot perform a live Google Workspace Add-on deployment or Gmail OAuth test from this environment.
