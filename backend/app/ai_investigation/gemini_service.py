"""Optional Gemini reasoning layer for SENTINEL-X.

The deterministic analysis remains authoritative. Gemini only explains evidence
already produced by the pipeline and is never used to calculate the risk score.
"""
import json
import os
from typing import Any, Dict

import httpx
from dotenv import load_dotenv

load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"))


DEFAULT_MODEL = "gemini-2.5-flash"
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def _clean_evidence(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the model input small and strictly tied to deterministic evidence."""
    allowed = {
        "case_id": bundle.get("case_id"),
        "email_metadata": bundle.get("email_metadata", {}),
        "risk": bundle.get("risk", {}),
        "authentication": bundle.get("authentication", {}),
        "infrastructure": bundle.get("infrastructure", {}),
        "indicators": bundle.get("indicators", {}),
        "content_analysis": bundle.get("content_analysis", {}),
    }
    # Do not send arbitrary user-controlled email body/HTML to the model.
    # The model should reason from normalized deterministic evidence only.
    allowed["evidence_scope"] = "Deterministic parser, authentication, IOC, reputation, geolocation, and risk outputs only."
    return allowed


def _fallback(reason: str) -> Dict[str, Any]:
    return {"available": False, "status": "unavailable", "reason": reason}


def analyze_with_gemini(bundle: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return _fallback("AI investigation unavailable")

    model = os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    evidence = _clean_evidence(bundle)
    prompt = f"""You are the explainability layer of SENTINEL-X, an email threat investigation prototype.

The deterministic pipeline has already calculated the risk score. DO NOT recalculate or override it.
Use ONLY the evidence JSON below. Never invent an IP, domain, URL, location, ISP, ASN, reputation,
authentication result, timestamp, threat actor, malware, attachment, or forensic event.
Do not infer a physical attacker location. Use the phrase 'observed sending infrastructure' for geolocation.
If evidence is insufficient, say 'Insufficient evidence' or 'Not available'.

Return ONLY valid JSON with exactly this shape:
{{
  "ai_disclaimer": "This is an AI-generated investigation/explanation based on deterministic evidence.",
  "why_flagged": "string (Why the email was flagged)",
  "key_evidence": ["list of key evidence points"],
  "threat_behavior": "string (Potential threat behavior)",
  "recommended_next_steps": ["list of recommended defensive next steps"]
}}

EVIDENCE JSON:
{json.dumps(evidence, ensure_ascii=False, indent=2)}"""

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    try:
        url = GEMINI_ENDPOINT.format(model=model)
        with httpx.Client(timeout=25.0) as client:
            response = client.post(url, params={"key": api_key}, json=payload)
            response.raise_for_status()
            data = response.json()

        text = ""
        for candidate in data.get("candidates", []):
            parts = candidate.get("content", {}).get("parts", [])
            for part in parts:
                if part.get("text"):
                    text += part["text"]
        if not text.strip():
            return _fallback("AI investigation unavailable")

        result = json.loads(text)
        if not isinstance(result, dict):
            return _fallback("AI investigation unavailable")

        required = {
            "ai_disclaimer", "why_flagged", "key_evidence",
            "threat_behavior", "recommended_next_steps"
        }
        if not required.issubset(result.keys()):
            return _fallback("AI investigation unavailable")
        if not isinstance(result.get("key_evidence"), list) or not isinstance(result.get("recommended_next_steps"), list):
            return _fallback("AI investigation unavailable")

        return {
            "available": True,
            "status": "success",
            **result,
        }
    except (httpx.HTTPError, ValueError, json.JSONDecodeError, KeyError, TypeError):
        return _fallback("AI investigation unavailable")
    except Exception:
        # AI must never break deterministic email analysis.
        return _fallback("AI investigation unavailable")
