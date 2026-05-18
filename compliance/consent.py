#!/usr/bin/env python3
"""
Consent Management — POPIA-compliant consent capture, scope tracking, and withdrawal.

Every consent event is:
  1. Recorded in the audit trail (tamper-evident chain)
  2. Persisted to a consent registry (JSON)
  3. Enforced at runtime (all PII operations check consent first)

Consent scopes:
  - "admin_communication": WhatsApp/SMS/voice for booking and reminders
  - "medical_aid_check": Healthbridge eligibility verification
  - "voice_recording": Call recording for quality/training
  - "data_retention": Storing data beyond active relationship

Default scope for general concierge: "admin_communication"
"""

import json
import os
import time
from datetime import datetime, timezone

from audit_trail import (
    log_consent_given,
    log_consent_withdrawn,
    log_event,
)

CONSENT_DIR = os.path.expanduser("~/.hermes/compliance/consent/")
ALLOWED_SCOPES = frozenset({
    "admin_communication",
    "medical_aid_check",
    "voice_recording",
    "data_retention",
    "whatsapp_booking",
})


def _ensure_dir():
    os.makedirs(CONSENT_DIR, exist_ok=True)


def _patient_file(phone: str) -> str:
    """Deterministic filename for patient consent records."""
    from audit_trail import _patient_id
    pid = _patient_id(phone)
    return os.path.join(CONSENT_DIR, f"{pid}.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_consent(phone: str) -> dict:
    """Return the current consent record for a phone number.

    Returns a dict with:
      - scopes: dict of {scope_name: {granted_at, expires_at, status}}
      - withdrawal_history: list of past withdrawals
      - latest: the most recent scope granted (for quick check)
    """
    path = _patient_file(phone)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {
        "patient_id": None,
        "scopes": {},
        "withdrawal_history": [],
        "latest": None,
    }


def has_consent(phone: str, scope: str = "admin_communication") -> bool:
    """Check if a patient has active consent for a given scope."""
    record = get_consent(phone)
    scope_data = record.get("scopes", {}).get(scope)
    if not scope_data:
        return False
    if scope_data.get("status") != "active":
        return False
    expires = scope_data.get("expires_at")
    if expires and expires < _now():
        return False
    return True


def grant_consent(phone: str, scope: str = "admin_communication",
                  expires_in_days: int = 365, channel: str = "whatsapp") -> dict:
    """Record explicit consent from a patient.

    Args:
        phone: Patient's phone number
        scope: One of ALLOWED_SCOPES
        expires_in_days: Consent expiry (default 1 year, renew on each interaction)
        channel: How consent was obtained (whatsapp, web, voice, form)

    Returns the updated consent record.
    """
    if scope not in ALLOWED_SCOPES:
        raise ValueError(f"Unknown consent scope: {scope}. Use one of {ALLOWED_SCOPES}")

    _ensure_dir()
    from audit_trail import _patient_id
    pid = _patient_id(phone)
    record = get_consent(phone)
    record["patient_id"] = pid

    now = _now()
    expires = None
    if expires_in_days:
        from datetime import timedelta
        expires = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()

    record.setdefault("scopes", {})[scope] = {
        "granted_at": now,
        "expires_at": expires,
        "status": "active",
        "channel": channel,
        "last_renewed": now,
    }
    record["latest"] = {
        "scope": scope,
        "granted_at": now,
        "channel": channel,
    }

    with open(_patient_file(phone), "w") as f:
        json.dump(record, f, indent=2, default=str)

    # Audit trail
    log_consent_given(phone, scope=scope)
    return record


def withdraw_consent(phone: str, scope: str = None) -> dict:
    """Withdraw consent for a specific scope (or all scopes if None).

    Returns the updated consent record.
    """
    record = get_consent(phone)
    now = _now()

    withdrawal_entry = {
        "withdrawn_at": now,
        "scope": scope or "all",
    }
    record.setdefault("withdrawal_history", []).append(withdrawal_entry)

    if scope and scope in record.get("scopes", {}):
        record["scopes"][scope]["status"] = "withdrawn"
        record["scopes"][scope]["withdrawn_at"] = now
        log_consent_withdrawn(phone)
    elif scope is None:
        for s in record.get("scopes", {}):
            record["scopes"][s]["status"] = "withdrawn"
            record["scopes"][s]["withdrawn_at"] = now
        log_consent_withdrawn(phone)

    record["latest"] = None

    with open(_patient_file(phone), "w") as f:
        json.dump(record, f, indent=2, default=str)

    return record


def require_consent(phone: str, scope: str = "admin_communication") -> str:
    """Check consent and return a routing decision.

    Returns one of:
      - "proceed": Consent active, proceed with processing
      - "consent_needed": No consent record, must ask first
      - "withdrawn": Consent was explicitly withdrawn
      - "expired": Consent existed but expired
    """
    record = get_consent(phone)
    scope_data = record.get("scopes", {}).get(scope)

    if not scope_data:
        return "consent_needed"

    if scope_data.get("status") == "withdrawn":
        return "withdrawn"

    if scope_data.get("status") == "active":
        expires = scope_data.get("expires_at")
        if expires and expires < _now():
            return "expired"
        return "proceed"

    return "consent_needed"


def get_prompt(scope: str = "admin_communication") -> str:
    """Return the consent prompt text for a given scope.

    These are the exact prompts from the compliance whitepaper.
    """
    prompts = {
        "admin_communication": (
            "Before I help you with your booking inquiry, I need to let you know:\n"
            "- I'll securely process your contact details for appointment management\n"
            "- Your information is encrypted and stored on SA servers\n"
            "- This communication is for administrative purposes only\n"
            "- You can withdraw consent anytime by replying STOP\n\n"
            "Do you consent? Reply YES or NO."
        ),
        "medical_aid_check": (
            "To check your medical aid benefits, I need your consent:\n"
            "- I'll securely verify your eligibility via Healthbridge\n"
            "- Your medical aid number and scheme are checked, not stored\n"
            "- You can withdraw consent anytime\n\n"
            "Do you consent to this check? Reply YES or NO."
        ),
    }
    return prompts.get(scope, (
        "I need your consent to process your data for this request. "
        "Reply YES to proceed or NO to decline."
    ))


def list_active_consents() -> list:
    """List all active consent records (for compliance dashboard)."""
    _ensure_dir()
    results = []
    for fname in os.listdir(CONSENT_DIR):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(CONSENT_DIR, fname)
        with open(path) as f:
            record = json.load(f)
        active = {s: d for s, d in record.get("scopes", {}).items()
                  if d.get("status") == "active"}
        if active:
            results.append({
                "patient_id": record.get("patient_id"),
                "active_scopes": list(active.keys()),
                "granted_since": min(d.get("granted_at", "") for d in active.values()),
                "soonest_expiry": min(
                    (d.get("expires_at", "") for d in active.values() if d.get("expires_at")),
                    default="never"
                ),
            })
    return results


if __name__ == "__main__":
    # Self-test
    _ensure_dir()
    test_phone = "+27710000001"
    
    # No consent yet
    status = require_consent(test_phone)
    assert status == "consent_needed", f"Expected consent_needed got {status}"
    print(f"1. No consent check: {status}")
    
    # Grant consent
    grant_consent(test_phone, scope="admin_communication")
    status = require_consent(test_phone)
    assert status == "proceed", f"Expected proceed got {status}"
    print(f"2. After grant: {status}")
    
    # Has consent check
    assert has_consent(test_phone) == True
    print(f"3. has_consent(): True")
    
    # Withdraw
    withdraw_consent(test_phone)
    status = require_consent(test_phone)
    assert status == "withdrawn", f"Expected withdrawn got {status}"
    print(f"4. After withdraw: {status}")
    
    assert has_consent(test_phone) == False
    print(f"5. has_consent() after withdraw: False")
    
    # Active consents list
    active = list_active_consents()
    print(f"6. Active consents (expect 0): {len(active)}")
    
    print("\nConsent management self-test PASSED")
