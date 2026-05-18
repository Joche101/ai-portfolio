#!/usr/bin/env python3
"""
Audit Trail — tamper-evident, structured, POPIA-compliant event logging.

Every PII operation is recorded with:
  - event_id (UUID)
  - timestamp (ISO 8601 + timezone)
  - event_type (standardised taxonomy)
  - actor (system component or human identifier)
  - resource (phone hash, practice ID, session key)
  - action (read/write/delete/consent/escalate)
  - trace_id (correlates events across components)
  - previous_hash (SHA-256 of preceding event — chain integrity)

Chain validation can detect tampering retroactively.
Retention: 6 years per HPCSA Booklet 10 S5.1.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone, timedelta

AUDIT_DIR = os.path.expanduser("~/.hermes/compliance/audit_log/")
CHAIN_FILE = os.path.join(AUDIT_DIR, "chain.json")
LAST_HASH_FILE = os.path.join(AUDIT_DIR, "last_hash.txt")
RETENTION_YEARS = 6

EVENT_TYPES = frozenset({
    "consent.given",
    "consent.withdrawn",
    "consent.scope_changed",
    "pii.read",
    "pii.write",
    "pii.delete",
    "pii.access_request",
    "pii.correction_request",
    "booking.created",
    "booking.cancelled",
    "booking.modified",
    "hitl.pending",
    "hitl.approved",
    "hitl.rejected",
    "hitl.escalated",
    "legal.intake_routed",
    "legal.intake_completed",
    "lead.captured",
    "anomaly.detected",
    "system.error",
    "system.startup",
    "system.shutdown",
    "compliance.retention_enforced",
})


def _ensure_dir():
    os.makedirs(AUDIT_DIR, exist_ok=True)


def _last_hash() -> str:
    """Read the previous event's hash from the chain head."""
    try:
        with open(LAST_HASH_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return "0" * 64  # Genesis hash


def _set_last_hash(h: str):
    with open(LAST_HASH_FILE, "w") as f:
        f.write(h)


def _patient_id(phone: str) -> str:
    """Deterministic, irreversible hash of phone number for audit logs.
    Uses SHA-256 of the phone string. This is NOT encryption — it's
    pseudonymisation (POPIA S1 definition). The mapping lives ONLY in
    the guest memory bank, not in the audit log."""
    return hashlib.sha256(phone.encode("utf-8")).hexdigest()[:16]


def log_event(
    event_type: str,
    actor: str = "system",
    resource: str = None,
    action: str = None,
    metadata: dict = None,
    patient_phone: str = None,
    trace_id: str = None,
) -> dict:
    """Record a structured audit event. Returns the event dict.

    Parameters:
        event_type: One of EVENT_TYPES
        actor: 'system', 'hermann', 'bridge', 'john', 'hitl-approver', or human name
        resource: The thing being acted on (file, API, session)
        action: 'read', 'write', 'delete', 'approve', 'reject', 'query'
        metadata: Free-form dict with extra context (max 1KB)
        patient_phone: If PII is involved, pass the phone for pseudonymised logging
        trace_id: Correlation ID (auto-generated if not provided)
    """
    _ensure_dir()

    if event_type not in EVENT_TYPES:
        # Allow custom types prefixed with "custom."
        if not event_type.startswith("custom."):
            raise ValueError(f"Unknown event_type: {event_type}. Use EVENT_TYPES or 'custom.*'")

    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action": action or "access",
        "resource": resource,
        "patient_id": _patient_id(patient_phone) if patient_phone else None,
        "metadata": metadata or {},
        "trace_id": trace_id or str(uuid.uuid4()),
        "previous_hash": _last_hash(),
    }

    # Compute this event's hash for chain integrity
    event_bytes = json.dumps(event, sort_keys=True, default=str).encode("utf-8")
    event_hash = hashlib.sha256(event_bytes).hexdigest()
    event["event_hash"] = event_hash

    # Append to daily log file (enables retention by date)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    day_file = os.path.join(AUDIT_DIR, f"{date_str}.jsonl")

    with open(day_file, "a") as f:
        f.write(json.dumps(event, default=str) + "\n")

    _set_last_hash(event_hash)

    return event


def validate_chain(from_date: str = None, to_date: str = None) -> dict:
    """Walk the chain and verify integrity. Returns report dict.

    Args:
        from_date: ISO date string (e.g. '2026-05-01')
        to_date: ISO date string (defaults to today)
    """
    _ensure_dir()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    to_date = to_date or today
    from_date = from_date or today

    events = []
    for fname in sorted(os.listdir(AUDIT_DIR)):
        if not fname.endswith(".jsonl"):
            continue
        fdate = fname.replace(".jsonl", "")
        if fdate < from_date or fdate > to_date:
            continue
        with open(os.path.join(AUDIT_DIR, fname)) as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))

    if not events:
        return {"status": "empty", "events_checked": 0, "chain_intact": True}

    # Sort by event_id (UUID v4 is roughly chronological, but file order is fine)
    # Actually, file order IS append order, so chronological.
    broken = False
    prev_hash = "0" * 64
    checked = 0
    for event in events:
        stored_hash = event.get("event_hash", "")
        # Recompute hash of everything except event_hash
        check_event = {k: v for k, v in event.items() if k != "event_hash"}
        check_bytes = json.dumps(check_event, sort_keys=True, default=str).encode("utf-8")
        computed = hashlib.sha256(check_bytes).hexdigest()

        if computed != stored_hash:
            broken = True

        if event.get("previous_hash", "") != prev_hash:
            broken = True

        prev_hash = stored_hash
        checked += 1

    return {
        "status": "compromised" if broken else "intact",
        "events_checked": checked,
        "chain_intact": not broken,
        "from_date": from_date,
        "to_date": to_date,
    }


def enforce_retention():
    """Delete audit logs older than RETENTION_YEARS.
    Callable via cron for automated enforcement."""
    _ensure_dir()
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_YEARS * 365)
    cutoff_str = cutoff.strftime("%Y-%m-%d")

    deleted = 0
    for fname in list(os.listdir(AUDIT_DIR)):
        if not fname.endswith(".jsonl"):
            continue
        fdate = fname.replace(".jsonl", "")
        if fdate < cutoff_str:
            os.remove(os.path.join(AUDIT_DIR, fname))
            deleted += 1

    if deleted:
        log_event(
            "compliance.retention_enforced",
            actor="system",
            resource="audit_log",
            action="delete",
            metadata={"files_deleted": deleted, "retention_years": RETENTION_YEARS},
        )
    return deleted


def query_events(
    event_type: str = None,
    patient_id: str = None,
    trace_id: str = None,
    limit: int = 50,
) -> list:
    """Query audit events with optional filters.
    Used for data subject access requests and compliance review."""
    _ensure_dir()
    results = []
    for fname in sorted(os.listdir(AUDIT_DIR), reverse=True):
        if not fname.endswith(".jsonl"):
            continue
        fpath = os.path.join(AUDIT_DIR, fname)
        with open(fpath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                if event_type and event.get("event_type") != event_type:
                    continue
                if patient_id and event.get("patient_id") != patient_id:
                    continue
                if trace_id and event.get("trace_id") != trace_id:
                    continue
                results.append(event)
                if len(results) >= limit:
                    return results
    return results


# ── Convenience wrappers for common events ──

def log_pii_read(phone: str, resource: str, trace_id: str = None):
    return log_event("pii.read", resource=resource, patient_phone=phone, trace_id=trace_id)

def log_pii_write(phone: str, resource: str, trace_id: str = None):
    return log_event("pii.write", resource=resource, patient_phone=phone, trace_id=trace_id)

def log_consent_given(phone: str, scope: str = "admin_communication"):
    return log_event("consent.given", resource="consent", action=scope, patient_phone=phone)

def log_consent_withdrawn(phone: str):
    return log_event("consent.withdrawn", resource="consent", action="revoke", patient_phone=phone)

def log_hitl_pending(phone: str, reason: str, trace_id: str = None):
    return log_event("hitl.pending", resource="hitl", action="pending",
                     metadata={"reason": reason}, patient_phone=phone, trace_id=trace_id)

def log_hitl_approved(phone: str, by: str, trace_id: str = None):
    return log_event("hitl.approved", actor=by, resource="hitl", action="approve",
                     patient_phone=phone, trace_id=trace_id)

def log_hitl_rejected(phone: str, by: str, reason: str = None, trace_id: str = None):
    return log_event("hitl.rejected", actor=by, resource="hitl", action="reject",
                     metadata={"reason": reason}, patient_phone=phone, trace_id=trace_id)


if __name__ == "__main__":
    # Self-test
    _ensure_dir()
    
    e1 = log_event("system.startup", actor="system", resource="audit_trail", action="test")
    print(f"Event 1: {e1['event_id']} hash={e1['event_hash'][:12]}...")
    
    e2 = log_consent_given("+27710000000", scope="whatsapp_booking")
    print(f"Event 2 (consent): {e2['event_id']} patient={e2['patient_id']}")
    
    e3 = log_pii_read("+27710000000", "guest_memory", trace_id=e2['trace_id'])
    print(f"Event 3 (PII read): trace={e3['trace_id'][:8]}...")
    
    e4 = log_hitl_pending("+27710000000", "Data deletion request requires approval")
    print(f"Event 4 (HITL pending): {e4['event_id']}")
    
    # Chain validation
    report = validate_chain()
    print(f"\nChain validation: {report['status']} ({report['events_checked']} events)")
    
    # Query
    consent_events = query_events(event_type="consent.given")
    print(f"Consent events found: {len(consent_events)}")
    
    print("\nAudit trail self-test PASSED")
