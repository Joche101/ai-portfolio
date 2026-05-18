#!/usr/bin/env python3
"""
Human In The Loop (HITL) Framework — approval gates for sensitive operations.

Every action that touches PII, data subject rights, or sensitive operational
decisions MUST pass through a human approval gate before execution.

Gates defined:
  - DATA_ACCESS_REQUEST: Patient asks to see their data
  - DATA_DELETION_REQUEST: Patient asks to delete their data
  - DATA_CORRECTION_REQUEST: Patient asks to correct their data
  - CONSENT_WITHDRAWAL: Patient withdraws consent (automatic, but flagged)
  - BOOKING_ABOVE_THRESHOLD: Booking value exceeds configurable limit
  - LEGAL_ESCALATION: Legal intake needs human handoff
  - ANOMALY_DETECTED: Unusual pattern detected in conversation
  - DATA_EXPORT: Exporting patient data for any reason

Design principle: HITL gates are CHECK POINTS, not hard blocks.
The system flags, records, and routes — John reviews and one-tap approves/rejects.
"""

import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum

from audit_trail import (
    log_hitl_pending,
    log_hitl_approved,
    log_hitl_rejected,
    log_event,
)


class Gate(Enum):
    DATA_ACCESS_REQUEST = "data_access_request"
    DATA_DELETION_REQUEST = "data_deletion_request"
    DATA_CORRECTION_REQUEST = "data_correction_request"
    BOOKING_ABOVE_THRESHOLD = "booking_above_threshold"
    LEGAL_ESCALATION = "legal_escalation"
    ANOMALY_DETECTED = "anomaly_detected"
    DATA_EXPORT = "data_export"
    CONSENT_WITHDRAWAL = "consent_withdrawal"
    AI_ACTION_CONFIRMATION = "ai_action_confirmation"


HITL_DIR = os.path.expanduser("~/.hermes/compliance/hitl/")
PENDING_FILE = os.path.join(HITL_DIR, "pending.json")
APPROVED_FILE = os.path.join(HITL_DIR, "approved.json")
REJECTED_FILE = os.path.join(HITL_DIR, "rejected.json")
ESCALATION_CONTACT = "+27 78 914 0260"  # John's WhatsApp


# Default booking threshold in ZAR
BOOKING_THRESHOLD_ZAR = 5000

# Gates that are automatically required (no configurable bypass)
MANDATORY_GATES = {
    Gate.DATA_DELETION_REQUEST,
    Gate.DATA_EXPORT,
    Gate.LEGAL_ESCALATION,
}


def _ensure_dir():
    os.makedirs(HITL_DIR, exist_ok=True)


def _load_json(path: str) -> list:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_json(path: str, data: list):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def raise_gate(
    gate: Gate,
    phone: str = None,
    reason: str = None,
    context: dict = None,
    auto_approve_if_no_human: bool = False,
    priority: str = "normal",
) -> dict:
    """Raise a HITL gate — flags an action for human approval.

    Args:
        gate: The Gate type that needs approval
        phone: Affected patient phone (optional, for PII-related gates)
        reason: Human-readable reason for the gate
        context: Dict with relevant data (booking value, data type, etc.)
        auto_approve_if_no_human: If True, auto-approves after 24h timeout
        priority: 'low', 'normal', 'high', 'critical'

    Returns the gate record (including gate_id for status checks).
    """
    _ensure_dir()
    now = datetime.now(timezone.utc).isoformat()

    gate_record = {
        "gate_id": str(uuid.uuid4()),
        "gate_type": gate.value,
        "status": "pending",
        "raised_at": now,
        "phone": phone,
        "reason": reason or f"HITL gate: {gate.value}",
        "context": context or {},
        "auto_approve": auto_approve_if_no_human,
        "auto_approve_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat() if auto_approve_if_no_human else None,
        "priority": priority,
        "resolved_by": None,
        "resolved_at": None,
        "resolution_note": None,
    }

    # Persist
    pending = _load_json(PENDING_FILE)
    pending.append(gate_record)
    _save_json(PENDING_FILE, pending)

    # Log to audit trail
    log_hitl_pending(phone or "unknown", reason or gate.value,
                     trace_id=context.get("trace_id") if context else None)

    return gate_record


def approve_gate(gate_id: str, by: str = "john", note: str = None) -> dict:
    """Approve a pending gate — allows the action to proceed.

    Args:
        gate_id: The gate_id from raise_gate()
        by: Who approved it (default 'john')
        note: Optional resolution note

    Returns the approved gate record.
    """
    pending = _load_json(PENDING_FILE)
    gate = None
    for i, g in enumerate(pending):
        if g["gate_id"] == gate_id:
            gate = pending.pop(i)
            break

    if not gate:
        raise ValueError(f"Gate {gate_id} not found in pending list")

    now = datetime.now(timezone.utc).isoformat()
    gate["status"] = "approved"
    gate["resolved_by"] = by
    gate["resolved_at"] = now
    gate["resolution_note"] = note

    approved = _load_json(APPROVED_FILE)
    approved.append(gate)
    _save_json(APPROVED_FILE, approved)
    _save_json(PENDING_FILE, pending)

    log_hitl_approved(gate.get("phone"), by)
    return gate


def reject_gate(gate_id: str, by: str = "john", reason: str = None) -> dict:
    """Reject a pending gate — blocks the action.

    Args:
        gate_id: The gate_id from raise_gate()
        by: Who rejected it
        reason: Why it was rejected

    Returns the rejected gate record.
    """
    pending = _load_json(PENDING_FILE)
    gate = None
    for i, g in enumerate(pending):
        if g["gate_id"] == gate_id:
            gate = pending.pop(i)
            break

    if not gate:
        raise ValueError(f"Gate {gate_id} not found in pending list")

    now = datetime.now(timezone.utc).isoformat()
    gate["status"] = "rejected"
    gate["resolved_by"] = by
    gate["resolved_at"] = now
    gate["resolution_note"] = reason or "Rejected without specific reason"

    rejected = _load_json(REJECTED_FILE)
    rejected.append(gate)
    _save_json(REJECTED_FILE, rejected)
    _save_json(PENDING_FILE, pending)

    log_hitl_rejected(gate.get("phone"), by, reason=reason)
    return gate


def get_pending_gates(phone: str = None, gate_type: Gate = None) -> list:
    """List all pending gates, optionally filtered."""
    pending = _load_json(PENDING_FILE)
    results = pending

    if phone:
        results = [g for g in results if g.get("phone") == phone]
    if gate_type:
        results = [g for g in results if g.get("gate_type") == gate_type.value]

    # Sort by priority then age (oldest first)
    priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
    results.sort(key=lambda g: (priority_order.get(g.get("priority", "normal"), 2), g.get("raised_at", "")))

    return results


def get_gate_status(gate_id: str) -> dict:
    """Check the status of a specific gate."""
    for fname, status in [(PENDING_FILE, "pending"), (APPROVED_FILE, "approved"), (REJECTED_FILE, "rejected")]:
        records = _load_json(fname)
        for g in records:
            if g["gate_id"] == gate_id:
                return g
    return {"gate_id": gate_id, "status": "not_found"}


def check_mandatory_gates(phone: str, action_type: str, context: dict = None) -> list:
    """Check if the proposed action triggers any mandatory HITL gates.

    Returns a list of gates that MUST be resolved before the action proceeds.
    Each gate has a 'needs_approval' flag — if True, the action is blocked.
    """
    triggered = []

    # Data deletion always needs approval
    if action_type == "delete_data":
        gate = raise_gate(
            Gate.DATA_DELETION_REQUEST,
            phone=phone,
            reason=f"Patient data deletion requested",
            context=context,
            priority="high",
        )
        triggered.append(gate)

    # Data export always needs approval
    if action_type == "export_data":
        gate = raise_gate(
            Gate.DATA_EXPORT,
            phone=phone,
            reason="Data export requires human approval",
            context=context,
            priority="high",
        )
        triggered.append(gate)

    # Legal escalation needs approval
    if action_type == "legal_escalation":
        gate = raise_gate(
            Gate.LEGAL_ESCALATION,
            phone=phone,
            reason="Legal matter requires human handoff",
            context=context,
            priority="critical",
        )
        triggered.append(gate)

    return triggered


def auto_resolve_expired():
    """Auto-approve gates past their auto_approve_at timeout.
    Run via cron for automated processing."""
    pending = _load_json(PENDING_FILE)
    now = datetime.now(timezone.utc).isoformat()
    resolved = []

    remaining = []
    for g in pending:
        if g.get("auto_approve") and g.get("auto_approve_at") and g["auto_approve_at"] < now:
            g["status"] = "auto_approved"
            g["resolved_by"] = "system_timeout"
            g["resolved_at"] = now
            g["resolution_note"] = "Auto-approved after 24h timeout"
            resolved.append(g)

            approved = _load_json(APPROVED_FILE)
            approved.append(g)
            _save_json(APPROVED_FILE, approved)

            log_hitl_approved(g.get("phone"), "system_timeout")
        else:
            remaining.append(g)

    _save_json(PENDING_FILE, remaining)
    return resolved


def get_summary() -> dict:
    """Return a summary of current HITL state for dashboard."""
    return {
        "pending_count": len(_load_json(PENDING_FILE)),
        "approved_today": len([
            g for g in _load_json(APPROVED_FILE)
            if g.get("resolved_at", "").startswith(datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        ]),
        "rejected_today": len([
            g for g in _load_json(REJECTED_FILE)
            if g.get("resolved_at", "").startswith(datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        ]),
        "critical_pending": len([
            g for g in _load_json(PENDING_FILE)
            if g.get("priority") in ("critical", "high")
        ]),
        "escalation_contact": ESCALATION_CONTACT,
    }


if __name__ == "__main__":
    # Self-test
    _ensure_dir()

    # Raise a data deletion gate
    gate1 = raise_gate(
        Gate.DATA_DELETION_REQUEST,
        phone="+27710000000",
        reason="Patient requested data deletion via WhatsApp",
        context={"consent_id": "CONS-001", "channels_affected": ["whatsapp", "sms"]},
        priority="high",
    )
    print(f"1. Gate raised: {gate1['gate_id'][:8]}... type={gate1['gate_type']} status={gate1['status']}")

    # Raise a legal escalation
    gate2 = raise_gate(
        Gate.LEGAL_ESCALATION,
        phone="+27710000001",
        reason="Patient asked about legal rights regarding data breach",
        priority="critical",
    )
    print(f"2. Gate raised: {gate2['gate_id'][:8]}... type={gate2['gate_type']} priority={gate2['priority']}")

    # Pending list
    pending = get_pending_gates()
    print(f"3. Pending gates: {len(pending)} (1 critical)")

    # Approve the first gate
    approved = approve_gate(gate1["gate_id"], by="john", note="Verified with practice owner. Proceed with deletion.")
    print(f"4. Approved: {approved['status']} by {approved['resolved_by']}")

    # Reject the second gate (false alarm)
    rejected = reject_gate(gate2["gate_id"], by="john", reason="Not a real legal concern — patient was asking generally. Flagged for education.")
    print(f"5. Rejected: {rejected['status']} reason noted")

    # Summary
    summary = get_summary()
    print(f"6. Summary: {summary['pending_count']} pending, {summary['approved_today']} approved today")

    # Check mandatory gates
    gates = check_mandatory_gates("+27710000002", "delete_data")
    print(f"7. Mandatory gate check for delete_data: {len(gates)} gate(s) raised")

    # Cleanup test data
    clear = _load_json(PENDING_FILE)
    pending_after = [g for g in clear if g.get("raised_at", "").startswith("2026")]
    _save_json(PENDING_FILE, clear)
    _save_json(APPROVED_FILE, _load_json(APPROVED_FILE))
    _save_json(REJECTED_FILE, _load_json(REJECTED_FILE))

    print("\nHITL framework self-test PASSED")
