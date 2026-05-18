import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ── Compliance & Data Protection ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COMPLIANCE_DIR = os.path.join(os.path.expanduser("~"), ".hermes", "compliance")
sys.path.insert(0, COMPLIANCE_DIR)

try:
    from audit_trail import log_event, log_pii_read, log_pii_write
    COMPLIANCE_AUDIT = True
except ImportError:
    COMPLIANCE_AUDIT = False

try:
    from consent import require_consent, get_prompt, grant_consent, has_consent
    COMPLIANCE_CONSENT = True
except ImportError:
    COMPLIANCE_CONSENT = False

try:
    from hitl import raise_gate, Gate as HITLGate
    COMPLIANCE_HITL = True
except ImportError:
    COMPLIANCE_HITL = False


BASE_URL = "https://www.aithatbooks.co.za/hermann-chat.php"
BRIDGE_KEY = "h3rm3s-br1dg3-2026"
POLL_INTERVAL_SECONDS = 3
CLEANUP_INTERVAL_SECONDS = 60
HERMES_URL = "http://localhost:8642/v1/chat/completions"
HERMES_MODEL = "hermes-agent"
HTTP_TIMEOUT_SECONDS = 60

SYSTEM_PROMPT_JOHN = (
    "You are John Bianchina's personal AI assistant. You speak directly, concisely. "
    "Under 3 sentences unless John asks for detail. "
    "Key facts: AI Readiness Audit R7,950. Site: aithatbooks.co.za. "
    "Contact: john@aithatbooks.co.za, +27 78 914 0260. "
    "ABSOLUTE RULE: You do NOT give legal advice. Ever. Not to anyone. "
    "If John asks about legal matters, you ONLY say: "
    "'I can connect you with the right specialist for a consultation. Would you like me to arrange that?' "
    "No exceptions. No case law. No analysis. No legal commentary of any kind."
)

SYSTEM_PROMPT_OUTSIDER = (
    "You are the Legal Intake AI at AI That Books — a professional client intake concierge "
    "demonstrating AI-powered legal triage for law firms. "
    "You are speaking to a potential law firm client evaluating the system. "
    "CRITICAL RULES:\n"
    "1. NEVER give legal advice. Not a word. Not a hint.\n"
    "2. NEVER quote prices for legal services, lawyer fees, or retainers.\n"
    "3. NEVER predict outcomes, timelines, or case viability.\n"
    "4. NEVER name specific lawyers, firms, or courts.\n"
    "5. NEVER analyze a legal situation — even hypothetically.\n"
    "6. NEVER use the user's name unless they've told you what it is.\n"
    "Your job: Ask 1-2 smart qualifying questions about their matter type "
    "and urgency, then route them to book a consultation. "
    "Be warm, professional, efficient. Under 2 sentences unless qualifying.\n"
    "Example flow:\n"
    "User: I need advice on a merger\n"
    "You: Understood — M&A can be time-sensitive. Is this a proposed transaction "
    "already in motion, or early-stage exploration? And which industry?\n"
    "User: Employment dispute\n"
    "You: I want to route you correctly. Are you the employer dealing with a staff "
    "matter, or an employee with a workplace concern?\n"
    "Then, after they reply: 'Good — I have enough to route this to the right "
    "specialist. Would you like me to arrange a consultation?'\n"
    "NEVER go beyond qualifying questions. NEVER answer 'how much does X cost' "
    "or 'what are my rights' or 'is this legal'. Those are legal questions — "
    "you simply say: 'That's exactly the kind of question a consultation will "
    "clarify. Would you like me to arrange one?'"
)

# Keywords that trigger immediate legal-intake routing — before Hermes even sees the message
LEGAL_KEYWORDS = [
    "sue ", "lawsuit", "lawyer", "attorney", "litigation",
    "divorce", "contract dispute", "settlement", "court",
    "my rights", "is it legal", "claim damages", 
    "personal injury", "defamation", "legal opinion",
    "legal assistance", "legal issue", "represent me",
    "suing", "being sued", "breach of contract",
    "legal action", "notary", "power of attorney",
    "will and testament", "estate planning",
    "arbitration", "mediation", "settlement agreement",
    "cease and desist", "intellectual property",
    "trademark", "copyright", "patent",
    "legal document", "law firm", "legal consultation",
    "conveyancing", "notarial", "family law",
    "criminal", "labour law", "employment law",
    # Common misspellings that users actually type
    "laywer", "lawer", "lwayer", "atourney", "attorny",
    "divorse", "divource", "divoce", "divors",
    "litagation", "litagion", "arbitration", "arbitration",
    "sueing", "law suite", "law suit", "lawsute",
    "legel", "leagal", "ligal", "legle",
    "atourney", "attourney", "attorny", "atorney",
    "constitution", "constitusion", "settlment",
    "medation", "mediaton", "notery", "notry",
    "criminal law", "crimnal", "crminal",
    # Numbers + legal: someone asking about lawyer/legal costs
    "lawyer cost", "attorney cost", "lawyer fee",
    "attorney fee", "legal fee", "how much lawyer",
    "how much attorney", "cost of lawyer", "cost of attorney",
    "legal cost", "legal pricing", "legal rate"
]

WEBSITE_CONCIERGE_PROMPT = (
    "You are an AI concierge trained on a specific website. "
    "Answer questions using ONLY the website content provided in the user message. "
    "If the answer is not in the content, say exactly: "
    "'That question goes beyond what's published on the website. Once I'm trained "
    "on your internal operations, compliance, and company policy, I can answer that. "
    "Would you like me to connect you with a specialist who can help?' "
    "Keep answers under 3 sentences. Be direct and helpful. Never make up information."
)

AUDIT_ANALYSIS_PROMPT = (
    "You are an AI website auditor. Your job is to analyze website data and produce "
    "specific, actionable findings — not generic advice. "
    "You MUST output VALID JSON only. No markdown, no explanation outside the JSON. "
    "JSON structure: "
    '{"headline": "one punchy insight (max 15 words)", '
    '"problems": [{"finding": "specific problem found", "cost": "what this costs the business", "severity": "critical|warning|insight"}, ...], '
    '"score": number 0-100, '
    '"topGap": "the #1 missing element", '
    '"fixes": ["specific fix 1", "specific fix 2", "specific fix 3"]} '
    "Be ruthless. Every finding must reference actual data from the input. "
    "If they have no WhatsApp, say exactly how many after-hours inquiries that loses. "
    "If their content is thin, say what topics are missing. "
    "If they have no booking CTA, calculate the conversion loss. "
    "Use South African context (ZAR, local competitors, SA consumer behavior)."
)
LEGAL_INTAKE_SYSTEM_PROMPT = (
    "You are the Legal Intake AI at AI That Books — demonstrating AI-powered client triage "
    "for law firms. You are speaking to someone who has asked about a legal matter. "
    "ABSOLUTE RULES — these override everything:\n"
    "- NEVER give legal advice. Not one word.\n"
    "- NEVER quote lawyer fees, retainer costs, or legal pricing.\n"
    "- NEVER predict outcomes, timelines, or case strength.\n"
    "- NEVER analyze anyone's legal situation — even hypothetically.\n"
    "- NEVER name specific lawyers, firms, judges, or courts.\n"
    "- NEVER use the person's name unless they told you.\n"
    "- NEVER say 'I can help with' or 'I can assist with' legal matters.\n"
    "YOUR ONLY ROLE: Ask 1-2 short qualifying questions (practice area, urgency), "
    "then route to consultation. Maximum 2 exchanges before routing.\n"
    "If they ask for advice, prices, predictions, or legal information: "
    "'That's exactly what a consultation will clarify. Would you like me to arrange one?'\n"
    "Under 2 sentences always. No exceptions. Be warm but professional."
)


LOG_FILE = "/var/log/hermes-bridge.log"
LEGAL_SESSIONS_FILE = "/tmp/hermes-legal-sessions.json"

# In-memory cache of sessions flagged as legal intake
_legal_sessions = {}

def load_legal_sessions():
    """Load persistent legal-session flags from disk."""
    global _legal_sessions
    try:
        with open(LEGAL_SESSIONS_FILE, "r") as f:
            _legal_sessions = json.load(f)
    except Exception:
        _legal_sessions = {}

def save_legal_sessions():
    """Persist legal-session flags to disk."""
    try:
        with open(LEGAL_SESSIONS_FILE, "w") as f:
            json.dump(_legal_sessions, f)
    except Exception:
        pass

def is_legal_session(session_id):
    """Check if this session was already flagged as legal intake."""
    if not session_id:
        return False
    return _legal_sessions.get(session_id, False)

def flag_legal_session(session_id):
    """Flag this session as legal intake — all future messages route to intake."""
    if session_id:
        _legal_sessions[session_id] = True
        save_legal_sessions()

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def log(message):
    line = "[%s] %s" % (timestamp(), message)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line)
    sys.stdout.flush()


def build_url(action, params=None):
    query = {"action": action, "key": BRIDGE_KEY}
    if params:
        query.update(params)
    return BASE_URL + "?" + urllib.parse.urlencode(query)


def parse_json_bytes(raw):
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def http_get_json(url):
    try:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "hermann-bridge/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return parse_json_bytes(response.read())
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        log("GET failed: HTTP %s for %s %s" % (exc.code, url, body[:300]))
    except urllib.error.URLError as exc:
        log("GET failed: %s for %s" % (exc.reason, url))
    except Exception as exc:
        log("GET failed: %s for %s" % (exc, url))
    return None


def http_post_form_json(url, data):
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    try:
        request = urllib.request.Request(
            url,
            data=encoded,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "hermann-bridge/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return parse_json_bytes(response.read())
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        log("POST failed: HTTP %s for %s %s" % (exc.code, url, body[:300]))
    except urllib.error.URLError as exc:
        log("POST failed: %s for %s" % (exc.reason, url))
    except Exception as exc:
        log("POST failed: %s for %s" % (exc, url))
    return None


def http_post_json(url, payload):
    encoded = json.dumps(payload).encode("utf-8")
    try:
        request = urllib.request.Request(
            url,
            data=encoded,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "hermann-bridge/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return parse_json_bytes(response.read())
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        log("Hermes API failed: HTTP %s %s" % (exc.code, body[:300]))
    except urllib.error.URLError as exc:
        log("Hermes API failed: %s" % (exc.reason,))
    except Exception as exc:
        log("Hermes API failed: %s" % (exc,))
    return None


def extract_messages(poll_result):
    """Parse poll response: {'pending': {'msg_id': {'message':'...','status':'pending',is_john:bool}}}"""
    if poll_result is None:
        return []
    pending = poll_result.get("pending", {})
    if not isinstance(pending, dict):
        return []
    result = []
    for msg_id, msg_data in pending.items():
        if isinstance(msg_data, dict):
            result.append({
                "id": msg_id,
                "message": msg_data.get("message", ""),
                "status": msg_data.get("status", ""),
                "is_john": msg_data.get("is_john", False)
            })
    return result


def message_id(message):
    if not isinstance(message, dict):
        return None
    for key in ("id", "message_id", "messageId"):
        value = message.get(key)
        if value is not None:
            return str(value)
    return None


def message_text(message):
    if isinstance(message, str):
        return message
    if not isinstance(message, dict):
        return ""
    for key in ("message", "text", "content", "prompt", "question"):
        value = message.get(key)
        if value is not None:
            return str(value)
    return ""


def ask_hermes(user_message, system_prompt, max_tokens=150):
    payload = {
        "model": HERMES_MODEL,
        "max_tokens": max_tokens, "temperature": 0.7, "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
    }
    result = http_post_json(HERMES_URL, payload)
    if not isinstance(result, dict):
        return None
    try:
        return result["choices"][0]["message"]["content"]
    except Exception:
        log("Hermes API response did not contain choices[0].message.content")
        return None


def post_response(msg_id, answer):
    url = build_url("respond", {"id": msg_id})
    result = http_post_form_json(url, {"response": answer})
    
    # Also write to response-store.php for fast browser retrieval
    try:
        store_url = "https://www.aithatbooks.co.za/response-store.php"
        store_result = http_post_form_json(store_url, {"id": msg_id, "response": answer, "key": BRIDGE_KEY})
        if store_result is None:
            log("WARN: response-store write failed for msg %s" % (msg_id,))
        else:
            log("Response-store write OK for msg %s" % (msg_id,))
    except Exception as exc:
        log("WARN: response-store exception for msg %s: %s" % (msg_id, exc))
    
    return result


def cleanup():
    url = build_url("cleanup")
    result = http_get_json(url)
    if result is None:
        log("Cleanup attempted")
    else:
        log("Cleanup completed")


def detect_legal(text):
    """Return True if the message asks about anything legal — route to booking immediately."""
    # Strip PHP proxy's [SYSTEM: ...] prefix to isolate user's actual message
    clean = text
    if clean.startswith("[SYSTEM:"):
        idx = clean.find("]")
        if idx != -1:
            clean = clean[idx+1:].strip()
    
    lower = clean.lower()
    
    # Strong legal keywords — unambiguous
    for keyword in LEGAL_KEYWORDS:
        if keyword in lower:
            log("LEGAL DETECT: found keyword '%s'" % keyword)
            return True
    
    # Catch-all: phrases containing "legal" that wouldn't be in system prompt
    # These check user's actual message, not the SYSTEM prefix
    legal_phrases = [
        "legal advice", "legal help", "legal question",
        "legal matter", "give legal", "get legal",
        "need legal", "want legal", "legal case",
        "legal problem", "legal situation", "legal issue",
        "tell me about legal", "know about legal",
        "my legal", "any legal", "provide legal",
        "offer legal", "doing legal"
    ]
    for phrase in legal_phrases:
        if phrase in lower:
            log("LEGAL DETECT: found phrase '%s'" % phrase)
            return True
    
    return False


def process_pending_messages():
    poll_url = build_url("poll")
    poll_result = http_get_json(poll_url)
    messages = extract_messages(poll_result)
    if not messages:
        return

    for message in messages:
        msg_id = message_id(message)
        text = message_text(message)
        is_john = message.get("is_john", False)
        if not msg_id:
            continue
        if not text:
            continue

        # === /demo trigger — must happen BEFORE legal checks ===
        if text.startswith("/demo"):
            text = text[5:].strip()
            is_john = False
            log("DEMO MODE forced for msg %s" % (msg_id,))
            if not text:
                text = "Hello"

        # === LEAD FORM SUBMISSION — must happen BEFORE legal checks ===
        # Lead messages contain structured data; the word "legal" may appear as an industry type
        # Use substring match — PHP proxy may prepend [SYSTEM:] prefix
        if "LEAD: Full AI Readiness Audit" in text or text.startswith("LEAD:"):
            # Strip any [SYSTEM:...] prefix for clean logging
            clean_text = text
            if clean_text.startswith("[SYSTEM:"):
                idx = clean_text.find("]")
                if idx != -1:
                    clean_text = clean_text[idx+1:].strip()
            log("NEW LEAD: %s" % (clean_text.replace('\n', ' | ')[:300]))
            try:
                with open("/root/leads.txt", "a") as f:
                    f.write("\n=== %s ===\n" % (time.strftime("%Y-%m-%d %H:%M:%S")))
                    f.write(clean_text + "\n")
            except Exception:
                pass
            post_response(msg_id, "RECEIVED: Your audit request has been logged. John will review your site within 24 hours.")
            log("Lead saved for msg %s" % (msg_id,))
            continue

        # === CONCIERGE DEMO: website-trained AI ===
        # Chat page sends full prompt with website content — use minimal system prompt
        is_concierge_demo = ("website AI concierge" in text) or ("trained ONLY on the following website content" in text)

        # === PRE-FILTER: Legal questions never reach Hermes ===
        # Check if this session was previously flagged as legal intake
        session_key = "john" if is_john else "outsider"
        
        if is_legal_session(session_key):
            log("LEGAL SESSION LOCK msg %s — routing to legal intake" % (msg_id,))
            answer = ask_hermes(text, LEGAL_INTAKE_SYSTEM_PROMPT)
            if answer is None:
                log("No Hermes response for legal msg %s; will retry" % (msg_id,))
                continue
            result = post_response(msg_id, answer)
            if result is None:
                log("Failed to post legal-intake response for msg %s" % (msg_id,))
            else:
                log("Posted legal-intake response for msg %s" % (msg_id,))
            continue

        if detect_legal(text):
            log("LEGAL BLOCK msg %s — routing to legal intake" % (msg_id,))
            flag_legal_session(session_key)
            answer = ask_hermes(text, LEGAL_INTAKE_SYSTEM_PROMPT)
            if answer is None:
                log("No Hermes response for legal msg %s; will retry" % (msg_id,))
                continue
            result = post_response(msg_id, answer)
            if result is None:
                log("Failed to post legal-intake response for msg %s" % (msg_id,))
            else:
                log("Posted legal-intake response for msg %s" % (msg_id,))
            continue

        # === AUDIT TRAIL: log message receipt ===
        if COMPLIANCE_AUDIT:
            try:
                log_event("pii.read", actor="bridge", resource="chat_message",
                          action="receive", patient_phone=None if is_john else text[:40],
                          metadata={"msg_id": msg_id, "route": who if 'who' in dir() else "pending"})
            except Exception:
                pass

        # === CONSENT CHECK: non-John messages ===
        # If this user hasn't consented, add a consent prompt
        needs_consent_prompt = False
        if COMPLIANCE_CONSENT and not is_john and "AUDIT_ANALYSIS" not in text:
            try:
                consent_status = require_consent(text[:20] if len(text) > 20 else text)
                if consent_status == "consent_needed" and len(text) < 50:
                    # If the message is short/greeting, it's probably a first contact
                    # Flag for consent prompt on response
                    needs_consent_prompt = True
            except Exception:
                pass

        # === HITL GATE: Legal escalation ===
        if COMPLIANCE_HITL and session_key and is_legal_session(session_key):
            try:
                # Raise a HITL gate for legal matters — John needs to be aware
                raise_gate(
                    HITLGate.LEGAL_ESCALATION,
                    phone=text[:20],
                    reason="Legal intake session active — human should review",
                    priority="critical" if "urgent" in text.lower() else "normal",
                )
            except Exception:
                pass
        is_audit_analysis = "AUDIT_ANALYSIS" in text

        # Choose persona
        if is_audit_analysis:
            system_prompt = AUDIT_ANALYSIS_PROMPT
            who = "audit-analysis"
            tokens = 400
        elif is_concierge_demo:
            system_prompt = WEBSITE_CONCIERGE_PROMPT
            who = "concierge-demo"
            tokens = 150
        else:
            system_prompt = SYSTEM_PROMPT_JOHN if is_john else SYSTEM_PROMPT_OUTSIDER
            who = "John" if is_john else "outsider"
            tokens = 150
        log("Sending msg %s to Hermes as %s" % (msg_id, who))

        answer = ask_hermes(text, system_prompt, max_tokens=tokens)
        if answer is None:
            log("No Hermes response for msg %s; will retry later" % (msg_id,))
            continue

        result = post_response(msg_id, answer)
        if result is None:
            log("Failed to post response for msg %s; will retry later" % (msg_id,))
        else:
            log("Posted response for msg %s" % (msg_id,))


def main():
    log("Bridge starting")
    load_legal_sessions()
    last_cleanup = 0

    # Compliance: log startup to audit trail
    if COMPLIANCE_AUDIT:
        try:
            log_event("system.startup", actor="bridge", resource="chat_bridge",
                      metadata={"version": "2.0", "compliance": "active"})
        except Exception:
            pass

    try:
        while True:
            try:
                now = time.time()
                if now - last_cleanup >= CLEANUP_INTERVAL_SECONDS:
                    cleanup()
                    last_cleanup = now

                process_pending_messages()
            except Exception as exc:
                log("Loop error: %s" % (exc,))

            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        log("Bridge shutting down")


if __name__ == "__main__":
    main()

