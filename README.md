# AI Governance Portfolio — Compliance Framework

**John Bianchina** · [pursuitreadiness.com](https://pursuitreadiness.com) · john@pursuitreadiness.com · [LinkedIn](https://www.linkedin.com/in/john-bianchina-88965078/)

A POPIA-compliant data protection layer for multi-industry AI systems. This repo contains the
governance modules, the audit trail, and one production bridge component.

Not a demo. These modules run under every system I deploy.

---

## What's in this repo

### `/compliance`

**`audit_trail.py`** — SHA-256 hash-chained event logging with tamper-evident verification. Every
PII operation is recorded with a UUID, timestamp, actor, resource, action and trace ID. Records are
chained, so altering any past entry breaks verification from that point forward. Retention: 2 years
active, 6 years archive.

**`consent.py`** — scope-based consent registry with capture, persistence and runtime enforcement.
Every PII operation checks consent before execution rather than trusting that a check happened
upstream.

**`hitl.py`** — human-in-the-loop approval gates for sensitive operations: data access, deletion,
correction, escalation, legal review. The gates are mandatory and cannot be bypassed
programmatically. This is the part that matters most in a regulated industry — the system can
refuse an action, but it can never take a sensitive one on its own.

### `/systems`

**`bridge.py`** — the WhatsApp-to-AI bridge component: persona routing (known user vs. new
prospect), multi-platform message relay, structured lead capture, and session locking for atomic
operations.

---

## Why these three modules, in this order

A check that depends on someone remembering to run it is not a control. Each module removes a
different class of failure:

| Module | The failure it prevents |
|---|---|
| `audit_trail` | "We think it processed that data, but we can't prove what happened." |
| `consent` | "The data was collected lawfully, so using it here must be fine." |
| `hitl` | "The automation was correct, but nobody authorised it." |

Hash-chaining rather than plain logging is deliberate. An editable log proves nothing when the
question is whether the log itself is trustworthy.

---

## Context

I built the compliance framework in 48 hours because a dental client needed POPIA guarantees before
they would deploy. Rather than write a checklist, I built a framework that made compliance
automatic, made decisions auditable enough to show a regulator, and kept human oversight mandatory
without turning it into a bottleneck.

It now underpins every AI system I deploy across legal, dental, real estate and healthcare work.
It was not in the plan. It emerged from a client's real problem, and the solution turned out to be
reusable infrastructure.

---

## Stack

Python · SHA-256 hash chaining · consent registries · webhook and API integration · SQLite /
Postgres · bash scripting · GitHub Actions (CI configured in `.github/workflows/python-app.yml`)

---

## What's coming

The next step is closing the loop: the AI learning from human decisions at the approval gate so
the gate is needed less often over time — while keeping the audit trail that proves it stayed safe.

---

**Let's talk.** john@pursuitreadiness.com · [pursuitreadiness.com](https://pursuitreadiness.com) · [LinkedIn](https://www.linkedin.com/in/john-bianchina-88965078/)
