# AI-Native Product Operator — Portfolio

**John Bianchina** · [aithatbooks.co.za](https://aithatbooks.co.za) · john@aithatbooks.co.za · +27 78 914 0260

> *"We're hiring for someone who treats AI as a daily working partner, who is restless about how things are done, and who is going to make us better every week by finding smarter ways to do the work."* — Ringier CDE

This repo is the evidence. Not a CV. A working system.

---

## What's Here

This repository contains production AI infrastructure that runs 24/7 on a VPS — a multi-agent AI operating system that handles real conversations, manages compliance, and orchestrates autonomous workflows across industries.

### Systems (`/systems`)

**`bridge.py`** — 598-line WhatsApp-to-AI bridge that connects real users to an AI concierge system. It handles:
- Persona routing (detects known users vs. new prospects)
- Multi-platform message relay (WhatsApp, webhook, API)
- Lead capture with structured qualification
- Campaign tracking with booking-stage progression
- Legal pre-filtering with compliance gates
- Session locking for atomic operations

This isn't a demo. It's running in production with 40+ hours uptime, handling conversations across legal, dental, and real estate verticals.

### Compliance Framework (`/compliance`)

POPIA-compliant data protection layer built for multi-industry AI systems:

- **`audit_trail.py`** — SHA-256 hash-chained event logging with tamper-evident verification. Every PII operation is recorded with UUID, timestamp, actor, resource, action, and trace ID. 2-year active / 6-year archive retention.
- **`consent.py`** — Scope-based consent registry with capture, persistence, and runtime enforcement. All PII operations check consent before execution.
- **`hitl.py`** — Human-in-the-loop approval gates for sensitive operations (data access, deletion, correction, escalation, legal review). Mandatory gates that cannot be bypassed programmatically.

### Architecture

```
                    ┌──────────────────────────────┐
                    │     WhatsApp / Web / API      │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │     PHP Proxy (cPanel)        │
                    │  → Persona routing            │
                    │  → Legal pre-filter            │
                    │  → Campaign tracking           │
                    └──────────────┬───────────────┘
                                   │
           ┌───────────────────────┼───────────────────────┐
           │                       │                       │
    ┌──────▼──────┐        ┌──────▼──────┐        ┌──────▼──────┐
    │   Hermes    │        │  Paperclip  │        │ Agent Zero  │
    │  Concierge  │◄──────►│ Orchestrator│◄──────►│ Autonomous  │
    │  (Gateway)  │        │ (Postgres)  │        │   (FAISS)   │
    └──────┬──────┘        └──────┬──────┘        └─────────────┘
           │                       │
    ┌──────▼───────────────────────▼──────┐
    │         Compliance Layer             │
    │  audit_trail │ consent │ hitl       │
    └──────────────────────────────────────┘
```

## Why This Matters for CDE

| CDE Requirement | Evidence in This Repo |
|---|---|
| **AI fluency in practice** | Multi-agent orchestration with model switching, tool routing, and autonomous workflows |
| **Bias toward automation** | Compliance is automated, lead capture is automated, persona routing is automated — no human does repetitive work |
| **Operational discipline** | Production system with audit trails, consent tracking, and HITL gates — designed for accountability |
| **Customer instinct** | Persona routing understands who's talking and adapts; lead capture qualifies without friction |
| **Technical literacy** | Python, Node.js, Docker, Postgres, API integration, bash scripting — all evidenced in working code |
| **Comfort with ambiguity** | This system wasn't built from a spec — it evolved through iteration, like CDE's growing product |
| **Strong written communication** | Code is documented, architecture is explained, compliance is traceable |

## Live Demos

The portfolio site at [aithatbooks.co.za](https://aithatbooks.co.za) has 4 interactive AI system demos:

- **Hermann Concierge** — AI guest intake for safari lodges (live in production)
- **DentaLink AI** — Dental enquiry triage with safety checks
- **CV Parsing Engine** — Structured candidate extraction
- **Business AI Framework** — Operational workflow automation across 6 industries

## What AI Changed for Me in the Last 12 Months

I stopped writing code to solve problems and started building systems that solve problems autonomously.

The bridge.py file in this repo used to be a manual workflow — I'd write a script, test it, deploy it, monitor it. Now the system monitors itself. When something breaks, the watchdog catches it before I notice. When a new client comes in, the persona router handles intake without me touching anything.

What I want to change next: close the loop entirely. Right now there's still a human review gate (by design, for compliance). The next step is building the feedback system where the AI learns from those human decisions and reduces the need for them over time — while maintaining the audit trail that proves it's safe.

## Something I Built Recently That I'm Proud Of

This repo. Not the code — the system around the code.

The compliance framework (audit, consent, HITL) was built in 48 hours because a dental client needed POPIA guarantees before they'd deploy. Rather than building a checklist, I built a framework that:

1. Made compliance automatic (not a manual process someone would skip)
2. Made decisions auditable (so the client could prove compliance to regulators)
3. Made human oversight mandatory but lightweight (so it didn't become a bottleneck)

That framework now underpins every AI system I deploy — legal, dental, real estate. It wasn't in the plan. It emerged because a client had a real problem, and the solution turned out to be reusable infrastructure. That's how I think about product: build the thing that makes the next thing faster.

---

**Let's talk.** john@aithatbooks.co.za · [aithatbooks.co.za](https://aithatbooks.co.za) · [LinkedIn](https://www.linkedin.com/in/john-bianchina-88965078/)
