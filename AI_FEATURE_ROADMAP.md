# AI Feature Roadmap

This roadmap focuses on AI features that fit the current codebase, improve the product meaningfully, and can be shipped in stages without breaking the existing security-first architecture.

## Current State

The project already has a strong foundation:

- request screening and threat scoring
- session-based anomaly handling
- adaptive defense compile and simulate flows
- audit logging and compliance export
- live dashboard telemetry
- multi-provider model adapter support

The biggest gap is that most of the system still relies on heuristics and fixed rules after the initial provider call. The next step is to add AI in places where it improves precision, operator workflow, and product value without letting the model make unsafe decisions on its own.

## Guiding Principle

Use AI as a supervised decision-support layer, not as an unchecked authority.

That means:

- keep hard blocks and policy enforcement deterministic
- add AI where confidence scoring, explanation, clustering, or recommendation helps
- validate every model output before acting on it
- keep a safe fallback path for every AI-assisted feature

---

## Priority Map

| Priority | Feature | Impact | Effort | Why it fits now |
| --- | --- | --- | --- | --- |
| P0 | AI intent classifier with confidence | High | Medium | Directly improves the weakest rule-based area |
| P0 | AI block explanations and safe rewrites | High | Low | Uses data you already collect and improves UX fast |
| P1 | Telemetry clustering and incident grouping | High | Medium | Makes the dashboard much more useful |
| P1 | AI policy recommendations from audit logs | High | Medium | Natural extension of adaptive defense |
| P1 | Dashboard copilot / analyst assistant | Very High | Medium | Strong demo feature and real operator value |
| P2 | Unstructured egress leak detection | High | Medium | Strong security upgrade beyond regexes |
| P2 | Multimodal upload analysis endpoints | Medium | Medium | Matches the product story better |
| P3 | Automated incident and compliance narratives | Medium | Low | Good reporting layer after other improvements |

---

## Phase 1: Quick Wins

These are the best first additions because they use the current architecture well and do not require a major redesign.

### 1. AI Intent Classifier With Confidence

#### Why

The current SQL intent classification is a rule engine:

- [secure_ai_layer/src/sql_planner/planner.py](/d:/TECHTARANG/TechTarang-Hackathon-GJUT/secure_ai_layer/src/sql_planner/planner.py:18)

It works for demos but will miss natural variations, ambiguous phrasing, and multi-part requests.

#### What to add

- a small intent-classification prompt that returns structured JSON
- allowed intents only
- confidence score
- extracted entities such as `loan_id`, `date_range`, `user_scope`
- deterministic fallback to the current rule-based classifier

#### Suggested implementation

- Add `classify_intent_with_ai()` in `secure_ai_layer/src/sql_planner/planner.py`
- Keep `classify_intent()` as the fallback path
- Add a policy section for:
  - `intent_classifier.enabled`
  - `intent_classifier.model`
  - `intent_classifier.min_confidence`
- If confidence is too low, return rule-based result

#### Validation rules

- reject any intent not in the approved template map
- reject malformed output
- reject missing confidence
- log whether result came from `rule`, `ai`, or `ai_fallback`

#### Files to change

- `secure_ai_layer/src/sql_planner/planner.py`
- `secure_ai_layer/src/config/policy.yaml`
- `secure_ai_layer/src/main.py`
- `secure_ai_layer/tests/test_sql_planner.py`

---

### 2. AI Block Explanations and Safe Rewrites

#### Why

The system already produces rich threat signals in:

- [secure_ai_layer/src/threat_scoring/engine.py](/d:/TECHTARANG/TechTarang-Hackathon-GJUT/secure_ai_layer/src/threat_scoring/engine.py:33)

But blocked responses only expose a basic error payload in:

- [secure_ai_layer/src/main.py](/d:/TECHTARANG/TechTarang-Hackathon-GJUT/secure_ai_layer/src/main.py:388)

That is functional, but not very helpful to users or operators.

#### What to add

- short human-readable explanation of why a request was blocked
- likely attack family
- safe alternative phrasing suggestion
- operator-facing explanation for the audit trail

#### Suggested implementation

- Add a helper module like `secure_ai_layer/src/explanations/generator.py`
- Input:
  - `risk_level`
  - `threat_score`
  - `signals`
  - `detected_families`
  - sanitized input preview
- Output:
  - `user_reason`
  - `operator_reason`
  - `safe_rewrite`

#### Safe pattern

- only run for blocked or flagged requests
- require structured JSON output
- if generation fails, fall back to deterministic templates

#### Files to change

- `secure_ai_layer/src/main.py`
- new module under `secure_ai_layer/src/explanations/`
- `dashboard/src/types.ts`
- `dashboard/src/components/AttackFeedTable.tsx`
- tests for blocked response payloads

---

## Phase 2: Operator Intelligence

This phase makes the dashboard much more than a live chart page.

### 3. Telemetry Clustering and Campaign Detection

#### Why

You already store detailed audit records in:

- [secure_ai_layer/src/audit/logger.py](/d:/TECHTARANG/TechTarang-Hackathon-GJUT/secure_ai_layer/src/audit/logger.py:56)

And summarize them for the dashboard in:

- [secure_ai_layer/src/main.py](/d:/TECHTARANG/TechTarang-Hackathon-GJUT/secure_ai_layer/src/main.py:167)

Right now the dashboard shows events, but not whether they belong to the same campaign.

#### What to add

- cluster similar attacks by:
  - message pattern
  - family
  - session behavior
  - source timing
- group them into incident buckets
- surface top active campaigns in the dashboard

#### Suggested implementation

- Start with lightweight embeddings or lexical similarity
- compute cluster summaries in a background-safe helper
- expose a new endpoint:
  - `GET /dashboard/incidents`

Each incident should return:

- `incident_id`
- `label`
- `family`
- `first_seen`
- `last_seen`
- `event_count`
- `affected_sessions`
- `top_signals`
- `severity_score`

#### Files to change

- new module: `secure_ai_layer/src/dashboard/incidents.py`
- `secure_ai_layer/src/main.py`
- `dashboard/src/lib/api.ts`
- `dashboard/src/types.ts`
- new dashboard component for incidents

---

### 4. AI Policy Recommendations From Audit Logs

#### Why

Adaptive defense is currently report-driven through:

- `/adaptive-defense/compile`
- `/adaptive-defense/simulate`

That is a good start, but the product should also learn from its own live traffic.

#### What to add

- analyze recent blocked and flagged records
- propose:
  - new semantic signals
  - new ML signatures
  - adjusted thresholds
  - tighter session policies
  - possible false-positive reviews

#### Suggested implementation

Add a new endpoint:

- `POST /adaptive-defense/recommend`

Input options:

- time window
- minimum event count
- include false-positive review

Output:

- recommended rules
- confidence
- supporting evidence from telemetry
- impact estimate
- whether recommendation is safe to auto-apply

#### Important constraint

Do not auto-apply by default.

Use human approval or a separate `apply_recommendation` flow.

#### Files to change

- new module under `secure_ai_layer/src/adaptive_defense/`
- `secure_ai_layer/src/main.py`
- `dashboard/src/components/AdaptiveDefensePanel.tsx`
- tests similar to `test_adaptive_defense.py`

---

### 5. Dashboard Copilot

#### Why

The dashboard UI in:

- [dashboard/src/App.tsx](/d:/TECHTARANG/TechTarang-Hackathon-GJUT/dashboard/src/App.tsx:162)

already has the right data model for a security copilot, but users still have to interpret everything manually.

#### What to add

An operator assistant that answers questions like:

- "Why did blocked traffic spike today?"
- "Which sessions look like tool-execution attempts?"
- "Summarize the top risky signals from the last hour."
- "What changed after adaptive defense was updated?"

#### Suggested implementation

Add:

- `POST /dashboard/copilot/query`

Context source:

- dashboard summary
- recent records
- active adaptive-defense state
- incidents if Phase 2.3 is done

Response:

- short answer
- supporting metrics
- cited records or clusters
- suggested next actions

#### Guardrails

- do not allow it to mutate policy directly
- keep response grounded in retrieved telemetry only
- use structured output

#### Files to change

- new backend module under `secure_ai_layer/src/dashboard/`
- `secure_ai_layer/src/main.py`
- `dashboard/src/lib/api.ts`
- `dashboard/src/types.ts`
- new `DashboardCopilotPanel.tsx`

---

## Phase 3: Security Depth

### 6. Unstructured Egress Leak Detection

#### Why

Current egress protection is regex-heavy:

- [secure_ai_layer/src/egress/redactor.py](/d:/TECHTARANG/TechTarang-Hackathon-GJUT/secure_ai_layer/src/egress/redactor.py:5)

That covers structured identifiers, but not:

- credentials
- secrets
- internal instructions
- sensitive narrative content
- high-risk summarizations of internal data

#### What to add

A second-stage egress classifier that labels outputs as:

- safe
- sensitive
- secret-like
- policy-violating
- needs review

#### Suggested implementation

- keep regex redaction as stage one
- run AI classification on the redacted text or raw response depending on risk mode
- if risk exceeds threshold:
  - redact further
  - replace with safe refusal
  - log a separate egress alert

#### Files to change

- `secure_ai_layer/src/egress/redactor.py`
- new module `secure_ai_layer/src/egress/classifier.py`
- `secure_ai_layer/src/main.py`
- dashboard metrics and alert feed types

---

### 7. Multimodal Upload Analysis

#### Why

The sanitizer already has multimodal helpers:

- [secure_ai_layer/src/ingress/sanitizer.py](/d:/TECHTARANG/TechTarang-Hackathon-GJUT/secure_ai_layer/src/ingress/sanitizer.py:82)

But the API still only exposes text chat.

#### What to add

- upload image endpoint
- upload PDF endpoint
- OCR/extraction output preview
- risk analysis on extracted content
- suspicious-span surfacing in dashboard

#### Suggested implementation

Add endpoints such as:

- `POST /v1/analyze/image`
- `POST /v1/analyze/pdf`

Return:

- extracted text preview
- triggered rules
- threat score
- attack families
- sanitized output

#### Files to change

- `secure_ai_layer/src/main.py`
- `secure_ai_layer/src/ingress/sanitizer.py`
- `dashboard/src/lib/api.ts`
- `dashboard/src/types.ts`
- new dashboard panel for multimodal analysis

---

## Phase 4: Reporting and Product Polish

### 8. AI Incident and Compliance Narratives

#### Why

There is already a basic telemetry summary endpoint:

- [secure_ai_layer/src/main.py](/d:/TECHTARANG/TechTarang-Hackathon-GJUT/secure_ai_layer/src/main.py:662)

This is a good seed, but it can become much more useful.

#### What to add

- executive incident summary
- compliance-ready narrative
- attack trend summary
- recommended actions
- before/after comparison for adaptive-defense changes

#### Suggested implementation

Expand `/ai-report` or split into:

- `GET /ai-report/security-summary`
- `GET /ai-report/compliance-summary`
- `GET /ai-report/incident-summary`

#### Files to change

- `secure_ai_layer/src/main.py`
- maybe a new reporting module under `secure_ai_layer/src/compliance/`
- dashboard report export actions

---

## Architectural Recommendations

These matter across all phases.

### 1. Create a dedicated AI service layer

Right now AI-related logic is spread across adapters, compiler flow, and endpoint handlers.

Create a folder like:

```text
secure_ai_layer/src/ai/
├── client.py
├── schemas.py
├── prompts/
├── intent_classifier.py
├── explanation_generator.py
├── telemetry_analyst.py
└── egress_classifier.py
```

This keeps:

- prompts versioned
- JSON schemas centralized
- retries and validation consistent
- fallback behavior reusable

### 2. Treat prompts as versioned assets

Do not inline large prompts in endpoint functions long term.

Move prompts into files or constants with:

- version tag
- owner
- test coverage
- fallback behavior

### 3. Add structured output validation everywhere

Every new AI feature should return strict JSON validated by Pydantic models.

This is especially important for:

- intent classification
- policy recommendations
- dashboard copilot
- block explanations

### 4. Add explicit source grounding for operator-facing AI

For dashboard answers and incident summaries, always return:

- supporting metrics
- source records or clusters
- time window

That keeps the answers inspectable.

---

## Suggested Delivery Order

### Sprint 1

- AI intent classifier with fallback
- AI block explanations
- prompt and schema scaffolding under `src/ai/`

### Sprint 2

- telemetry clustering
- `GET /dashboard/incidents`
- dashboard incidents panel

### Sprint 3

- adaptive-defense recommendations from live logs
- dashboard approval flow for recommendations

### Sprint 4

- dashboard copilot
- grounded telemetry Q&A

### Sprint 5

- unstructured egress leak detection
- multimodal upload endpoints

### Sprint 6

- richer AI incident reports
- compliance narratives

---

## Best Demo Combination

If the goal is a high-impact demo without overbuilding, ship this combination first:

1. AI intent classifier with confidence and fallback
2. AI block explanation with safe rewrite suggestion
3. Telemetry clustering with incident cards
4. Dashboard copilot grounded in recent records

That set makes the product feel much more complete while staying aligned with the existing architecture.

---

## Risks To Watch

| Risk | Why it matters | Mitigation |
| --- | --- | --- |
| Trusting AI too early | Can weaken the security posture | Keep policy enforcement deterministic |
| Hallucinated policy suggestions | Dangerous if auto-applied | Human approval and schema validation |
| UI-only AI demos | Looks good but does not improve product core | Prioritize backend intelligence first |
| Cost creep | Several new AI endpoints can get expensive | Add caching, thresholds, and smaller models |
| Latency growth | Security middleware must stay responsive | Use async calls and only invoke AI when needed |

---

## Concrete Next Build

If building starts now, the best first implementation is:

- `src/ai/intent_classifier.py`
- `src/ai/explanation_generator.py`
- integrate both into:
  - `secure_ai_layer/src/sql_planner/planner.py`
  - `secure_ai_layer/src/main.py`
- add:
  - `intent_source`
  - `intent_confidence`
  - `block_explanation`
  - `safe_rewrite`

That gives the fastest path to a noticeably smarter system.
