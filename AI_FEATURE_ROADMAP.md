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
| P2 | Continuous AI Red Teaming | Very High | High | Elevates Simulator from manual to autonomous |
| P3 | AI-Assisted Human Review (HITL) | High | Medium | Accelerates triage for ambiguous requests |
| P3 | Automated incident and compliance narratives | Medium | Low | Good reporting layer after other improvements |
| P4 | SIEM & Ticketing Integration (Jira/Splunk) | High | High | Enterprise readiness |
| P4 | Autonomous Threat Remediation Agents | Very High | High | Future state, requires high trust |

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

## Phase 5: Active Defense & Deception

### 9. AI-Generated Deceptive Payloads (Honey-Tokens)

#### Why
Currently, the system blocks threats and returns an error. Advanced attackers will probe the system to learn its boundaries. Serving them dynamic, convincing fake data wastes their resources and captures richer Indicators of Compromise (IOCs) without alerting them that they are caught.

#### What to add
- Dynamic honey-token generation based on the attacker's requested schema.
- AI-hallucinated "believable" database records or configuration files for blocked malicious intents.
- Silent tracking of sessions interacting with deceptive payloads.

#### Suggested implementation
- Add `POST /adaptive-defense/deceive`
- Triggered when `threat_score` is high but `policy.action == "deceive"`
- Uses a fast LLM to return a syntactically valid but fake payload matching the expected application response.

#### Files to change
- new module: `secure_ai_layer/src/adaptive_defense/deception.py`
- `secure_ai_layer/src/main.py` (add deception middleware execution)

---

## Phase 6: Enterprise Integration & Triage

### 10. AI-Formatted SIEM / SOAR Alerts

#### Why
Enterprise SOC (Security Operations Center) teams don't want to check another dashboard; they want data in Splunk, Datadog, or Microsoft Sentinel. AI can analyze unstructured request anomalies and normalize them into standard formats like OCSF (Open Cybersecurity Schema Framework).

#### What to add
- Background task that takes raw incidents and maps them to standard security schemas.
- Auto-generated remediation plays (e.g., "Block IP constraint", "Rotate credentials") sent directly to SOAR platforms contextually.

#### Files to change
- new module: `secure_ai_layer/src/compliance/siem_exporter.py`

---

## Phase 5: Advanced Threat Intelligence & Autonomous Response

This phase represents the long-term vision, moving from decision support to supervised autonomous security operations.

### 9. Predictive Threat Modeling
#### Why
Currently, the system reacts to incoming threats. It should ideally anticipate them based on historical data and generalized patterns.

#### What to add
- Time-series forecasting for attack vectors.
- Identification of seasonal or targeted attack trends.
- Automated alerts for expected traffic anomalies before they hit critical thresholds.
- Pre-emptive tuning of rate limits during forecasted attack windows.

### 10. Autonomous Canary Generation
#### Why
Active defense is better than passive defense. Generating dynamic honeypots distracts attackers and gathers high-fidelity threat intel.

#### What to add
- AI-generated fake endpoints, database records, and API keys tailored to current attacker behaviors.
- Seamless injection of these traps into the adaptive defense layer.
- Maximum-severity alerts triggered upon any interaction with canary data.

---

## Metrics for Success (KPIs)

To quantify the impact of this AI roadmap, track the following baseline metrics before and after deployment:

| Metric | Goal | Primary AI Driver |
| --- | --- | --- |
| **False Positive Rate (FPR)** | >40% Reduction | AI Intent Classifier & Confidence Scoring |
| **Mean Time to Understand (MTTU)** | >60% Faster | AI Block Explanations & Dashboard Copilot |
| **Policy Update Velocity** | Minutes, not days | AI Policy Recommendations from Audit Logs |
| **Zero-Day Egress Catch Rate** | >80% increase | Unstructured Egress Leak Detection |

---

## Phase 5: Autonomous Continuous Red Teaming

### 9. AI-Driven Adversarial Simulation

#### Why
You have `scripts/red_team.py` and `SimulatorPanel.tsx`, but testing is currently manual or uses static payloads. To stay ahead of evolving prompt injections and jailbreaks, the system needs to continuously blind-test itself.

#### What to add
- An LLM-powered attacker agent that dynamically generates novel prompt injections and evasion techniques.
- Automated scheduled simulation runs against the current active policy.
- Auto-generation of new blocking rules based on successful breaches (closing the feedback loop with Adaptive Defense).

#### Suggested implementation
Add endpoint:
- `POST /simulator/auto-run`

Input:
- Target intent
- Mutation techniques (e.g., base64 encoding, persona adoption, translation)

Output:
- Success/Fail rate of attacks
- Gap analysis report
- Drafted adaptive rules to block the successful attacks

#### Files to change
- `secure_ai_layer/scripts/red_team.py` (convert to an imported service)
- `secure_ai_layer/src/adaptive_defense/recommender.py`
- `dashboard/src/components/SimulatorPanel.tsx`

---

## Phase 6: Cost & Latency Orchestration

### 10. Dynamic Semantic Routing

#### Why
Invoking frontier models for every classification, explanation, or fallback is expensive and adds unnecessary latency.

#### What to add
- A lightweight router that evaluates request complexity (token length, heuristic threat presence).
- Routes simple, low-risk classification tasks to fast, cheap models (e.g., Claude 3 Haiku, Gemini Flash, or local Ollama).
- Escalates high-risk, ambiguous, or complex SQL intent queries to heavy frontier models.

#### Suggested implementation
- Expand `secure_ai_layer/src/adapters/factory.py` to support dynamic fallback grading.
- Add `secure_ai_layer/src/ai/router.py`.

---

## Success Metrics & KPIs

To prove these AI features add substantive value, track these KPIs via `MetricCard.tsx`:

- **Classification Accuracy (Precision/Recall)**: How often the AI intent classifier correctly matches operator consensus vs. the legacy rule engine.
- **Mean Time to Resolution (MTTR)**: Reduction in operator investigation time due to AI Block Explanations and Clustering.
- **Adaptive Defense Acceptance Rate**: The percentage of AI-recommended policy rules practically approved by human operators via the `HumanReviewPanel.tsx`.
- **Zero-Day Catch Rate**: Number of unstructured sensitive data blocks (egress) or novel injection attacks (ingress) caught by the AI that bypassed standard regex/heuristics.

---

## Success Metrics & KPIs

To ensure these AI features add concrete value rather than just novelty, we will track the following KPIs:

| Metric | Target | How We Measure |
| --- | --- | --- |
| **Intent Classification Accuracy** | > 95% | Compared against a golden dataset of 1,000+ labeled user queries |
| **False Positive Escalation Rate** | < 2% | Percentage of safe requests incorrectly flagged by the AI classifier |
| **Operator Triage Time** | -50% | Time taken by an admin to resolve or dismiss a flagged incident in the dashboard |
| **Inline AI Overhead (Latency)** | < 200ms | P95 latency added to the critical path (e.g., early intent checks) |
| **Copilot Helpfulness Score** | > 4.5/5 | Explicit thumbs up/down user feedback on dashboard copilot answers |

---

## Model Selection & Routing Strategy

Not all AI tasks require the largest, most expensive models. The system will use a tiered routing strategy via the existing adapter pattern:

1. **Local / Small Models (e.g., Ollama Llama 3 8B, Mistral, sub-1B specialized models)**
   - **Use cases:** Initial intent classification, basic egress PII detection, high-volume inline filtering.
   - **Why:** Zero external cost, ultra-low latency, strict data privacy.
2. **Fast Cloud Models (e.g., Claude 3.5 Haiku, GPT-4o-mini)**
   - **Use cases:** Block explanations, safe rewrites, telemetry clustering summaries.
   - **Why:** High throughput, cheap, capable of strict structured JSON generation.
3. **Heavy Reasoning Models (e.g., Claude 3.5 Sonnet, GPT-4o)**
   - **Use cases:** Dashboard Copilot queries, automated compliance narratives, policy recommendations.
   - **Why:** Requires deep context synthesis, complex reasoning over logs, and high-quality human-readable output.

---

## AI Evaluation (Evals) Framework

To safely deploy Phase 2 and Phase 3, we must implement an LLM-Ops Evaluation pipeline.

### 1. Golden Datasets
We will maintain version-controlled datasets in `tests/evals/`:
- **Red Team Dataset:** 500+ known attack payloads (SQLi, prompt injection, XSS) to ensure AI filters do not degrade base security.
- **Ambiguous Intent Dataset:** Tricky user queries to test the accuracy of the `intent_classifier`.

### 2. LLM-as-a-Judge
For complex outputs like the Dashboard Copilot, we will use an offline evaluator (e.g., using DeepEval or custom scripts) that grades the pipeline on:
- **Faithfulness:** Did the copilot hallucinate, or is the answer grounded in the provided telemetry?
- **Answer Relevance:** Did it actually answer the operator's question?
- **Toxicity/Bias:** Standard enterprise safety checks.

---

## Latency & Cost Budgets

Incorporating AI heavily can impact operating margins and user experience. We are establishing strict budgets for feature types:

| Feature Flow | Latency Budget (P95) | Cost Budget (Per 1k Tokens) | Execution |
| --- | --- | --- | --- |
| **Inline Blocking (Egress/Intent)** | < 150ms | $0.00 (Local) | Blocking / Synchronous |
| **Block Explanation & Rewrite** | < 600ms | < $0.15 | Synchronous (Parallelized) |
| **Incident Clustering** | < 5 seconds | < $0.75 | Background Worker / CRON |
| **Dashboard Copilot Q&A** | < 3 seconds | < $3.00 | Streaming / Asynchronous |
| **Compliance Report Gen** | < 30 seconds| < $5.00 | Scheduled / On-Demand |

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

## Phase 5: Advanced Threat Hunting (Future Vision)

Once the core supervised AI features are stable, the system can move toward predictive and active defense mechanisms.

### 9. LLM-Powered Dynamic Honeypots
- **Why:** Static honeypots are easily fingerprinted by advanced attackers.
- **What:** AI generates realistic, context-aware fake data (e.g., synthetic user records, dynamic API endpoints) to bait attackers and waste their resources.
- **Implementation:** A new `HoneypotGenerator` module that intercepts high-risk sessions and seamlessly routes them to a simulated LLM environment.

### 10. Predictive Attack Graphing
- **Why:** Dashboard incidents show what *has* happened, not what *will* happen.
- **What:** Use ML to predict the next likely steps of an attacker based on their current session trajectory and historical MITRE ATT&CK patterns.
- **Implementation:** Graph-based analysis combined with LLM sequence prediction, visualized in the dashboard as a "Predictive Attack Path".

---

## Model Selection Strategy

Since the architecture supports multiple providers (`claude_adapter`, `gemini_adapter`, `ollama_adapter`), we should route tasks based on cost, latency, and reasoning requirements.

| Task | Preferred Model Tier | Typical Latency Budget | Recommended Adapter |
| --- | --- | --- | --- |
| Intent Classification | Small / Local | < 100ms | `ollama_adapter` (Llama 3 8B) or Gemini Flash |
| Block Explanations | Medium | < 500ms | Claude 3.5 Haiku or GPT-4o-mini |
| Egress Leak Detection | Medium / Fast | < 200ms | Gemini Flash or Claude 3.5 Haiku |
| Dashboard Copilot QA | Large / Reasoning | < 2000ms | `claude_adapter` (Claude 3.5 Sonnet) |
| Policy Recommendations | Large / Reasoning | Async / Batch | `claude_adapter` (Claude 3.5 Sonnet) |

---

## Success Metrics & KPIs

To ensure AI features add value without introducing fragility, track these metrics:

1. **AI Processing Overhead:** Total added latency per request. **Target: < 150ms** for inline features (Intent, Egress).
2. **False Positive Rate (FPR) Reduction:** Drop in legitimate traffic blocked after AI intent and adaptive defense are active. **Target: 30% reduction.**
3. **Copilot Resolution Rate:** Percentage of dashboard alerts resolved or triaged directly via Copilot interactions. **Target: 40% of incidents.**
4. **Fallback Trigger Rate:** How often the system falls back to deterministic rules due to low AI confidence or timeouts. **Target: < 5%.**

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

## Success Metrics & KPIs (How to Measure Impact)

Adding AI must demonstrably improve the platform. Track these metrics before and after deployment:

- **False Positive Rate (FPR)**: Should decrease as the AI Intent Classifier correctly identifies benign complex queries that defeated strict regex rules.
- **Mean Time to Resolution (MTTR)**: Time spent by analysts reviewing logs. Should decrease significantly (target >40%) with Dashboard Copilot and AI Explanations.
- **Threat Catch Rate**: Should increase with Egress Leak Detection capturing unstructured PII, credentials, and secrets.
- **AI Latency Overhead**: Track the latency added to the critical path (target < 200ms for synchronous ingress screening; async for dashboard telemetry).
- **Cost per 1k requests**: Track token usage and API costs to ensure economic viability. Heavily cache repetitive blocked queries to save tokens.

---

## AI Testing & Evaluation Strategy (LLMOps)

You cannot test AI features with simple assertions alone. Implement a robust evaluation pipeline:

- **Evaluations (Evals) Framework**: Validate the `intent_classifier` against a golden dataset of 500+ known good/bad prompts in CI/CD.
- **LLM-as-a-Judge**: Use a stronger model (e.g., GPT-4o or Claude 3.5 Sonnet) offline to rate the quality, accuracy, and safety of the `explanation_generator` outputs.
- **Continuous Red Teaming**: Automate weekly red-team scripts targeting the new AI endpoints to ensure prompt injection or jailbreaks don't bypass the new classifiers.
- **Shadow Mode Deployment**: Run the AI classifiers in "shadow mode" (logging decisions but not altering the control flow) for 7 days before actively acting on their confidence scores.

---

## Future Expansion (Phase 5 & Beyond)

Looking past the immediate roadmap, here are long-term AI capabilities to consider:

- **Autonomous Auto-Remediation**: The system automatically writes, tests, and deploys hotfixes (e.g., adaptive firewall rules, blocklist updates) for zero-day vulnerabilities without human intervention.
- **SIEM/SOAR Integration**: Push AI-formatted threat summaries directly to external platforms like Datadog, Splunk, Jira, or PagerDuty via Webhooks.
- **Federated Threat Intelligence**: Share anonymized attack embeddings across different tenant environments to proactively block emerging threats globally.
- **Predictive User Behavior Analytics (UBA)**: Baseline normal user interaction sequences using pattern recognition to alert on anomalies like sudden mass-data-exfiltration intents.

---

## 🚀 AI Model Selection Strategy

Not all AI tasks require the same model. To balance latency, cost, and intelligence, use a multi-model routing strategy:

| Feature Category | Recommended Model Tier | Latency Budget | Reasoning |
| --- | --- | --- | --- |
| **Inline Blocking (Egress, Intent)** | Fast / Small (e.g., Gemini Flash, Claude Haiku, Llama 3 8B) | < 200ms | Must execute in the critical path of the request without blocking user flows. |
| **Operator Intelligence (Clustering)**| Fast / Small (Embeddings) | N/A (Async) | High volume processing of logs requires cheap, fast vector/embedding generation. |
| **Dashboard Copilot / Q&A** | Capable / Medium (e.g., Claude 3.5 Sonnet, GPT-4o) | < 2s | Needs strong context window and reasoning, but user is waiting for an interactive chat response. |
| **Policy Recommendations / Audit** | Advanced / Large (e.g., Claude 3 Opus, GPT-4) | N/A (Batch) | Deep reasoning over complex security logs. Runs in background or on-demand. |

---

## 📊 Metrics for Success (KPIs)

To prove these AI features actually add value, track these telemetry points before and after deployment:

- **False Positive Reduction:** % of requests incorrectly blocked by rules vs. AI intent classifier.
- **Operator MTTR (Mean Time To Resolve):** Time taken for an analyst to review a flagged incident (target: < 2 mins with Dashboard Copilot vs > 10 mins manual).
- **Safe Rewrite Acceptance:** % of blocked users who successfully complete their request using the AI's "safe alternative phrasing".
- **Added Latency (Critical Path):** Keep P99 latency overhead for inline AI tasks strictly under 250ms.

---

## 🔮 Phase 5: Advanced Autonomous Operations (Future Vision)

Once Phases 1-4 are stable, the system can evolve from just "Assisting" to "Actively Defending":

### 9. Autonomous Red-Teaming (Continuous Testing)
- **Concept:** The system automatically generates synthetic adversarial prompts targeting its own endpoints during low-traffic periods.
- **Impact:** Ensures adaptive defenses are working without waiting for real attackers.

### 10. Dynamic Honey-Token Generation
- **Concept:** AI generates fake, highly credible PII/credentials and injects them into suspicious session responses. 
- **Impact:** Any attempt to exfiltrate or use these tokens immediately triggers a severe block and high-confidence threat score.

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

---

## Phase 5: Advanced Agentic Workflows (Future Horizon)

Once the core supervised AI features are stable, the system can evolve toward proactive, multi-agent defense.

### 9. Multi-Agent Incident Response (Automated Triage)

#### Why
Human operators suffer from alert fatigue. When a complex, multi-stage attack occurs, analysts manually correlate ingress payloads, sql_planner rules, threat scores, and egress behavior.

#### What to add
- A coordinator agent that spawns specialized sub-agents when a critical incident is triggered.
- **Recon Agent**: Analyzes session history, IP reputation, and prior blocked attempts.
- **Payload Agent**: Deconstructs the SQL/NoSQL injection or prompt injection techniques used.
- **Synthesizer Agent**: Compiles findings into a structured incident report.

#### Suggested implementation
- Integrate an orchestration framework (like LangGraph or AutoGen) under a new `src/ai/orchestration/` module.
- Trigger asynchronously via background tasks so it does not block the main request loop.

### 10. Automated YARA / Sigma Rule Generation

#### Why
Currently, the adaptive defense operates purely in the application layer. Bridging the gap to traditional SOC teams means exporting intelligence in industry-standard formats.

#### What to add
- Automatically format unique attack payloads into **YARA rules** for network/file scanning.
- Transform detected behavior patterns into **Sigma rules** for SIEM tools (e.g., Splunk, Elastic).
- Expose via `GET /compliance/rules/export`

---

## AI Evaluation & Metrics (Evals)

You cannot improve what you do not measure. To ensure AI features do not degrade latency, cost, or security, implement a continuous evaluation pipeline.

### Core Metrics to Track
- **Classifier Precision/Recall**: Maintain a "Golden Dataset" of 1,000+ known attack and benign prompts. Run the `intent_classifier` against this dataset on every major PR.
- **Latency Overhead (P95/P99)**: Imposing a strict budget (e.g., +150ms max for inline classification). Complex tasks like block explanations should run asynchronously where possible.
- **Cost per 1M Requests**: Track token usage distinctively by endpoint and provider to prevent runaway LLM costs.

---

## Model Tiering Strategy

Not every feature requires a massive, expensive LLM. Implement a tiered approach in `policy.yaml`:

- **Tier 1 (Edge / Local - Sub 50ms)**: Minimal local models (e.g., fine-tuned Phi-3 or Llama-3-8B) for real-time `intent_classifier` and PII redaction.
- **Tier 2 (Cloud Fast - Sub 300ms)**: Models like Claude 3.5 Haiku or GPT-4o-mini for `block_explanation` and `safe_rewrite`.
- **Tier 3 (Cloud Heavy - Asynchronous)**: Highest reasoning models (Claude 3.5 Sonnet / GPT-4o) for `Dashboard Copilot`, `Telemetry Clustering`, and `Policy Recommendations`.

### 9. Automated Threat Hunting
- **Why**: Currently, the system only evaluates traffic as it passes through. Advanced persistent threats (APTs) often operate "low and slow".
- **What to add**: A background job that runs periodic AI-driven sweeps over historical logs to find correlated anomalies that evaded real-time detection.
- **Implementation**: Schedule an offline analysis task that groups logs by user/IP over a 7-day period and analyzes the chain of events using a high-context LLM.

### 10. Predictive Rule Generation
- **Why**: Adaptive defense currently learns from immediate past attacks. It should anticipate the next step in an attack kill chain.
- **What to add**: AI models predicting future attack vectors based on current reconnaissance traffic, generating pre-emptive block rules.

---

## Integration & Ecosystem Setup

To make the AI features truly enterprise-ready, they need to hook into existing security operations workflows.

- **SIEM / SOAR Connectors**: Stream the new AI-generated `security-summary` and `incident clusters` to tools like Splunk, Datadog, or Microsoft Sentinel.
- **ChatOps Alerts**: Push critical AI-identified incidents (with the `block_explanation` and `safe_rewrite`) directly to a dedicated Slack or Microsoft Teams channel for instant operator review.

---

## Success Metrics (KPIs)

To ensure the AI features are actually improving the product, track these metrics:

1. **Mean Time to Resolution (MTTR)**: Should decrease as the Dashboard Copilot answers operator questions faster.
2. **False Positive Reduction Rate**: The AI Intent Classifier should drop false blocks by at least 15-20%.
3. **Operator Acceptance Rate**: Measure how often operators click "Apply" on the AI Policy Recommendations. A rate > 70% indicates high quality.
4. **AI Latency Overhead**: The time added to request processing by `intent_classifier` and `explanation_generator`. Must remain under 100ms for acceptable UX.

---

## Phase 5: Advanced Threat Hunting (Future Horizon)

Once the core operator workflows are enhanced with AI, the system can move from reactive defense to proactive threat hunting.

### 9. Dynamic Honey-Prompt Generation
- **Why:** Attackers often probe for specific vulnerabilities (e.g., direct SQL injection vs. prompt extraction).
- **What:** Use AI to generate dynamic, safe "honey-tokens" or fake schemas injected into the context when suspicious activity is detected. If the model attempts to use them, the attacker's intent is confirmed beyond doubt.
- **Action:** Add a `honey_token_generator.py` that contextualizes fake data based on the current attack campaign.

### 10. Automated Red-Team Simulators
- **Why:** The existing `/adaptive-defense/simulate` flow requires manual test cases or basic fuzzing.
- **What:** An autonomous Red Team Agent that continuously generates novel bypass techniques tailored to the specific policies of the environment.
- **Action:** Expand `red_team.py` to use a dedicated attacker LLM that iteratively tries to bypass the `defense_compiler.py` rules.

---

## Model Selection Strategy

To manage cost and latency, the architecture should implement a **Model Routing Tier** rather than using a single model for everything:

| Task | Required Traits | Recommended Tier | Example Models |
| --- | --- | --- | --- |
| Intent Classification | Ultra-low latency, strict JSON capability | Tier 1 (Fast/Cheap) | Claude 3.5 Haiku, Gemini Flash, Llama 3.1 8B |
| Block Explanations | Low latency, conversational tone | Tier 1 (Fast/Cheap) | Claude 3.5 Haiku, Gemini Flash |
| Incident Clustering | Batch processing, large context window | Tier 2 (Balanced) | Claude 3.5 Sonnet, GPT-4o-mini |
| Policy Recommendation | High reasoning, code/regex generation | Tier 3 (Heavy) | Claude 3.5 Sonnet, GPT-4o |
| Dashboard Copilot | High reasoning, tool usage, data retrieval | Tier 3 (Heavy) | Claude 3.5 Sonnet, GPT-4o |

---

## KPIs and Success Metrics

To ensure these AI features deliver real security and operational value, we should track the following metrics:

1. **Analyst Efficiency:**
   - **MTTI (Mean Time To Investigate):** Target >50% reduction using AI Block Explanations and Incident Clustering.
   - **Time to Remediation:** Track the speed at which live policy recommendations are reviewed and applied.
   
2. **Classifier Accuracy:**
   - **False Positive Rate:** Measure the delta between strict-rule decisions vs. AI-supported intent decisions.
   - **Validation Fallback Rate:** Track how often the AI intent/egress classifiers fail schema validation and fall back to deterministic rules (Target: < 2%).

3. **System Performance:**
   - **Middleware Added Latency:** Goal is < 200ms overhead for inline AI checks (e.g., intent classification, egress validation). 
   - **Latency Degradation:** Track if AI services are correctly shedding load or falling back to rules during upstream API slowdowns.

---

## Phase 5: Proactive Security (Future Horizon)

Once the core supervised AI features are stable, the system can move from reactive defense to proactive threat hunting.

### 9. Automated Red Teaming & Continuous Simulation

#### Why
The current `red_team.py` script is manual and runs static test cases. To stay ahead of attackers, the system needs to continuously generate novel attack vectors based on live threat intelligence.

#### What to add
- AI-driven payload mutation engine
- Continuous adversarial testing against staging policies
- Automated rule-gap identification
- Integration with the simulator panel to visualize theoretical breaches

### 10. Dynamic Model Routing & Cost Optimization

#### Why
Routing all security checks to heavy models (like Claude 3.5 Sonnet or GPT-4o) is expensive and slow. 

#### What to add
- An intelligent router that sends obvious traffic to fast/cheap models (e.g., Llama 3 8B, Claude 3 Haiku)
- Escalation paths: if a fast model is uncertain (confidence < 0.8), route to a heavier reasoning model
- Real-time latency vs. cost vs. security tracking in the dashboard

---

## Success Metrics & KPIs (How we measure impact)

To ensure these AI features actually improve the product, track:

| Metric | Target | Description |
| --- | --- | --- |
| **False Positive Escalation Rate** | < 5% | % of AI-blocked requests that are manually overridden by operators |
| **Analyst Time-to-Resolution (TTR)** | -40% | Time spent investigating incidents after Telemetry Clustering is active |
| **AI Classifier Latency** | < 200ms | Added latency for inline AI intent classification |
| **Model Fallback Rate** | < 1% | % of requests hitting the deterministic fallback due to model timeouts/parsing errors |
| **Copilot Usage Rate** | > 60% | % of operator sessions that actively query the Dashboard Copilot |

---

## Recommended Model Mapping

| Feature | Recommended Model Class | Why |
| --- | --- | --- |
| **Intent Classification** | Fast/Local (Llama 3 8B, Haiku, GPT-4o-mini) | Latency is critical; task is narrow and structured. |
| **Block Explanations** | Fast (Haiku, Gemini Flash) | Needs to be generated inline quickly for user feedback. |
| **Dashboard Copilot** | Heavy/Reasoning (Sonnet 3.5, GPT-4o) | High reasoning required; latency is less critical for operator workflows. |
| **Egress Leak Detection** | Fine-tuned Local / specialized NLP | Privacy matters; sending sensitive egress data to public APIs is risky. |
| **Policy Recommendations** | Heavy/Reasoning (Sonnet 3.5, GPT-4o) | Requires deep context window and complex synthetic logic generation. |


---

## Phase 5: Autonomous Security Operations (Future)

Once the foundational AI layers (Phases 1-4) are stable, the system can evolve from decision-support to autonomous action.

### 9. Automated Red Teaming (Self-Testing)
- **Why:** The current `red_team.py` script requires manual execution or basic scheduled runs.
- **What to add:** An LLM-powered attacker agent that continuously probes the API endpoints in a sandbox, learning from past blocked requests to craft novel bypass attempts.
- **Impact:** Automatically discovers edge cases before live attackers do, enriching the adaptive defense loop.

### 10. Auto-Quarantine and Dynamic Rate Limiting
- **Why:** High-confidence malicious campaigns currently rely on fixed rate limiters.
- **What to add:** AI agents that dynamically deploy temporary WAF-style blocks or shadow-ban specific session IPs based on multi-turn behavior analysis.

---

## LLM Model Selection Strategy

To balance latency, cost, and intelligence, a multi-model routing approach should be adopted:

| Capability | Recommended Model Class | Why |
| --- | --- | --- |
| **Intent Classification** | Fast/Small (e.g., Claude 3.5 Haiku, Llama 3 8B) | Needs sub-100ms latency. Highly structured JSON output. |
| **Egress Classifier** | Fast/Small (Local Ollama / Gemini Flash) | Privacy-critical. Data shouldn't leave the trust boundary if possible. |
| **Block Explanation** | Balanced (e.g., Claude 3.5 Sonnet, GPT-4o-mini) | Needs context awareness and good formatting. |
| **Policy Recommendation** | Large/Reasoning (e.g., Claude 3 Opus, GPT-4o) | Highly complex logic, runs async via background workers. |

---

## Key Performance Indicators (KPIs)

To prove these AI features are working, track:

1. **False Positive Reduction Rate:** Decrease in legitimate requests blocked after AI explanation/intent refinement.
2. **Mean Time to Understand (MTTU):** Time an operator spends reviewing a dashboard incident (should drop with Copilot).
3. **AI Recommendation Acceptance Rate:** Percentage of AI-proposed adaptive defense rules that human operators actually approve.
4. **Latency Overhead:** The added ms per request for AI guardrails (target: < 200ms for inline checks).
