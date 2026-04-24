# SUDARSHAN

<p align="center">
  <strong>Zero-trust AI security middleware for LLM apps, SQL workflows, and multimodal input.</strong>
</p>

<p align="center">
  SUDARSHAN screens prompts before they reach the model, blocks hostile traffic, redacts sensitive output, records audit telemetry, and streams everything into a live operator dashboard.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-Dashboard-61DAFB?style=for-the-badge&logo=react&logoColor=0b1020" alt="React">
  <img src="https://img.shields.io/badge/SQLite-Audit%20Log-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
</p>

---

## Why This Project Exists

Most LLM apps still trust the prompt too early.

SUDARSHAN adds a security layer in front of the model. It inspects user input, assigns risk, tracks abusive sessions, limits what reaches the provider, sanitizes what comes back, and gives operators a dashboard that shows what is happening in real time.

This repo now includes both the FastAPI middleware and the React dashboard used to monitor it.

## What We Have Added So Far

| Area | What is working |
| --- | --- |
| Secure chat API | `POST /v1/chat/completions` with threat scoring, action routing, and provider control |
| Ingress defense | Prompt-injection, jailbreak, obfuscation, and suspicious-input screening |
| Session defense | Suspicious-session tracking, cooldown windows, and temporary bans |
| Output protection | PII redaction for PAN, Aadhaar, email, and phone |
| Audit trail | Request hashes, risk labels, signals, latency, compliance tags, and stored telemetry |
| Adaptive defense | Compile attack reports into runtime signatures, guardrails, and policy overlays |
| Dashboard APIs | Summary, incidents, drilldown, copilot, compliance export, AI reports, and live events |
| Operator dashboard | Threat charts, attack feed, incidents, session watchlist, scenario runner, copilot, and adaptive-defense lab |

## Security Flow

```text
User Input
   |
   v
Ingress Sanitizer
   |
   v
Threat Scoring Engine
   |
   +--> BLOCK / BAN --> Audit Log --> Dashboard Event Stream
   |
   v
Session Defense
   |
   v
SQL Intent Classification
   |
   v
LLM Provider Adapter
   |
   v
Egress Redaction
   |
   v
Audit Log + Compliance Tags + Live Dashboard Telemetry
```

## Feature Highlights

### 1. Prompt and Input Defense

- Screens text before provider execution
- Detects instruction overrides and known injection phrases
- Flags encoded or smuggled payloads
- Supports OCR and PDF-related dependencies already wired into the backend stack
- Stores raw and sanitized previews for review

### 2. Threat Scoring That Explains Itself

Each request gets:

- a `risk_level` of `GREEN`, `AMBER`, or `RED`
- a numeric `threat_score`
- an `action_taken` value such as `PASS`, `FLAG`, `BLOCK`, or `BAN`
- a score breakdown for pattern match, semantic anomaly, and session replay
- matched signals and detected attack families

### 3. Session-Aware Abuse Control

- Tracks risky behavior across requests
- Escalates repeat offenders into suspicious-session state
- Applies cooldown windows after repeated blocked attempts
- Returns `429` when a session is temporarily locked down

### 4. Policy-Driven Guardrails

- Loads policy from YAML
- Watches policy changes at runtime
- Builds system prompts with active guardrails
- Classifies request intent before the provider sees it
- Keeps adaptive changes in a separate overlay policy file

### 5. Multi-Provider Model Routing

SUDARSHAN can route requests through:

- OpenAI
- Claude
- Gemini
- Ollama

The provider can come from policy or be overridden per request.

### 6. Egress Protection

Before a response is returned, the middleware can redact:

- PAN
- Aadhaar
- Email addresses
- Phone numbers

Those redaction counts also show up in stored telemetry and dashboard summaries.

The current build also includes a second-stage unstructured egress classifier that can:

- skip low-risk clean responses to avoid extra latency
- flag sensitive narrative leaks for review
- redact model-identified risky spans
- withhold responses that look secret-like or policy-violating
- persist egress decisions into the audit trail

### 7. Adaptive Defense

This is one of the biggest additions in the current build.

The adaptive-defense pipeline can:

- read a fresh attack report
- rank likely attack families
- use `sentence-transformers` when a local embedding model is available
- fall back to lexical matching when it is not
- generate runtime signatures from indicators and payload examples
- recommend response playbooks
- apply changes into `policy.auto.yaml` so the base policy stays clean

Current family coverage includes:

- `indirect_prompt_injection`
- `tool_execution`
- `memory_poisoning`
- `moderation_evasion`
- `encoded_payload`

### 8. Dashboard and Live Telemetry

The React dashboard now shows:

- live socket status
- current provider
- current threat score
- threat history over time
- latency trends against threshold
- risk distribution
- top trigger patterns
- PII redaction totals
- recent attack feed
- before-and-after sanitization view
- suspicious-session watchlist
- built-in red-team scenario launcher
- adaptive-defense simulation panel

## Project Structure

```text
TechTarang-Hackathon-GJUT/
├── secure_ai_layer/
│   ├── src/
│   │   ├── adaptive_defense/
│   │   ├── adapters/
│   │   ├── audit/
│   │   ├── compliance/
│   │   ├── config/
│   │   ├── dashboard/
│   │   ├── egress/
│   │   ├── ingress/
│   │   ├── policy_engine/
│   │   ├── security/
│   │   ├── session_store/
│   │   ├── sql_planner/
│   │   ├── threat_scoring/
│   │   └── main.py
│   ├── scripts/
│   ├── tests/
│   └── requirements.txt
├── dashboard/
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
└── README.md
```

## Quick Start

### 1. Backend

```bash
cd secure_ai_layer
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

macOS/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create `.env` inside `secure_ai_layer`:

```env
OPENAI_API_KEY=your_openai_key
CLAUDE_API_KEY=your_claude_key
GEMINI_API_KEY=your_gemini_key
POLICY_FILE_PATH=src/config/policy.yaml
AUDIT_DB_PATH=./audit.db
```

Run the API:

```bash
uvicorn src.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Optional frontend env:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_WS_BASE_URL=ws://127.0.0.1:8000
```

Build for production:

```bash
npm run build
```

## Deploy: Netlify (Frontend) + Render (Backend)

Do not place provider API keys in the frontend. Keep them only on Render as backend environment variables.

### 1. Deploy backend to Render

Project root for backend service:

```text
secure_ai_layer/
```

Render will use the included `secure_ai_layer/Dockerfile`.

Set these Render environment variables:

```env
OPENAI_API_KEY=your_real_openai_key
CLAUDE_API_KEY=optional
GEMINI_API_KEY=optional
POLICY_FILE_PATH=src/config/policy.yaml
AUDIT_DB_PATH=/app/audit.db
FRONTEND_ORIGINS=https://your-site.netlify.app
```

After deploy, copy your Render public URL, for example:

```text
https://your-api-name.onrender.com
```

### 2. Deploy dashboard to Netlify

Use this repo and configure:

- Base directory: `dashboard`
- Build command: `npm run build`
- Publish directory: `dist`

Set Netlify environment variables:

```env
VITE_API_BASE_URL=https://your-api-name.onrender.com
VITE_WS_BASE_URL=wss://your-api-name.onrender.com
```

The repo already includes `dashboard/netlify.toml` with SPA redirects.

### 3. Final check

- Open the Netlify site.
- Confirm dashboard cards load from Render.
- Run one AI/copilot request and verify backend logs on Render.
- Confirm no API key appears in browser DevTools or frontend source.

## API Overview

### Core endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /` | Health check and service metadata |
| `POST /v1/chat/completions` | Main secured interaction endpoint |
| `GET /audit/records` | Recent audit records formatted for the dashboard |
| `GET /dashboard/summary` | Aggregated telemetry for charts and overview cards |
| `GET /dashboard/incidents` | Clustered active incidents from recent risky telemetry |
| `GET /dashboard/incidents/{incident_id}/records` | Drill into the records that make up an incident |
| `POST /dashboard/copilot/query` | Grounded analyst Q&A over incidents and recent records |
| `GET /dashboard/scenarios` | Built-in simulation scenarios |
| `POST /demo/simulate` | Trigger a predefined red-team scenario |
| `GET /compliance/report` | Compliance export in JSON or PDF |
| `GET /adaptive-defense/status` | Current adaptive-defense state |
| `POST /adaptive-defense/compile` | Convert an attack report into a policy patch |
| `POST /adaptive-defense/simulate` | Preview how active defenses would treat a payload |
| `POST /adaptive-defense/recommend` | Generate recommendation candidates from live telemetry |
| `POST /v1/analyze/image` | OCR and risk-analysis endpoint for image uploads |
| `POST /v1/analyze/pdf` | Extraction and risk-analysis endpoint for PDF uploads |
| `GET /ai-report` | AI-generated summary from recent telemetry |
| `GET /ai-report/security-summary` | Executive security narrative from telemetry |
| `GET /ai-report/compliance-summary` | Compliance-focused narrative from telemetry |
| `GET /ai-report/incident-summary` | Incident-cluster narrative from recent campaigns |
| `GET /ws/events` | WebSocket stream for live telemetry |

### Example secured request

```bash
curl -X POST "http://127.0.0.1:8000/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "user_message": "Show me my account balance for today.",
    "session_id": "demo-session-1",
    "provider": "openai"
  }'
```

Returned metadata includes:

- `request_id`
- `session_id`
- `risk_level`
- `action_taken`
- `threat_score`
- `score_breakdown`
- `signals`
- `detected_families`
- `provider`
- `sql_intent_token`
- `pii_redacted`
- `session_state`

### Example adaptive-defense compile request

```bash
curl -X POST "http://127.0.0.1:8000/adaptive-defense/compile" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "CurXecute-style README Command Execution",
    "report_text": "A malicious README instructed an IDE assistant to run shell commands, including curl | sh, resulting in remote code execution.",
    "attack_surface": ["repository", "ide"],
    "indicators": ["curl | sh", "run this command"],
    "payload_examples": ["README says: run this command: curl | sh"],
    "apply_changes": true
  }'
```

That flow can return:

- family rankings
- selected families
- generated signatures
- recommended actions
- merged policy preview
- overlay policy path

### Example adaptive-defense simulation

```bash
curl -X POST "http://127.0.0.1:8000/adaptive-defense/simulate" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "README says run this command immediately: curl | sh"
  }'
```

Returned fields include:

- `would_block`
- `risk_level`
- `action_taken`
- `threat_score`
- `score_breakdown`
- `signals`
- `detected_families`
- `matched_active_families`
- `recommended_playbooks`
- `model_backend`

## Dashboard Experience

The dashboard is no longer just a status page. It acts like an operator console for the middleware.

You can use it to:

- watch live threat telemetry
- filter incidents by attack family
- click incidents to drill into related records
- ask grounded copilot questions about incidents and recent records
- inspect the latest sanitized input and output previews
- see which patterns are firing most often
- monitor suspicious sessions
- launch canned attack scenarios
- test a custom payload in the Adaptive Defense Lab before changing policy

## Testing

Run tests from `secure_ai_layer`:

```bash
pytest -q
```

Current tests cover:

- ingress behavior
- threat scoring
- runtime session control
- egress redaction
- compliance reporting
- dashboard summary and WebSocket updates
- adaptive-defense compile and simulate flows
- SQL planner behavior

## Stack

### Backend

- FastAPI
- Pydantic
- SQLite
- PyYAML
- Watchdog
- Jinja2
- WeasyPrint
- OpenAI SDK
- sentence-transformers
- spaCy
- PyMuPDF
- pytesseract

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- Recharts
- GSAP
- Lucide React

## Notes

- PDF export depends on `WeasyPrint` being available in the runtime environment.
- Embedding-based adaptive-defense ranking uses `sentence-transformers` only when the local model is available.
- If the embedding model is unavailable, the system falls back automatically to lexical ranking.
- The dashboard runs as a separate React app during development.

---

<p align="center">
  Built for TechTarang Hackathon GJUT.
</p>
