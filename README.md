# Secure AI Interaction Layer

Hackathon prototype for a zero-trust AI middleware that sits between LLM apps and enterprise data systems. The project now includes:

- A FastAPI security middleware with ingress inspection, composite threat scoring, session anomaly tracking, egress PII redaction, immutable audit logging, compliance export, and WebSocket telemetry.
- A React dashboard with live attack counters, latency and threat charts, a before/after sanitiser panel, suspicious session watchlist, and one-click red-team demo scenarios.

## Project Structure

- `secure_ai_layer/`: Python backend and tests
- `dashboard/`: React + Vite + Tailwind dashboard
- `context/PRD_v2.0.md`: product requirements document used for implementation

## Backend Features

- `POST /v1/chat/completions`: secure chat entrypoint
- `GET /audit/records`: latest audit records
- `GET /dashboard/summary`: dashboard bootstrap payload
- `GET /dashboard/scenarios`: built-in red-team scenarios
- `POST /demo/simulate`: trigger hackathon demo traffic
- `GET /compliance/report?format=json|pdf`: export compliance report
- `WS /ws/events`: live telemetry stream

## Run the Backend

From `secure_ai_layer/`:

```bash
python -m pip install -r requirements.txt
python -m uvicorn src.main:app --reload
```

The API starts on `http://127.0.0.1:8000`.

## Run the Dashboard

From `dashboard/`:

```bash
npm install
npm run dev
```

The dashboard starts on `http://127.0.0.1:5173`.

Optional environment variables:

- `VITE_API_BASE_URL`
- `VITE_WS_BASE_URL`

Use `dashboard/.env.example` as the starting point.

## Demo Flow

1. Start the backend.
2. Start the dashboard.
3. Open the dashboard and use the `Red-Team Console`.
4. Trigger `Prompt Injection`, `Persona Hijack`, or `Base64 Smuggling`.
5. Watch the attack feed, threat gauge, suspicious session panel, and sanitiser comparison update live.

## Verification

Backend tests:

```bash
cd secure_ai_layer
python -m pytest
```

Frontend build:

```bash
cd dashboard
npm run build
```
