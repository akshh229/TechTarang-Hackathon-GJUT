# Secure AI Interaction Layer (SAIL)

[![Status](https://img.shields.io/badge/status-active-success.svg)](#)
[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](#)
[![Event](https://img.shields.io/badge/event-TechTarang%20Hackathon-orange.svg)](#)

> **Secure AI Interaction Layer for SQL & Multimodal Systems**
>
> A mandatory, language-agnostic security middleware ("AI Firewall & SDK") that wraps LLM integrations to intercept requests, sanitise multimodal inputs, enforce SQL access policies, redact PII, and record immutable audit trails.

---

## 🛡️ The Problem

Enterprises deploying AI assistants over internal databases face critical security risks:

1.  **Prompt Injection**: Ranked #1 on the OWASP Top 10 for LLM Applications. Adversarial instructions in text, images, or PDFs hijack model behavior.
2.  **Excessive Agency**: Unrestricted SQL generation allows LLMs to read, modify, or destroy sensitive data.
3.  **PII Leakage**: Identifiers (Aadhaar, PAN, emails, etc.) are surfaced verbatim to unauthorized users in LLM responses.

Existing solutions like standard Web Application Firewalls (WAFs) and model-level guardrails fail because they cannot understand the semantic meaning of LLM prompts or are easily bypassed by hidden content (e.g., in images or PDFs).

---

## ✨ Features (v2.0)

This version extends our prototype into a demonstrable enterprise product:

-   **Multimodal Ingress Sanitisation**: Detects and blocks prompt injections across plain text, images (OCR), and PDFs.
-   **Policy-Aware SQL Planner**: Maps natural language intents to pre-approved, parameterised SQL templates. The LLM never composes raw SQL.
-   **PII Redaction (Egress)**: Automatically redacts sensitive data (PAN, Aadhaar, phone, email) from LLM output.
-   **Immutable Audit Trail**: Append-only SQLite logging for every request, with zero application-level deletes or updates.
-   **Policy-as-Config Framework**: Hot-reloadable YAML configurations for security rules, SQL policies, and risk thresholds without requiring restarts.
-   **Live Attack Dashboard (New)**: Real-time React UI displaying the attack feed, blocked counts, PII redaction stats, and a latency gauge.
-   **Composite Threat Intelligence Score (New)**: A 0–100 risk score computed per request based on pattern matching, session frequency, and semantic anomalies.
-   **Multi-LLM Provider Adapter (New)**: Provider-agnostic architecture supporting OpenAI, Claude, and Gemini.
-   **Session-Level Anomaly Detection (New)**: Identifies and bans multi-step APT-style attacks across a session.
-   **Red-Team Test Suite**: Benchmarked against public corpora (PromptBench, garak) to quantify resistance.
-   **Compliance Reporting (New)**: One-click exportable reports mapped to DPDP Act 2023 obligations.

---

## 🏗️ Architecture: Zero-Trust "Sandwich" Model

SAIL sits between the user and the LLM, acting as a two-way filter.

```text
Client Request
       ↓
[INGRESS LAYER]   Sanitisation → Threat Score Engine → Intent Classification → SQL Planner
       ↓                                  ↓
                              Session Anomaly Store (Redis/in-memory)
       ↓
[PROVIDER ADAPTER]  OpenAI  |  Claude  |  Gemini  |  Ollama  (pluggable)
       ↓
LLM Engine  (selected provider)
       ↓
[EGRESS LAYER]    PII Redaction → Response Validation → Audit Log Write
       ↓                                  ↓
Sanitised Response → Client     WebSocket broadcast → React Dashboard
```

---

## 🚀 Getting Started

*(Instructions for setup and execution will be added here)*

### Prerequisites

-   Python 3.10+
-   Tesseract OCR (for image sanitisation)
-   Node.js & npm (for the React Dashboard)

---

## 🧪 Testing & Red Teaming

The system includes a red-team test suite benchmarking against the OWASP LLM test cases, targeting a block rate of at least 47/50 on the garak/PromptBench corpus.

---

## 📄 Compliance

Designed with the **DPDP Act 2023** in mind, featuring comprehensive PII masking and one-click PDF/JSON compliance report generation.

---

*Built by Team Techinnovate for the TechTarang Hackathon | April 2026*