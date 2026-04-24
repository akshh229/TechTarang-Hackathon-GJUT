import sys

content = open(r'd:\TECHTARANG\TechTarang-Hackathon-GJUT\secure_ai_layer\src\main.py', 'rb').read().decode('utf-8')

insertion = '''

@app.get("/ai-report/security-summary")
async def ai_report_security_summary() -> Dict[str, Any]:
    """Executive security summary with top attack families and mitigations."""
    logger = get_audit_logger()
    records = logger.get_records(limit=300)
    summary = build_dashboard_summary(records)
    _, adapter = get_provider_adapter(None)
    prompt = (
        "You are a senior threat analyst. Write a concise executive security summary based on this telemetry:\\n"
        f"Blocked: {summary['totals']['blocked_requests']} | "
        f"Flagged: {summary['totals']['flagged_requests']} | "
        f"Clean: {summary['totals']['clean_requests']} | "
        f"Suspicious sessions: {summary['totals']['suspicious_sessions']}\\n"
        f"Top attack patterns: {summary['top_patterns']}\\n"
        f"Risk distribution: {summary['risk_distribution']}\\n"
        "Provide: (1) Threat landscape, (2) Top active attack families, "
        "(3) Recommended immediate mitigations. Be concise and operator-facing."
    )
    try:
        report_text = await adapter.complete("You are a Cybersecurity Expert AI.", prompt, temperature=0.2)
    except Exception as exc:
        report_text = f"[Fallback] Security summary generation failed: {exc}"
    return {
        "report_type": "security_summary",
        "status": "success",
        "report_text": report_text,
        "metrics_snapshot": summary["totals"],
        "top_patterns": summary["top_patterns"],
        "risk_distribution": summary["risk_distribution"],
        "timestamp": utc_now_iso(),
    }


@app.get("/ai-report/compliance-summary")
async def ai_report_compliance_summary() -> Dict[str, Any]:
    """AI-generated compliance narrative aligned to DPDP / ISO 27001 frameworks."""
    logger = get_audit_logger()
    records = logger.get_records(limit=500)
    compliance_report = compliance_reporter.build_report(records, None, None)
    summary = build_dashboard_summary(records)
    _, adapter = get_provider_adapter(None)
    prompt = (
        "You are a compliance officer AI. Write a compliance narrative for the following firewall telemetry:\\n"
        f"Total requests analysed: {summary['totals']['total_requests']}\\n"
        f"Blocked: {summary['totals']['blocked_requests']} | Flagged: {summary['totals']['flagged_requests']}\\n"
        f"PII redacted: {summary['pii_totals']}\\n"
        "Framework: India DPDP Act, ISO 27001 Annex A.\\n"
        "Provide: (1) Compliance posture assessment, (2) Data minimisation observations, "
        "(3) Recommendations to close any compliance gaps. Use formal language."
    )
    try:
        report_text = await adapter.complete("You are a Compliance Expert AI.", prompt, temperature=0.15)
    except Exception as exc:
        report_text = f"[Fallback] Compliance narrative generation failed: {exc}"
    return {
        "report_type": "compliance_summary",
        "status": "success",
        "report_text": report_text,
        "pii_totals": summary["pii_totals"],
        "compliance_data": compliance_report,
        "timestamp": utc_now_iso(),
    }


@app.get("/ai-report/incident-summary")
async def ai_report_incident_summary() -> Dict[str, Any]:
    """AI-generated incident summary clustering active attack campaigns."""
    logger = get_audit_logger()
    records = logger.get_records(limit=400)
    incidents = build_incidents(records, limit=10)
    summary = build_dashboard_summary(records)
    _, adapter = get_provider_adapter(None)
    incident_digest = [
        {
            "label": inc.get("label"),
            "family": inc.get("family"),
            "event_count": inc.get("event_count"),
            "severity_score": inc.get("severity_score"),
            "first_seen": inc.get("first_seen"),
            "last_seen": inc.get("last_seen"),
        }
        for inc in incidents
    ]
    prompt = (
        "You are a threat hunter AI. Summarise the following active attack incidents:\\n"
        f"{incident_digest}\\n"
        f"Total events in window: {summary['totals']['total_requests']}\\n"
        "Provide: (1) Incident-by-incident narrative, (2) Campaign attribution hypothesis, "
        "(3) Recommended next actions for each incident. Be specific and concise."
    )
    try:
        report_text = await adapter.complete("You are a Threat Hunter AI.", prompt, temperature=0.2)
    except Exception as exc:
        report_text = f"[Fallback] Incident summary generation failed: {exc}"
    return {
        "report_type": "incident_summary",
        "status": "success",
        "report_text": report_text,
        "active_incidents": incidents,
        "incident_count": len(incidents),
        "timestamp": utc_now_iso(),
    }

'''

# Try CRLF needle first, then LF
for needle in ['\r\n\r\nfrontend_dir', '\n\nfrontend_dir']:
    if needle in content:
        new_content = content.replace(needle, insertion + needle.lstrip('\r\n') + needle[len(needle.lstrip('\r\n')):], 1)
        # simpler: just insert before the needle
        idx = content.index(needle)
        new_content = content[:idx] + insertion + content[idx:]
        open(r'd:\TECHTARANG\TechTarang-Hackathon-GJUT\secure_ai_layer\src\main.py', 'wb').write(new_content.encode('utf-8'))
        print(f'DONE (needle={repr(needle[:10])})')
        sys.exit(0)

print('NEEDLE NOT FOUND')
print(repr(content[-200:]))
