export type RiskLevel = "GREEN" | "AMBER" | "RED";

export interface SessionState {
  suspicious: boolean;
  cooldown_active: boolean;
  risky_request_count: number;
  blocked_request_count: number;
  cooldown_remaining_seconds: number;
}

export interface ScoreBreakdown {
  pattern_match: number;
  session_replay: number;
  semantic_anomaly: number;
  adaptive_family_boost?: number;
}

export interface TelemetryRecord {
  request_id: string;
  timestamp: string;
  session_id: string;
  risk_level: RiskLevel;
  threat_score: number;
  action_taken: string;
  provider: string;
  latency_ms: number;
  injection_signals: string[];
  score_breakdown: ScoreBreakdown;
  sql_intent_token: string;
  intent_source?: string;
  intent_confidence?: number;
  pii_redactions: Record<string, number>;
  input_preview: string;
  sanitized_input_preview: string;
  sanitized_response_preview: string;
  block_explanation?: string;
  safe_rewrite?: string;
  egress_label?: string;
  egress_recommended_action?: string;
  egress_reasons?: string[];
  egress_was_classified?: boolean;
  incident_family: string;
  session_state: SessionState;
  compliance_tags: string[];
}

export interface SeriesPoint {
  timestamp: string;
  latency_ms?: number;
  threshold_ms?: number;
  threat_score?: number;
  risk_level?: RiskLevel;
}

export interface SuspiciousSession {
  session_id: string;
  risky_request_count: number;
  blocked_request_count: number;
  cooldown_active: boolean;
  cooldown_remaining_seconds: number;
}

export interface Incident {
  incident_id: string;
  label: string;
  family: string;
  top_signal: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  affected_sessions: number;
  actions: Record<string, number>;
  top_signals: Array<{ signal: string; count: number }>;
  avg_threat_score: number;
  severity_score: number;
  sample_input: string;
  latest_explanation: string;
  latest_safe_rewrite: string;
  related_request_ids: string[];
}

export interface DashboardSummary {
  totals: {
    total_requests: number;
    blocked_requests: number;
    flagged_requests: number;
    clean_requests: number;
    suspicious_sessions: number;
    avg_threat_score: number;
    p50_latency_ms: number;
    avg_latency_ms: number;
  };
  risk_distribution: Record<string, number>;
  action_breakdown: Record<string, number>;
  provider_breakdown: Record<string, number>;
  pii_totals: Record<string, number>;
  top_patterns: Array<{ pattern: string; count: number }>;
  latency_series: Array<Required<Pick<SeriesPoint, "timestamp" | "latency_ms" | "threshold_ms">>>;
  threat_series: Array<Required<Pick<SeriesPoint, "timestamp" | "threat_score" | "risk_level">>>;
  suspicious_sessions: SuspiciousSession[];
  latest_before_after: {
    raw_input: string;
    sanitized_input: string;
    sanitized_response: string;
    risk_level: RiskLevel;
    threat_score: number;
    action_taken: string;
  };
  recent_records: TelemetryRecord[];
  current_provider: string;
  latency_threshold_ms: number;
}

export interface Scenario {
  id: string;
  title: string;
  description: string;
}

export interface AdaptiveDefenseSimulation {
  message_preview: string;
  sanitized_input_preview: string;
  would_block: boolean;
  risk_level: RiskLevel;
  action_taken: string;
  threat_score: number;
  score_breakdown: ScoreBreakdown;
  signals: string[];
  detected_families: string[];
  matched_active_families: string[];
  recommended_playbooks: Array<{
    family: string;
    action: string;
    reason: string;
  }>;
  sql_intent_token: string;
  session_state: SessionState & { session_id: string };
  model_backend: string;
}

export interface AdaptiveDefenseStatus {
  enabled: boolean;
  active_families: string[];
  protected_surfaces: string[];
  prompt_guardrail_count: number;
  semantic_signal_count: number;
  ml_signature_count: number;
  response_playbook_count: number;
  model_backend: string;
  overlay_policy_path: string;
  service?: string;
}

export interface PolicyRecommendationItem {
  rule_type: string;
  description: string;
  proposed_value: Record<string, unknown>;
  confidence: number;
  evidence_count: number;
  impact: string;
  safe_to_auto_apply: boolean;
}

export interface PolicyRecommendationResult {
  recommendations: PolicyRecommendationItem[];
  false_positive_candidates: string[];
  summary: string;
  digest?: Record<string, unknown> | null;
  generated_at?: string | null;
}

export interface AttackReportCompileResult {
  report_id: string;
  generated_at: string;
  title: string;
  severity: string;
  detected_families: string[];
  detected_surfaces: string[];
  rationale: string[];
  ml_analysis?: Record<string, unknown>;
  policy_patch: Record<string, unknown>;
  policy_patch_yaml: string;
  merged_policy_preview: Record<string, unknown>;
  summary: {
    new_injection_rules: number;
    new_guardrails: number;
    new_semantic_signals: number;
    new_ml_signatures: number;
  };
  applied: boolean;
  overlay_policy_path?: string;
  overlay_policy_yaml?: string;
}

export interface SocketMessage {
  type: "bootstrap" | "telemetry";
  payload: TelemetryRecord | TelemetryRecord[];
}

export interface IncidentDrilldown {
  incident_id: string;
  count: number;
  records: TelemetryRecord[];
}

export interface DashboardCopilotMetric {
  label: string;
  value: string;
}

export interface DashboardCopilotRecordCitation {
  request_id: string;
  timestamp: string;
  risk_level: string;
  action_taken: string;
  signal: string;
}

export interface DashboardCopilotIncidentCitation {
  incident_id: string;
  label: string;
  family: string;
  severity_score: number;
  event_count: number;
}

export interface DashboardCopilotResponse {
  answer: string;
  supporting_metrics: DashboardCopilotMetric[];
  cited_records: DashboardCopilotRecordCitation[];
  cited_incidents: DashboardCopilotIncidentCitation[];
  suggested_next_actions: string[];
  grounding: {
    scope_label: string;
    record_count: number;
    incident_count: number;
  };
}
