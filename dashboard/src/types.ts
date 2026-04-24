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
  pii_redactions: Record<string, number>;
  input_preview: string;
  sanitized_input_preview: string;
  sanitized_response_preview: string;
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

export interface SocketMessage {
  type: "bootstrap" | "telemetry";
  payload: TelemetryRecord | TelemetryRecord[];
}
