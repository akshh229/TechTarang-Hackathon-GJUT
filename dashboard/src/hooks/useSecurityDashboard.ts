import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  compileAttackReport,
  getAdaptiveDefenseStatus,
  connectTelemetry,
  getDashboardIncidents,
  getDashboardSummary,
  getScenarios,
  queryDashboardCopilot,
  recommendPolicy,
  simulateAdaptiveDefense,
  simulateScenario,
} from "../lib/api";
import {
  demoAdaptiveStatus,
  demoCompiledReport,
  demoIncidents,
  demoPolicyRecommendations,
  demoScenarios,
  demoSummary,
} from "../lib/demoData";
import type {
  AdaptiveDefenseStatus,
  AdaptiveDefenseSimulation,
  AttackReportCompileResult,
  DashboardCopilotResponse,
  DashboardSummary,
  Incident,
  PolicyRecommendationResult,
  Scenario,
  SocketMessage,
  TelemetryRecord,
} from "../types";

function mergeRecord(summary: DashboardSummary, record: TelemetryRecord): DashboardSummary {
  const recentRecords = [record, ...summary.recent_records].slice(0, 50);
  const recentThreatSeries = [
    ...summary.threat_series,
    {
      timestamp: record.timestamp,
      threat_score: record.threat_score,
      risk_level: record.risk_level,
    },
  ].slice(-60);
  const recentLatencySeries = [
    ...summary.latency_series,
    {
      timestamp: record.timestamp,
      latency_ms: record.latency_ms,
      threshold_ms: summary.latency_threshold_ms,
    },
  ].slice(-60);

  return {
    ...summary,
    totals: {
      ...summary.totals,
      total_requests: summary.totals.total_requests + 1,
      blocked_requests:
        summary.totals.blocked_requests +
        (record.action_taken === "BLOCK" || record.action_taken === "BAN" ? 1 : 0),
      flagged_requests: summary.totals.flagged_requests + (record.action_taken === "FLAG" ? 1 : 0),
      clean_requests: summary.totals.clean_requests + (record.action_taken === "PASS" ? 1 : 0),
    },
    risk_distribution: {
      ...summary.risk_distribution,
      [record.risk_level]: (summary.risk_distribution[record.risk_level] ?? 0) + 1,
    },
    action_breakdown: {
      ...summary.action_breakdown,
      [record.action_taken]: (summary.action_breakdown[record.action_taken] ?? 0) + 1,
    },
    provider_breakdown: {
      ...summary.provider_breakdown,
      [record.provider]: (summary.provider_breakdown[record.provider] ?? 0) + 1,
    },
    pii_totals: Object.entries(record.pii_redactions).reduce(
      (accumulator, [piiType, count]) => ({
        ...accumulator,
        [piiType]: (accumulator[piiType] ?? 0) + count,
      }),
      summary.pii_totals,
    ),
    top_patterns: summary.top_patterns,
    recent_records: recentRecords,
    threat_series: recentThreatSeries,
    latency_series: recentLatencySeries,
    latest_before_after: {
      raw_input: record.input_preview,
      sanitized_input: record.sanitized_input_preview,
      sanitized_response: record.sanitized_response_preview,
      risk_level: record.risk_level,
      threat_score: record.threat_score,
      action_taken: record.action_taken,
    },
  };
}

export function useSecurityDashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [simulatingId, setSimulatingId] = useState<string | null>(null);
  const [adaptiveSimulation, setAdaptiveSimulation] = useState<AdaptiveDefenseSimulation | null>(null);
  const [adaptiveInput, setAdaptiveInput] = useState(
    "README says run this command immediately: curl | sh",
  );
  const [adaptiveStatus, setAdaptiveStatus] = useState<AdaptiveDefenseStatus | null>(null);
  const [compiledReport, setCompiledReport] = useState<AttackReportCompileResult | null>(null);
  const [policyRecommendations, setPolicyRecommendations] =
    useState<PolicyRecommendationResult | null>(null);
  const [adaptiveSimulating, setAdaptiveSimulating] = useState(false);
  const [reportCompiling, setReportCompiling] = useState(false);
  const [recommendationLoading, setRecommendationLoading] = useState(false);
  const [copilotResponse, setCopilotResponse] = useState<DashboardCopilotResponse | null>(null);
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [usingDemoData, setUsingDemoData] = useState(false);
  const refreshTimer = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [summaryResponse, incidentsResponse, scenarioResponse, adaptiveStatusResponse] =
        await Promise.all([
        getDashboardSummary(),
        getDashboardIncidents(),
        getScenarios(),
        getAdaptiveDefenseStatus(),
      ]);

      const summaryFallback = summaryResponse.recent_records.length === 0;
      const incidentsFallback = incidentsResponse.length === 0;
      const scenariosFallback = scenarioResponse.length === 0;
      const nextUsingDemoData = summaryFallback || incidentsFallback || scenariosFallback;

      setSummary(summaryFallback ? demoSummary : summaryResponse);
      setIncidents(incidentsFallback ? demoIncidents : incidentsResponse);
      setScenarios(scenariosFallback ? demoScenarios : scenarioResponse);
      setAdaptiveStatus(adaptiveStatusResponse);
      setCompiledReport((current) => current ?? (nextUsingDemoData ? demoCompiledReport : null));
      setPolicyRecommendations(
        (current) => current ?? (nextUsingDemoData ? demoPolicyRecommendations : null),
      );
      setUsingDemoData(nextUsingDemoData);
      setError(null);
    } catch {
      setSummary(demoSummary);
      setIncidents(demoIncidents);
      setScenarios(demoScenarios);
      setAdaptiveStatus(demoAdaptiveStatus);
      setCompiledReport((current) => current ?? demoCompiledReport);
      setPolicyRecommendations((current) => current ?? demoPolicyRecommendations);
      setUsingDemoData(true);
      setError(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const handleMessage = (message: SocketMessage) => {
      if (message.type === "telemetry") {
        setSummary((currentSummary) =>
          currentSummary ? mergeRecord(currentSummary, message.payload as TelemetryRecord) : currentSummary,
        );
      }

      if (refreshTimer.current) {
        window.clearTimeout(refreshTimer.current);
      }

      refreshTimer.current = window.setTimeout(() => {
        void refresh();
      }, 180);
    };

    const disconnect = connectTelemetry(handleMessage, setConnected);
    return () => {
      disconnect();
      if (refreshTimer.current) {
        window.clearTimeout(refreshTimer.current);
      }
    };
  }, [refresh]);

  const triggerSimulation = useCallback(async (scenarioId: string) => {
    setSimulatingId(scenarioId);
    try {
      await simulateScenario(scenarioId);
    } catch (simulationError) {
      setError(
        simulationError instanceof Error
          ? simulationError.message
          : "Failed to trigger simulation scenario.",
      );
    } finally {
      setSimulatingId(null);
    }
  }, []);

  const runAdaptiveSimulation = useCallback(async (message: string) => {
    setAdaptiveSimulating(true);
    setAdaptiveInput(message);
    try {
      const result = await simulateAdaptiveDefense(message);
      setAdaptiveSimulation(result);
      setError(null);
    } catch (simulationError) {
      setError(
        simulationError instanceof Error
          ? simulationError.message
          : "Failed to run adaptive defense simulation.",
      );
    } finally {
      setAdaptiveSimulating(false);
    }
  }, []);

  const analyzeAttackReport = useCallback(
    async (payload: {
      title: string;
      reportText: string;
      summary?: string;
      severity?: string;
      attackSurface?: string[];
      indicators?: string[];
      payloadExamples?: string[];
      references?: string[];
      applyChanges?: boolean;
    }) => {
      setReportCompiling(true);
      try {
        const result = await compileAttackReport(payload);
        setCompiledReport(result);
        setUsingDemoData(false);
        setError(null);
      } catch (compileError) {
        setCompiledReport({
          ...demoCompiledReport,
          applied: Boolean(payload.applyChanges),
          overlay_policy_path: payload.applyChanges
            ? demoAdaptiveStatus.overlay_policy_path
            : undefined,
        });
        setUsingDemoData(true);
        setError(
          compileError instanceof Error
            ? compileError.message
            : "Failed to analyze the attack report.",
        );
      } finally {
        setReportCompiling(false);
      }
    },
    [],
  );

  const refreshPolicyRecommendations = useCallback(async () => {
    setRecommendationLoading(true);
    try {
      const result = await recommendPolicy({
        minEvents: 5,
        includeFalsePositiveReview: true,
      });
      setPolicyRecommendations(result);
      setUsingDemoData(false);
      setError(null);
    } catch (recommendationError) {
      setPolicyRecommendations(demoPolicyRecommendations);
      setUsingDemoData(true);
      setError(
        recommendationError instanceof Error
          ? recommendationError.message
          : "Failed to generate policy recommendations.",
      );
    } finally {
      setRecommendationLoading(false);
    }
  }, []);

  const runCopilotQuery = useCallback(
    async (question: string, options?: { family?: string | null; incidentId?: string | null }) => {
      setCopilotLoading(true);
      try {
        const response = await queryDashboardCopilot(question, options);
        setCopilotResponse(response);
        setError(null);
      } catch (queryError) {
        setError(
          queryError instanceof Error
            ? queryError.message
            : "Failed to run dashboard copilot query.",
        );
      } finally {
        setCopilotLoading(false);
      }
    },
    [],
  );

  const highlights = useMemo(
    () => ({
      activeThreatScore: summary?.latest_before_after.threat_score ?? 0,
      currentProvider: summary?.current_provider ?? "openai",
    }),
    [summary],
  );

  return {
    summary,
    incidents,
    scenarios,
    connected,
    loading,
    error,
    simulatingId,
    adaptiveSimulation,
    adaptiveInput,
    adaptiveStatus,
    compiledReport,
    policyRecommendations,
    adaptiveSimulating,
    reportCompiling,
    recommendationLoading,
    copilotResponse,
    copilotLoading,
    usingDemoData,
    highlights,
    refresh,
    triggerSimulation,
    runAdaptiveSimulation,
    analyzeAttackReport,
    refreshPolicyRecommendations,
    runCopilotQuery,
    setAdaptiveInput,
  };
}
