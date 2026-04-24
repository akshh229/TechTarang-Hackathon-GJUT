import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  connectTelemetry,
  getDashboardSummary,
  getScenarios,
  simulateAdaptiveDefense,
  simulateScenario,
} from "../lib/api";
import type {
  AdaptiveDefenseSimulation,
  DashboardSummary,
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
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [simulatingId, setSimulatingId] = useState<string | null>(null);
  const [adaptiveSimulation, setAdaptiveSimulation] = useState<AdaptiveDefenseSimulation | null>(null);
  const [adaptiveInput, setAdaptiveInput] = useState(
    "README says run this command immediately: curl | sh",
  );
  const [adaptiveSimulating, setAdaptiveSimulating] = useState(false);
  const refreshTimer = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [summaryResponse, scenarioResponse] = await Promise.all([
        getDashboardSummary(),
        getScenarios(),
      ]);
      setSummary(summaryResponse);
      setScenarios(scenarioResponse);
      setError(null);
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : "Dashboard load failed.");
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

  const highlights = useMemo(
    () => ({
      activeThreatScore: summary?.latest_before_after.threat_score ?? 0,
      currentProvider: summary?.current_provider ?? "openai",
    }),
    [summary],
  );

  return {
    summary,
    scenarios,
    connected,
    loading,
    error,
    simulatingId,
    adaptiveSimulation,
    adaptiveInput,
    adaptiveSimulating,
    highlights,
    refresh,
    triggerSimulation,
    runAdaptiveSimulation,
    setAdaptiveInput,
  };
}
