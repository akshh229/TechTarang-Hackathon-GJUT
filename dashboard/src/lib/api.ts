import type {
  AdaptiveDefenseSimulation,
  DashboardCopilotResponse,
  DashboardSummary,
  IncidentDrilldown,
  Incident,
  Scenario,
  SocketMessage,
} from "../types";

const apiBaseUrl =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") ?? "http://127.0.0.1:8000";

const wsBaseUrl =
  import.meta.env.VITE_WS_BASE_URL?.replace(/\/$/, "") ??
  apiBaseUrl.replace(/^http/, "ws");

async function fetchJson<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(errorBody || `Request failed with status ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  return fetchJson<DashboardSummary>("/dashboard/summary");
}

export async function getScenarios(): Promise<Scenario[]> {
  const response = await fetchJson<{ scenarios: Scenario[] }>("/dashboard/scenarios");
  return response.scenarios;
}

export async function getDashboardIncidents(): Promise<Incident[]> {
  const response = await fetchJson<{ incidents: Incident[] }>("/dashboard/incidents");
  return response.incidents;
}

export async function getIncidentRecords(incidentId: string): Promise<IncidentDrilldown> {
  return fetchJson<IncidentDrilldown>(`/dashboard/incidents/${incidentId}/records`);
}

export async function queryDashboardCopilot(
  question: string,
  options?: { family?: string | null; incidentId?: string | null },
): Promise<DashboardCopilotResponse> {
  return fetchJson<DashboardCopilotResponse>("/dashboard/copilot/query", {
    method: "POST",
    body: JSON.stringify({
      question,
      family: options?.family ?? null,
      incident_id: options?.incidentId ?? null,
    }),
  });
}

export async function simulateScenario(scenarioId: string): Promise<void> {
  await fetchJson("/demo/simulate", {
    method: "POST",
    body: JSON.stringify({ scenario_id: scenarioId }),
  });
}

export async function simulateAdaptiveDefense(
  message: string,
): Promise<AdaptiveDefenseSimulation> {
  return fetchJson<AdaptiveDefenseSimulation>("/adaptive-defense/simulate", {
    method: "POST",
    body: JSON.stringify({ message }),
  });
}

export function connectTelemetry(
  onMessage: (message: SocketMessage) => void,
  onStatusChange: (connected: boolean) => void,
): () => void {
  const socket = new WebSocket(`${wsBaseUrl}/ws/events`);

  socket.addEventListener("open", () => {
    onStatusChange(true);
  });

  socket.addEventListener("message", (event) => {
    const parsedMessage = JSON.parse(event.data) as SocketMessage;
    onMessage(parsedMessage);
  });

  socket.addEventListener("close", () => {
    onStatusChange(false);
  });

  socket.addEventListener("error", () => {
    onStatusChange(false);
  });

  return () => {
    socket.close();
  };
}
