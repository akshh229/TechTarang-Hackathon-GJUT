import type { DashboardSummary, Scenario, SocketMessage } from "../types";

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

export async function simulateScenario(scenarioId: string): Promise<void> {
  await fetchJson("/demo/simulate", {
    method: "POST",
    body: JSON.stringify({ scenario_id: scenarioId }),
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
