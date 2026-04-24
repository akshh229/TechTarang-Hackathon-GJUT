import { useState } from "react";
import type { DashboardCopilotResponse, Incident } from "../types";

interface DashboardCopilotPanelProps {
  loading: boolean;
  response: DashboardCopilotResponse | null;
  selectedFamily: string | null;
  selectedIncident: Incident | null;
  onSubmit: (question: string) => void | Promise<void>;
}

const starterQuestions = [
  "Why did blocked traffic spike today?",
  "Which family looks most active right now?",
  "What should the analyst check next?",
];

function readableFamily(family: string) {
  return family.replace(/_/g, " ");
}

export function DashboardCopilotPanel({
  loading,
  response,
  selectedFamily,
  selectedIncident,
  onSubmit,
}: DashboardCopilotPanelProps) {
  const [question, setQuestion] = useState("Why did blocked traffic spike today?");

  const scopeLabel = selectedIncident
    ? selectedIncident.label
    : selectedFamily
      ? readableFamily(selectedFamily)
      : "all recent incidents";

  return (
    <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="max-w-2xl">
          <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Dashboard Copilot</p>
          <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
            Ask over incidents and recent records
          </h3>
          <p className="mt-3 text-sm leading-7 text-muted">
            Grounded in the current dashboard window. Scope is {scopeLabel}.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          {selectedFamily ? (
            <span className="rounded-full border border-accent/20 bg-accent/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] text-accent">
              Family {readableFamily(selectedFamily)}
            </span>
          ) : null}
          {selectedIncident ? (
            <span className="rounded-full border border-danger/20 bg-danger/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] text-danger">
              Incident focus
            </span>
          ) : null}
        </div>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-[22px] border border-borderGlass/10 bg-panelSoft/70 p-4">
          <div className="flex flex-wrap gap-2">
            {starterQuestions.map((starter) => (
              <button
                key={starter}
                type="button"
                onClick={() => setQuestion(starter)}
                className="rounded-full border border-borderGlass/12 bg-white/55 px-3 py-1.5 text-xs uppercase tracking-[0.18em] text-muted transition hover:bg-white/75 hover:text-ink"
              >
                {starter}
              </button>
            ))}
          </div>

          <label className="mt-4 block text-[0.68rem] uppercase tracking-[0.24em] text-muted">
            Analyst prompt
          </label>
          <textarea
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            rows={3}
            className="mt-3 w-full resize-none rounded-[20px] border border-borderGlass/12 bg-white/70 px-4 py-3 text-sm leading-7 text-ink outline-none transition focus:border-accent/50"
            placeholder="Ask about spikes, sessions, tool execution, or top risky signals."
          />

          <div className="mt-4 flex items-center justify-between gap-3">
            <p className="text-xs uppercase tracking-[0.18em] text-muted">
              Uses incidents plus recent records only
            </p>
            <button
              type="button"
              onClick={() => onSubmit(question.trim())}
              disabled={loading || question.trim().length < 3}
              className="rounded-full border border-accent/30 bg-accent/10 px-4 py-2 text-xs uppercase tracking-[0.24em] text-accent transition hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Thinking" : "Run query"}
            </button>
          </div>
        </div>

        <div className="rounded-[22px] border border-borderGlass/10 bg-white/60 p-4">
          <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Response</p>
          {response ? (
            <>
              <p className="mt-3 text-sm leading-7 text-ink/90">{response.answer}</p>

              <div className="mt-4 flex flex-wrap gap-2">
                {response.supporting_metrics.map((metric) => (
                  <span
                    key={metric.label}
                    className="rounded-full border border-borderGlass/12 bg-panelSoft/70 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] text-muted"
                  >
                    {metric.label}: {metric.value}
                  </span>
                ))}
              </div>

              <div className="mt-4 grid gap-4 md:grid-cols-2">
                <div>
                  <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Cited incidents</p>
                  <div className="mt-3 space-y-2">
                    {response.cited_incidents.map((incident) => (
                      <div
                        key={incident.incident_id}
                        className="rounded-[18px] border border-borderGlass/10 bg-panelSoft/65 px-3 py-3 text-sm text-ink/90"
                      >
                        {incident.label}
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Cited records</p>
                  <div className="mt-3 space-y-2">
                    {response.cited_records.map((record) => (
                      <div
                        key={record.request_id}
                        className="rounded-[18px] border border-borderGlass/10 bg-panelSoft/65 px-3 py-3 text-sm text-ink/90"
                      >
                        {record.request_id.slice(0, 8)} · {record.action_taken} · {record.risk_level}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="mt-4 rounded-[18px] border border-success/20 bg-success/10 p-4">
                <p className="text-[0.68rem] uppercase tracking-[0.24em] text-success">Next actions</p>
                <div className="mt-3 space-y-2 text-sm leading-7 text-ink/90">
                  {response.suggested_next_actions.map((action) => (
                    <p key={action}>{action}</p>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <p className="mt-3 text-sm leading-7 text-muted">
              Ask a question to get a grounded summary with cited incidents and records.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
