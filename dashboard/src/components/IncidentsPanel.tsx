import type { Incident } from "../types";

interface IncidentsPanelProps {
  incidents: Incident[];
  familyOptions: string[];
  selectedFamily: string | null;
  selectedIncidentId: string | null;
  onFamilyChange: (family: string | null) => void;
  onSelectIncident: (incident: Incident) => void;
}

function formatTime(timestamp: string) {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function readableFamily(family: string) {
  return family.replace(/_/g, " ");
}

export function IncidentsPanel({
  incidents,
  familyOptions,
  selectedFamily,
  selectedIncidentId,
  onFamilyChange,
  onSelectIncident,
}: IncidentsPanelProps) {
  return (
    <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Incident Clusters</p>
          <h3 className="mt-3 font-display text-2xl font-semibold text-ink">Active campaigns</h3>
        </div>
        <div className="rounded-full border border-borderGlass/12 bg-white/55 px-3 py-1 text-xs uppercase tracking-[0.25em] text-muted">
          {incidents.length} clusters
        </div>
      </div>

      <div className="mb-5 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onFamilyChange(null)}
          className={`interactive-chip rounded-full border px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] transition ${
            selectedFamily === null
              ? "border-accent/30 bg-accent/10 text-accent"
              : "border-borderGlass/12 bg-white/55 text-muted hover:bg-white/75 hover:text-ink"
          }`}
        >
          All families
        </button>
        {familyOptions.map((family) => (
          <button
            key={family}
            type="button"
            onClick={() => onFamilyChange(family)}
            className={`interactive-chip rounded-full border px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] transition ${
              selectedFamily === family
                ? "border-accent/30 bg-accent/10 text-accent"
                : "border-borderGlass/12 bg-white/55 text-muted hover:bg-white/75 hover:text-ink"
            }`}
          >
            {readableFamily(family)}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        {incidents.length === 0 ? (
          <div className="rounded-[22px] border border-borderGlass/10 bg-panelSoft/70 px-4 py-6 text-sm text-muted">
            {selectedFamily
              ? `No incidents match ${readableFamily(selectedFamily)} in the current window.`
              : "No flagged or blocked incident clusters yet. Run a few scenarios to populate this view."}
          </div>
        ) : (
          incidents.map((incident) => (
            <button
              type="button"
              key={incident.incident_id}
              onClick={() => onSelectIncident(incident)}
              className={`interactive-item w-full rounded-[22px] border p-4 text-left transition ${
                selectedIncidentId === incident.incident_id
                  ? "border-accent/30 bg-accent/10"
                  : "border-borderGlass/10 bg-panelSoft/70 hover:bg-panelSoft"
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="font-display text-lg text-ink">{incident.label}</p>
                  <p className="mt-1 text-sm text-muted">
                    {incident.event_count} events across {incident.affected_sessions} sessions
                  </p>
                </div>
                <div className="rounded-full border border-danger/20 bg-danger/10 px-3 py-1 text-xs uppercase tracking-[0.2em] text-danger">
                  Severity {incident.severity_score}
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <span className="interactive-chip rounded-full border border-borderGlass/12 bg-white/55 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.16em] text-muted">
                  {incident.family}
                </span>
                {incident.top_signals.map((signal) => (
                  <span
                    key={`${incident.incident_id}-${signal.signal}`}
                    className="interactive-chip rounded-full border border-accent/20 bg-accent/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.16em] text-accent"
                  >
                    {signal.signal} · {signal.count}
                  </span>
                ))}
              </div>

              <div className="mt-4 grid gap-4 md:grid-cols-2">
                <div className="interactive-item rounded-[18px] border border-borderGlass/10 bg-white/55 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.2em] text-muted">Latest explanation</p>
                  <p className="mt-3 text-sm leading-7 text-ink/90">
                    {incident.latest_explanation || "No explanation stored for this cluster."}
                  </p>
                </div>
                <div className="interactive-item rounded-[18px] border border-borderGlass/10 bg-white/55 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.2em] text-muted">Sample payload</p>
                  <p className="mt-3 text-sm leading-7 text-ink/90">{incident.sample_input}</p>
                </div>
              </div>

              {incident.latest_safe_rewrite ? (
                <div className="interactive-item mt-4 rounded-[18px] border border-success/20 bg-success/10 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.2em] text-success">Safe rewrite</p>
                  <p className="mt-3 text-sm leading-7 text-ink/90">{incident.latest_safe_rewrite}</p>
                </div>
              ) : null}

              <div className="mt-4 flex items-center justify-between text-xs uppercase tracking-[0.18em] text-muted">
                <span>First {formatTime(incident.first_seen)}</span>
                <span>Last {formatTime(incident.last_seen)}</span>
                <span>Avg score {incident.avg_threat_score}</span>
              </div>
            </button>
          ))
        )}
      </div>
    </div>
  );
}
