import type { TelemetryRecord } from "../types";

interface AttackFeedTableProps {
  records: TelemetryRecord[];
}

function toneClasses(riskLevel: string) {
  if (riskLevel === "RED") {
    return "bg-danger/15 text-danger ring-danger/30";
  }
  if (riskLevel === "AMBER") {
    return "bg-warning/15 text-warning ring-warning/30";
  }
  return "bg-success/15 text-success ring-success/30";
}

export function AttackFeedTable({ records }: AttackFeedTableProps) {
  return (
    <div className="reveal-card rounded-[28px] border border-borderGlass bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Live Feed</p>
          <h3 className="mt-3 font-display text-2xl font-semibold text-ink">Incoming traffic</h3>
        </div>
        <div className="rounded-full border border-white/10 px-3 py-1 text-xs uppercase tracking-[0.25em] text-muted">
          Last {records.length}
        </div>
      </div>

      <div className="overflow-hidden rounded-3xl border border-white/8">
        <div className="grid grid-cols-[1.4fr_1fr_0.9fr_0.9fr_1.2fr] gap-3 border-b border-white/8 bg-white/5 px-4 py-3 text-[0.68rem] uppercase tracking-[0.25em] text-muted">
          <span>Timestamp</span>
          <span>Session</span>
          <span>Risk</span>
          <span>Score</span>
          <span>Action</span>
        </div>
        <div className="max-h-[24rem] overflow-y-auto">
          {records.map((record) => (
            <div
              key={record.request_id}
              className="grid grid-cols-[1.4fr_1fr_0.9fr_0.9fr_1.2fr] gap-3 border-b border-white/6 px-4 py-4 text-sm text-ink/90 last:border-b-0"
            >
              <div>
                <p>{new Date(record.timestamp).toLocaleTimeString()}</p>
                <p className="mt-1 text-xs text-muted">{record.provider}</p>
              </div>
              <div>
                <p>{record.session_id}</p>
                <p className="mt-1 text-xs text-muted">{record.sql_intent_token}</p>
              </div>
              <div>
                <span
                  className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] ring-1 ${toneClasses(record.risk_level)}`}
                >
                  {record.risk_level}
                </span>
              </div>
              <div>
                <p className="font-display text-xl">{record.threat_score}</p>
                <p className="text-xs text-muted">{record.latency_ms} ms</p>
              </div>
              <div>
                <p>{record.action_taken}</p>
                <p className="mt-1 text-xs text-muted">
                  {record.injection_signals[0] ?? "No signal"}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
