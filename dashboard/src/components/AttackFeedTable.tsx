import { Fragment, useState } from "react";
import type { TelemetryRecord } from "../types";

interface AttackFeedTableProps {
  records: TelemetryRecord[];
  activeIncidentLabel?: string | null;
  selectedFamily?: string | null;
  highlightedRequestIds?: string[];
  onClearDrilldown?: () => void;
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

function intentLabel(record: TelemetryRecord) {
  if (!record.intent_source) {
    return record.sql_intent_token;
  }

  const confidence =
    typeof record.intent_confidence === "number"
      ? `${Math.round(record.intent_confidence * 100)}%`
      : "--";
  return `${record.sql_intent_token} · ${record.intent_source} · ${confidence}`;
}

function readableFamily(family: string) {
  return family.replace(/_/g, " ");
}

export function AttackFeedTable({
  records,
  activeIncidentLabel,
  selectedFamily,
  highlightedRequestIds = [],
  onClearDrilldown,
}: AttackFeedTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const highlightedSet = new Set(highlightedRequestIds);

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

      {activeIncidentLabel || selectedFamily ? (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-[20px] border border-accent/20 bg-accent/10 px-4 py-3 text-xs uppercase tracking-[0.18em] text-accent">
          {activeIncidentLabel ? <span>Drilldown {activeIncidentLabel}</span> : null}
          {!activeIncidentLabel && selectedFamily ? (
            <span>Family {readableFamily(selectedFamily)}</span>
          ) : null}
          {onClearDrilldown ? (
            <button
              type="button"
              onClick={onClearDrilldown}
              className="rounded-full border border-accent/20 bg-black/10 px-3 py-1 text-[0.65rem] text-accent transition hover:bg-black/20"
            >
              Clear focus
            </button>
          ) : null}
        </div>
      ) : null}

      <div className="overflow-hidden rounded-3xl border border-white/8">
        <div className="grid grid-cols-[1.2fr_1.45fr_0.9fr_0.9fr_1.35fr] gap-3 border-b border-white/8 bg-white/5 px-4 py-3 text-[0.68rem] uppercase tracking-[0.25em] text-muted">
          <span>Timestamp</span>
          <span>Session / Intent</span>
          <span>Risk</span>
          <span>Score</span>
          <span>Action / AI</span>
        </div>
        <div className="max-h-[24rem] overflow-y-auto">
          {records.length === 0 ? (
            <div className="px-4 py-8 text-sm text-muted">
              No recent records match the current drilldown.
            </div>
          ) : null}
          {records.map((record) => {
            const isHighlighted = highlightedSet.size === 0 || highlightedSet.has(record.request_id);
            return (
            <Fragment key={record.request_id}>
              <button
                type="button"
                onClick={() =>
                  setExpandedId((current) => (current === record.request_id ? null : record.request_id))
                }
                className={`grid w-full grid-cols-[1.2fr_1.45fr_0.9fr_0.9fr_1.35fr] gap-3 border-b px-4 py-4 text-left text-sm text-ink/90 transition hover:bg-white/[0.03] ${
                  isHighlighted
                    ? "border-accent/15 bg-accent/[0.03]"
                    : "border-white/6"
                }`}
              >
                <div>
                  <p>{new Date(record.timestamp).toLocaleTimeString()}</p>
                  <p className="mt-1 text-xs text-muted">{record.provider}</p>
                </div>
                <div>
                  <p>{record.session_id}</p>
                  <p className="mt-1 text-xs text-muted">{intentLabel(record)}</p>
                  <p className="mt-1 text-[0.65rem] uppercase tracking-[0.18em] text-accent/90">
                    {readableFamily(record.incident_family || "unknown")}
                  </p>
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
                    {record.block_explanation || record.injection_signals[0] || "No signal"}
                  </p>
                </div>
              </button>

              {expandedId === record.request_id ? (
                <div className="border-b border-white/6 bg-[#0b1020]/80 px-4 py-4">
                  <div className="flex flex-wrap gap-2">
                    <span className="rounded-full border border-white/10 bg-white/[0.05] px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.16em] text-muted">
                      Intent {record.intent_source ?? "rule"}
                    </span>
                    <span className="rounded-full border border-accent/20 bg-accent/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.16em] text-accent">
                      Family {readableFamily(record.incident_family)}
                    </span>
                    <span className="rounded-full border border-accent/20 bg-accent/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.16em] text-accent">
                      Confidence {typeof record.intent_confidence === "number" ? `${Math.round(record.intent_confidence * 100)}%` : "--"}
                    </span>
                    {record.block_explanation ? (
                      <span className="rounded-full border border-danger/20 bg-danger/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.16em] text-danger">
                        Explanation ready
                      </span>
                    ) : null}
                    {record.safe_rewrite ? (
                      <span className="rounded-full border border-success/20 bg-success/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.16em] text-success">
                        Safe rewrite available
                      </span>
                    ) : null}
                  </div>

                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    <div className="rounded-[18px] border border-white/8 bg-white/[0.03] p-4">
                      <p className="text-[0.68rem] uppercase tracking-[0.2em] text-muted">Explanation</p>
                      <p className="mt-3 text-sm leading-7 text-ink/90">
                        {record.block_explanation || "No block explanation for this event."}
                      </p>
                    </div>
                    <div className="rounded-[18px] border border-white/8 bg-white/[0.03] p-4">
                      <p className="text-[0.68rem] uppercase tracking-[0.2em] text-muted">Safe rewrite</p>
                      <p className="mt-3 text-sm leading-7 text-ink/90">
                        {record.safe_rewrite || "No rewrite suggested for this event."}
                      </p>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    <div className="rounded-[18px] border border-white/8 bg-white/[0.03] p-4">
                      <p className="text-[0.68rem] uppercase tracking-[0.2em] text-muted">Input preview</p>
                      <p className="mt-3 text-sm leading-7 text-ink/90">{record.input_preview}</p>
                    </div>
                    <div className="rounded-[18px] border border-white/8 bg-white/[0.03] p-4">
                      <p className="text-[0.68rem] uppercase tracking-[0.2em] text-muted">Sanitized input</p>
                      <p className="mt-3 text-sm leading-7 text-ink/90">{record.sanitized_input_preview}</p>
                    </div>
                  </div>
                </div>
              ) : null}
            </Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
}
