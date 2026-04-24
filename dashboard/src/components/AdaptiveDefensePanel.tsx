import { Radar, ShieldCheck, ShieldX, Sparkles, Workflow } from "lucide-react";

import type { AdaptiveDefenseSimulation } from "../types";

interface AdaptiveDefensePanelProps {
  input: string;
  result: AdaptiveDefenseSimulation | null;
  loading: boolean;
  onInputChange: (value: string) => void;
  onRun: (message: string) => void | Promise<void>;
}

function titleCase(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export function AdaptiveDefensePanel({
  input,
  result,
  loading,
  onInputChange,
  onRun,
}: AdaptiveDefensePanelProps) {
  const wouldBlock = result?.would_block ?? false;

  return (
    <section className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">
            Adaptive Defense Lab
          </p>
          <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
            Live countermeasure preview
          </h3>
          <p className="mt-3 max-w-2xl text-sm leading-7 text-muted">
            Paste a suspicious prompt and preview how the active adaptive-defense policy would
            classify, score, and counter it before provider execution.
          </p>
        </div>

        <div
          className={`grid h-11 w-11 place-items-center rounded-2xl border ${
            wouldBlock ? "border-danger/30 bg-danger/10 text-danger" : "border-accent/30 bg-accent/10 text-accent"
          }`}
        >
          {wouldBlock ? <ShieldX size={18} /> : <ShieldCheck size={18} />}
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_1.05fr]">
        <div className="space-y-4">
          <label className="block">
            <span className="text-[0.68rem] uppercase tracking-[0.28em] text-muted">
              Attack payload
            </span>
            <textarea
              value={input}
              onChange={(event) => onInputChange(event.target.value)}
              rows={7}
              className="mt-3 w-full rounded-[22px] border border-borderGlass/12 bg-panelSoft/80 px-4 py-4 text-sm leading-7 text-ink outline-none transition focus:border-accent/40"
              placeholder="Paste a suspicious message or attack snippet..."
            />
          </label>

          <button
            type="button"
            onClick={() => void onRun(input)}
            disabled={loading || !input.trim()}
            className="action-button inline-flex items-center gap-3 rounded-full border border-accent/25 bg-accent/10 px-5 py-3 text-sm uppercase tracking-[0.25em] text-ink disabled:cursor-wait disabled:opacity-70"
          >
            <Radar size={15} />
            {loading ? "Scanning" : "Simulate Defense"}
          </button>
        </div>

        <div
          key={
            result
              ? `${result.message_preview}-${result.threat_score}-${result.action_taken}`
              : "adaptive-defense-empty"
          }
          className={`rounded-[24px] border p-4 transition duration-300 ${
            wouldBlock
              ? "border-danger/25 bg-danger/10 threat-surge"
              : "border-accent/20 bg-accent/10"
          }`}
        >
          {!result ? (
            <div className="grid h-full min-h-[20rem] place-items-center rounded-[18px] border border-borderGlass/10 bg-white/45 px-6 text-center text-sm leading-7 text-muted">
              Run a simulation to see risk level, matched attack families, and response playbooks.
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-[0.68rem] uppercase tracking-[0.28em] text-muted">Outcome</p>
                  <div className="mt-2 flex items-center gap-3">
                    <span
                      className={`inline-flex rounded-full px-3 py-1 text-xs uppercase tracking-[0.24em] ${
                        wouldBlock ? "bg-danger/15 text-danger" : "bg-success/15 text-success"
                      }`}
                    >
                      {result.action_taken}
                    </span>
                    <span className="font-display text-3xl font-semibold text-ink">
                      {result.threat_score}
                    </span>
                  </div>
                </div>

                <div className="interactive-item rounded-[18px] border border-borderGlass/12 bg-white/55 px-4 py-3 text-right">
                  <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Model backend</p>
                  <p className="mt-2 font-display text-lg text-ink">{result.model_backend}</p>
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-3">
                <div className="interactive-item rounded-[20px] border border-borderGlass/10 bg-white/55 px-4 py-3">
                  <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Pattern</p>
                  <p className="mt-2 font-display text-2xl text-ink">
                    {result.score_breakdown.pattern_match}
                  </p>
                </div>
                <div className="interactive-item rounded-[20px] border border-borderGlass/10 bg-white/55 px-4 py-3">
                  <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Semantic</p>
                  <p className="mt-2 font-display text-2xl text-ink">
                    {result.score_breakdown.semantic_anomaly}
                  </p>
                </div>
                <div className="interactive-item rounded-[20px] border border-borderGlass/10 bg-white/55 px-4 py-3">
                  <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Session</p>
                  <p className="mt-2 font-display text-2xl text-ink">
                    {result.score_breakdown.session_replay}
                  </p>
                </div>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="interactive-item rounded-[20px] border border-borderGlass/10 bg-white/55 p-4">
                  <div className="flex items-center gap-2 text-muted">
                    <Sparkles size={15} />
                    <p className="text-[0.68rem] uppercase tracking-[0.28em]">Detected families</p>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {result.detected_families.length ? (
                      result.detected_families.map((family) => (
                        <span
                          key={family}
                          className="interactive-chip rounded-full border border-borderGlass/12 bg-panelSoft/70 px-3 py-2 text-xs uppercase tracking-[0.18em] text-ink"
                        >
                          {titleCase(family)}
                        </span>
                      ))
                    ) : (
                      <span className="text-sm text-muted">No families matched.</span>
                    )}
                  </div>
                </div>

                <div className="interactive-item rounded-[20px] border border-borderGlass/10 bg-white/55 p-4">
                  <div className="flex items-center gap-2 text-muted">
                    <Workflow size={15} />
                    <p className="text-[0.68rem] uppercase tracking-[0.28em]">Playbooks</p>
                  </div>
                  <div className="mt-3 space-y-2">
                    {result.recommended_playbooks.length ? (
                      result.recommended_playbooks.map((playbook) => (
                        <div
                          key={`${playbook.family}-${playbook.action}`}
                          className="interactive-item rounded-[16px] border border-borderGlass/10 bg-panelSoft/75 px-3 py-3"
                        >
                          <p className="text-xs uppercase tracking-[0.2em] text-accent">
                            {titleCase(playbook.action)}
                          </p>
                          <p className="mt-2 text-sm leading-6 text-ink/90">{playbook.reason}</p>
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-muted">No playbooks currently attached.</p>
                    )}
                  </div>
                </div>
              </div>

              <div className="interactive-item rounded-[20px] border border-borderGlass/10 bg-panelSoft/80 p-4">
                <p className="text-[0.68rem] uppercase tracking-[0.28em] text-muted">
                  Sanitised payload + signals
                </p>
                <p className="mt-3 text-sm leading-7 text-ink/90">{result.sanitized_input_preview}</p>
                <div className="mt-4 flex flex-wrap gap-2">
                  {result.signals.map((signal) => (
                    <span
                      key={signal}
                      className="interactive-chip rounded-full border border-borderGlass/12 bg-white/55 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.16em] text-muted"
                    >
                      {signal}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
