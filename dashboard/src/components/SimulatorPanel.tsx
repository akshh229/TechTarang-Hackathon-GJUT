import { Play, ShieldAlert } from "lucide-react";

import type { Scenario } from "../types";

interface SimulatorPanelProps {
  scenarios: Scenario[];
  simulatingId: string | null;
  onTrigger: (scenarioId: string) => void | Promise<void>;
}

export function SimulatorPanel({
  scenarios,
  simulatingId,
  onTrigger,
}: SimulatorPanelProps) {
  return (
    <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
      <div className="mb-5 flex items-start justify-between">
        <div>
          <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Red-Team Console</p>
          <h3 className="mt-3 font-display text-2xl font-semibold text-ink">Demo scenarios</h3>
        </div>
        <div className="grid h-11 w-11 place-items-center rounded-2xl border border-danger/30 bg-danger/10 text-danger">
          <ShieldAlert size={18} />
        </div>
      </div>

      <div className="space-y-3">
        {scenarios.map((scenario) => {
          const active = simulatingId === scenario.id;
          return (
            <button
              key={scenario.id}
              type="button"
              onClick={() => void onTrigger(scenario.id)}
              disabled={active}
              className="interactive-item group flex w-full items-center justify-between rounded-[22px] border border-borderGlass/10 bg-panelSoft/70 px-4 py-4 text-left transition duration-300 hover:border-accent/30 hover:bg-panelSoft disabled:cursor-wait disabled:opacity-70"
            >
              <div>
                <p className="font-display text-lg font-medium text-ink">{scenario.title}</p>
                <p className="mt-1 text-sm leading-6 text-muted">{scenario.description}</p>
              </div>
              <span className="interactive-chip inline-flex items-center gap-2 rounded-full border border-borderGlass/12 bg-white/55 px-3 py-2 text-xs uppercase tracking-[0.25em] text-ink">
                <Play size={14} />
                {active ? "Running" : "Launch"}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
