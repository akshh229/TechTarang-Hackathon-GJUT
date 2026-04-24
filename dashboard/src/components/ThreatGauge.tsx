import type { CSSProperties } from "react";
import { PolarAngleAxis, RadialBar, RadialBarChart, ResponsiveContainer } from "recharts";

interface ThreatGaugeProps {
  score: number;
}

export function ThreatGauge({ score }: ThreatGaugeProps) {
  const clampedScore = Math.max(0, Math.min(score, 100));
  const tone =
    clampedScore >= 60 ? "var(--danger)" : clampedScore >= 30 ? "var(--warning)" : "var(--success)";
  const stance = clampedScore >= 60 ? "Block" : clampedScore >= 30 ? "Flag" : "Pass";

  return (
    <div
      className="reveal-card threat-gauge-shell rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl"
      style={{ "--gauge-tone": tone } as CSSProperties}
    >
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Threat Gauge</p>
          <h3 className="mt-3 font-display text-2xl font-semibold text-ink">Composite score</h3>
        </div>
        <div className="rounded-full border border-borderGlass/12 bg-white/55 px-3 py-1 text-xs uppercase tracking-[0.25em] text-muted">
          0-100
        </div>
      </div>

      <div className="relative h-56">
        <div className="threat-gauge-ring" />
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            innerRadius="55%"
            outerRadius="100%"
            data={[{ score: clampedScore, fill: tone }]}
            startAngle={210}
            endAngle={-30}
            barSize={18}
          >
            <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
            <RadialBar dataKey="score" cornerRadius={18} background />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-display text-5xl font-semibold text-ink">{clampedScore}</span>
          <span className="mt-2 text-sm uppercase tracking-[0.25em] text-muted">{stance}</span>
        </div>
      </div>
    </div>
  );
}
