import type { ReactNode } from "react";

interface MetricCardProps {
  eyebrow: string;
  value: string;
  accent: string;
  description: string;
  icon: ReactNode;
}

export function MetricCard({
  eyebrow,
  value,
  accent,
  description,
  icon,
}: MetricCardProps) {
  return (
    <article className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
      <div className="mb-4 flex items-start justify-between">
        <div>
          <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">{eyebrow}</p>
          <h3 className="mt-3 font-display text-3xl font-semibold text-ink">{value}</h3>
        </div>
        <div
          className="interactive-item grid h-11 w-11 place-items-center rounded-2xl border border-borderGlass/12 text-ink"
          style={{ background: accent }}
        >
          {icon}
        </div>
      </div>
      <p className="max-w-[22ch] text-sm leading-6 text-muted">{description}</p>
    </article>
  );
}
