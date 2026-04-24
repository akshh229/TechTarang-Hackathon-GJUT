import { useEffect, useMemo, useRef } from "react";
import {
  Activity,
  Cpu,
  Orbit,
  Shield,
  ShieldAlert,
  Siren,
  TimerReset,
  Waves,
} from "lucide-react";
import gsap from "gsap";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { AttackFeedTable } from "./components/AttackFeedTable";
import { MetricCard } from "./components/MetricCard";
import { SimulatorPanel } from "./components/SimulatorPanel";
import { ThreatGauge } from "./components/ThreatGauge";
import { useSecurityDashboard } from "./hooks/useSecurityDashboard";

function formatShortTimestamp(timestamp: string) {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function App() {
  const dashboardRef = useRef<HTMLDivElement | null>(null);
  const {
    summary,
    scenarios,
    connected,
    loading,
    error,
    simulatingId,
    highlights,
    refresh,
    triggerSimulation,
  } = useSecurityDashboard();

  useEffect(() => {
    if (!dashboardRef.current) {
      return;
    }

    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (mediaQuery.matches) {
      return;
    }

    const context = gsap.context(() => {
      gsap.fromTo(
        ".reveal-card",
        { opacity: 0, y: 36, rotateX: -8 },
        {
          opacity: 1,
          y: 0,
          rotateX: 0,
          duration: 0.8,
          stagger: 0.08,
          ease: "power3.out",
        },
      );
    }, dashboardRef);

    return () => {
      context.revert();
    };
  }, [summary?.recent_records.length]);

  const riskPie = useMemo(
    () =>
      Object.entries(summary?.risk_distribution ?? {}).map(([name, value]) => ({
        name,
        value,
        fill:
          name === "RED"
            ? "var(--danger)"
            : name === "AMBER"
              ? "var(--warning)"
              : "var(--success)",
      })),
    [summary?.risk_distribution],
  );

  const piiBars = useMemo(
    () =>
      Object.entries(summary?.pii_totals ?? {}).map(([name, value]) => ({
        name: name.toUpperCase(),
        value,
      })),
    [summary?.pii_totals],
  );

  if (loading && !summary) {
    return (
      <main className="min-h-screen bg-[#05070f] px-6 py-10 text-ink">
        <div className="mx-auto max-w-7xl animate-pulse rounded-[36px] border border-white/5 bg-panel/60 p-10 shadow-glass">
          <div className="h-16 rounded-3xl bg-white/5" />
          <div className="mt-8 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <div key={index} className="h-40 rounded-[28px] bg-white/5" />
            ))}
          </div>
        </div>
      </main>
    );
  }

  if (!summary) {
    return (
      <main className="min-h-screen bg-[#05070f] px-6 py-10 text-ink">
        <div className="mx-auto max-w-4xl rounded-[36px] border border-danger/25 bg-panel/80 p-10 shadow-glass">
          <p className="text-sm uppercase tracking-[0.3em] text-danger">Dashboard unavailable</p>
          <h1 className="mt-4 font-display text-4xl font-semibold">Could not load telemetry.</h1>
          <p className="mt-4 max-w-2xl text-base leading-7 text-muted">{error}</p>
          <button
            type="button"
            onClick={() => void refresh()}
            className="mt-8 rounded-full border border-white/10 bg-white/5 px-5 py-3 text-sm uppercase tracking-[0.25em] text-ink transition hover:bg-white/10"
          >
            Retry
          </button>
        </div>
      </main>
    );
  }

  return (
    <main
      ref={dashboardRef}
      className="min-h-screen bg-[#05070f] bg-grid bg-[length:54px_54px] px-4 py-4 font-body text-ink md:px-6 md:py-6"
    >
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute left-[-12%] top-[-8%] h-80 w-80 rounded-full bg-[radial-gradient(circle_at_center,rgba(53,201,204,0.25),transparent_68%)] blur-3xl" />
        <div className="absolute right-[-8%] top-[14%] h-[28rem] w-[28rem] rounded-full bg-[radial-gradient(circle_at_center,rgba(255,106,72,0.18),transparent_70%)] blur-3xl" />
        <div className="absolute bottom-[-10%] left-[12%] h-72 w-72 rounded-full bg-[radial-gradient(circle_at_center,rgba(122,167,255,0.18),transparent_68%)] blur-3xl" />
      </div>

      <div className="relative mx-auto flex max-w-7xl flex-col gap-5">
        <section className="reveal-card overflow-hidden rounded-[34px] border border-borderGlass bg-[linear-gradient(135deg,rgba(14,20,39,0.95),rgba(9,12,24,0.82))] p-6 shadow-glass backdrop-blur-xl md:p-8">
          <div className="flex flex-col gap-8 xl:flex-row xl:items-end xl:justify-between">
            <div className="max-w-3xl">
              <div className="inline-flex items-center gap-3 rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-xs uppercase tracking-[0.28em] text-muted">
                <Shield size={14} />
                Secure AI Interaction Layer
              </div>
              <h1 className="mt-6 max-w-4xl font-display text-4xl font-semibold leading-tight md:text-5xl">
                AI firewall dashboard for SQL and multimodal attack telemetry.
              </h1>
              <p className="mt-5 max-w-3xl text-base leading-8 text-muted md:text-lg">
                Live middleware observability for prompt injection, session replay anomalies,
                PII leakage, and provider-safe request handling.
              </p>
            </div>

            <div className="grid gap-4 md:grid-cols-3 xl:min-w-[28rem]">
              <div className="rounded-[28px] border border-white/10 bg-white/[0.05] p-5">
                <p className="text-[0.68rem] uppercase tracking-[0.32em] text-muted">Socket</p>
                <div className="mt-4 flex items-center gap-3">
                  <span
                    className={`h-3 w-3 rounded-full ${connected ? "bg-success shadow-[0_0_20px_rgba(117,255,169,0.8)]" : "bg-danger shadow-[0_0_18px_rgba(255,106,72,0.8)]"}`}
                  />
                  <span className="font-display text-2xl font-semibold">
                    {connected ? "Live" : "Reconnecting"}
                  </span>
                </div>
              </div>

              <div className="rounded-[28px] border border-white/10 bg-white/[0.05] p-5">
                <p className="text-[0.68rem] uppercase tracking-[0.32em] text-muted">Provider</p>
                <p className="mt-4 font-display text-2xl font-semibold capitalize">
                  {highlights.currentProvider}
                </p>
              </div>

              <div className="rounded-[28px] border border-white/10 bg-white/[0.05] p-5">
                <p className="text-[0.68rem] uppercase tracking-[0.32em] text-muted">Active Score</p>
                <p className="mt-4 font-display text-2xl font-semibold">{highlights.activeThreatScore}</p>
              </div>
            </div>
          </div>
        </section>

        <section className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            eyebrow="Blocked attacks"
            value={summary.totals.blocked_requests.toString()}
            accent="linear-gradient(135deg, rgba(255, 106, 72, 0.28), rgba(255, 42, 109, 0.18))"
            description="Hard-denied prompt injection attempts and sessions already pushed into cooldown."
            icon={<ShieldAlert size={18} />}
          />
          <MetricCard
            eyebrow="Flagged traffic"
            value={summary.totals.flagged_requests.toString()}
            accent="linear-gradient(135deg, rgba(255, 191, 87, 0.26), rgba(255, 129, 84, 0.18))"
            description="Requests allowed through with elevated scrutiny and threat intelligence markings."
            icon={<Siren size={18} />}
          />
          <MetricCard
            eyebrow="P50 latency"
            value={`${summary.totals.p50_latency_ms} ms`}
            accent="linear-gradient(135deg, rgba(122, 167, 255, 0.26), rgba(53, 201, 204, 0.18))"
            description="Median middleware cost from ingress screening through egress sanitisation."
            icon={<TimerReset size={18} />}
          />
          <MetricCard
            eyebrow="Suspicious sessions"
            value={summary.totals.suspicious_sessions.toString()}
            accent="linear-gradient(135deg, rgba(126, 247, 177, 0.26), rgba(53, 201, 204, 0.18))"
            description="Multi-step replay and low-and-slow patterns currently being tracked by session."
            icon={<Orbit size={18} />}
          />
        </section>

        <section className="grid gap-5 xl:grid-cols-[1.15fr_0.85fr]">
          <div className="reveal-card rounded-[28px] border border-borderGlass bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Attack Curve</p>
                <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
                  Threat score over time
                </h3>
              </div>
              <div className="rounded-full border border-white/10 px-3 py-1 text-xs uppercase tracking-[0.25em] text-muted">
                Last {summary.threat_series.length}
              </div>
            </div>

            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={summary.threat_series}>
                  <defs>
                    <linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--danger)" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="var(--danger)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatShortTimestamp}
                    stroke="rgba(216,229,255,0.55)"
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="rgba(216,229,255,0.55)"
                    tickLine={false}
                    axisLine={false}
                    domain={[0, 100]}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "rgba(10, 16, 30, 0.92)",
                      border: "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 18,
                    }}
                    labelFormatter={formatShortTimestamp}
                  />
                  <Area
                    type="monotone"
                    dataKey="threat_score"
                    stroke="var(--danger)"
                    strokeWidth={2.5}
                    fill="url(#threatFill)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <ThreatGauge score={summary.latest_before_after.threat_score} />
        </section>

        <section className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr_0.9fr]">
          <div className="reveal-card rounded-[28px] border border-borderGlass bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Risk Mix</p>
                <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
                  Distribution
                </h3>
              </div>
              <Waves className="text-muted" size={18} />
            </div>

            <div className="grid gap-4 md:grid-cols-[0.95fr_1.05fr]">
              <div className="h-60">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={riskPie}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={52}
                      outerRadius={82}
                      paddingAngle={4}
                    >
                      {riskPie.map((entry) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "rgba(10, 16, 30, 0.92)",
                        border: "1px solid rgba(255,255,255,0.08)",
                        borderRadius: 18,
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-3">
                {riskPie.map((entry) => (
                  <div
                    key={entry.name}
                    className="rounded-[20px] border border-white/8 bg-white/[0.04] px-4 py-3"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span
                          className="h-3 w-3 rounded-full"
                          style={{ backgroundColor: entry.fill }}
                        />
                        <span className="text-sm uppercase tracking-[0.24em] text-muted">
                          {entry.name}
                        </span>
                      </div>
                      <span className="font-display text-2xl">{entry.value}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="reveal-card rounded-[28px] border border-borderGlass bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">PII Redaction</p>
                <h3 className="mt-3 font-display text-2xl font-semibold text-ink">Masked fields</h3>
              </div>
              <Cpu className="text-muted" size={18} />
            </div>

            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={piiBars}>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                  <XAxis
                    dataKey="name"
                    stroke="rgba(216,229,255,0.55)"
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="rgba(216,229,255,0.55)"
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "rgba(10, 16, 30, 0.92)",
                      border: "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 18,
                    }}
                  />
                  <Bar dataKey="value" radius={[12, 12, 0, 0]} fill="var(--accent)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="reveal-card rounded-[28px] border border-borderGlass bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Top Signals</p>
                <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
                  Trigger patterns
                </h3>
              </div>
              <Activity className="text-muted" size={18} />
            </div>

            <div className="space-y-3">
              {summary.top_patterns.map((pattern) => (
                <div
                  key={pattern.pattern}
                  className="rounded-[20px] border border-white/8 bg-white/[0.04] px-4 py-3"
                >
                  <div className="flex items-center justify-between gap-4">
                    <p className="text-sm leading-6 text-ink">{pattern.pattern}</p>
                    <span className="rounded-full bg-danger/10 px-3 py-1 text-xs uppercase tracking-[0.2em] text-danger">
                      {pattern.count}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="grid gap-5 xl:grid-cols-[1.15fr_0.85fr]">
          <AttackFeedTable records={summary.recent_records} />

          <div className="grid gap-5">
            <div className="reveal-card rounded-[28px] border border-borderGlass bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
              <div className="mb-5 flex items-center justify-between">
                <div>
                  <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Sanitiser View</p>
                  <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
                    Before / after
                  </h3>
                </div>
                <div className="rounded-full border border-white/10 px-3 py-1 text-xs uppercase tracking-[0.25em] text-muted">
                  {summary.latest_before_after.action_taken}
                </div>
              </div>

              <div className="grid gap-4">
                <div className="rounded-[22px] border border-danger/20 bg-danger/10 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.28em] text-danger">Raw input</p>
                  <p className="mt-3 text-sm leading-7 text-ink/90">
                    {summary.latest_before_after.raw_input || "No traffic yet."}
                  </p>
                </div>
                <div className="rounded-[22px] border border-accent/20 bg-accent/10 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.28em] text-accent">Sanitised input</p>
                  <p className="mt-3 text-sm leading-7 text-ink/90">
                    {summary.latest_before_after.sanitized_input || "Awaiting sanitised payload."}
                  </p>
                </div>
                <div className="rounded-[22px] border border-success/20 bg-success/10 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.28em] text-success">Sanitised response</p>
                  <p className="mt-3 text-sm leading-7 text-ink/90">
                    {summary.latest_before_after.sanitized_response ||
                      "Blocked requests stop before provider execution."}
                  </p>
                </div>
              </div>
            </div>

            <div className="reveal-card rounded-[28px] border border-borderGlass bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
              <div className="mb-5 flex items-center justify-between">
                <div>
                  <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Watchlist</p>
                  <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
                    Session anomalies
                  </h3>
                </div>
                <Orbit className="text-muted" size={18} />
              </div>

              <div className="space-y-3">
                {summary.suspicious_sessions.length === 0 ? (
                  <div className="rounded-[22px] border border-white/8 bg-white/[0.04] px-4 py-6 text-sm text-muted">
                    No suspicious sessions yet. Launch a red-team scenario to light this panel up.
                  </div>
                ) : (
                  summary.suspicious_sessions.map((session) => (
                    <div
                      key={session.session_id}
                      className="rounded-[22px] border border-white/8 bg-white/[0.04] px-4 py-4"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <p className="font-display text-lg text-ink">{session.session_id}</p>
                          <p className="mt-1 text-sm text-muted">
                            {session.risky_request_count} risky requests, {session.blocked_request_count} blocks
                          </p>
                        </div>
                        <span
                          className={`rounded-full px-3 py-1 text-xs uppercase tracking-[0.24em] ${
                            session.cooldown_active
                              ? "bg-danger/12 text-danger"
                              : "bg-warning/12 text-warning"
                          }`}
                        >
                          {session.cooldown_active ? "Cooldown" : "Suspicious"}
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </section>

        <section className="grid gap-5 xl:grid-cols-[0.95fr_1.05fr]">
          <SimulatorPanel
            scenarios={scenarios}
            simulatingId={simulatingId}
            onTrigger={triggerSimulation}
          />

          <div className="reveal-card rounded-[28px] border border-borderGlass bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Latency Monitor</p>
                <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
                  Middleware overhead
                </h3>
              </div>
              <div className="rounded-full border border-white/10 px-3 py-1 text-xs uppercase tracking-[0.25em] text-muted">
                Threshold {summary.latency_threshold_ms} ms
              </div>
            </div>

            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={summary.latency_series}>
                  <defs>
                    <linearGradient id="latencyFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.55} />
                      <stop offset="95%" stopColor="var(--accent)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatShortTimestamp}
                    stroke="rgba(216,229,255,0.55)"
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="rgba(216,229,255,0.55)"
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "rgba(10, 16, 30, 0.92)",
                      border: "1px solid rgba(255,255,255,0.08)",
                      borderRadius: 18,
                    }}
                    labelFormatter={formatShortTimestamp}
                  />
                  <Area
                    type="monotone"
                    dataKey="latency_ms"
                    stroke="var(--accent)"
                    strokeWidth={2.5}
                    fill="url(#latencyFill)"
                  />
                  <Area
                    type="monotone"
                    dataKey="threshold_ms"
                    stroke="var(--warning)"
                    strokeDasharray="6 6"
                    fillOpacity={0}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        {error ? (
          <div className="reveal-card rounded-[24px] border border-danger/20 bg-danger/10 px-5 py-4 text-sm text-danger">
            {error}
          </div>
        ) : null}
      </div>
    </main>
  );
}
