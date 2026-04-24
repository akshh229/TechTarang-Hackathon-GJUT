import { useEffect, useMemo, useRef, useState } from "react";
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
import { ScrollTrigger } from "gsap/ScrollTrigger";
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

import { AdaptiveDefensePanel } from "./components/AdaptiveDefensePanel";
import { AttackFeedTable } from "./components/AttackFeedTable";
import { DashboardCopilotPanel } from "./components/DashboardCopilotPanel";
import { IncidentsPanel } from "./components/IncidentsPanel";
import { MetricCard } from "./components/MetricCard";
import { SimulatorPanel } from "./components/SimulatorPanel";
import { ThreatGauge } from "./components/ThreatGauge";
import { useSecurityDashboard } from "./hooks/useSecurityDashboard";
import { getIncidentRecords } from "./lib/api";
import type { Incident, TelemetryRecord } from "./types";

gsap.registerPlugin(ScrollTrigger);

function formatShortTimestamp(timestamp: string) {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatIntentConfidence(confidence?: number) {
  if (typeof confidence !== "number") {
    return "--";
  }
  return `${Math.round(confidence * 100)}%`;
}

const chartGridStroke = "rgba(123, 96, 74, 0.12)";
const chartAxisStroke = "rgba(92, 74, 58, 0.62)";
const chartTooltipStyle = {
  background: "rgba(255, 248, 239, 0.98)",
  border: "1px solid rgba(123, 96, 74, 0.12)",
  borderRadius: 18,
  color: "rgb(43, 35, 29)",
};

export default function App() {
  const dashboardRef = useRef<HTMLDivElement | null>(null);
  const feedSectionRef = useRef<HTMLDivElement | null>(null);
  const {
    summary,
    incidents,
    scenarios,
    connected,
    loading,
    error,
    simulatingId,
    adaptiveSimulation,
    adaptiveInput,
    adaptiveSimulating,
    copilotResponse,
    copilotLoading,
    highlights,
    refresh,
    triggerSimulation,
    runAdaptiveSimulation,
    runCopilotQuery,
    setAdaptiveInput,
  } = useSecurityDashboard();
  const [selectedFamily, setSelectedFamily] = useState<string | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [incidentRecords, setIncidentRecords] = useState<TelemetryRecord[]>([]);
  const [incidentLoading, setIncidentLoading] = useState(false);

  useEffect(() => {
    const dashboard = dashboardRef.current;
    if (!dashboard) {
      return;
    }

    const handlePointerMove = (event: PointerEvent) => {
      const rect = dashboard.getBoundingClientRect();
      dashboard.style.setProperty("--pointer-x", `${event.clientX - rect.left}px`);
      dashboard.style.setProperty("--pointer-y", `${event.clientY - rect.top}px`);
    };

    dashboard.addEventListener("pointermove", handlePointerMove);

    return () => {
      dashboard.removeEventListener("pointermove", handlePointerMove);
    };
  }, []);

  useEffect(() => {
    if (!dashboardRef.current) {
      return;
    }

    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (mediaQuery.matches) {
      return;
    }

    const context = gsap.context(() => {
      gsap.utils.toArray<HTMLElement>(".reveal-card").forEach((card, index) => {
        gsap.set(card, {
          transformPerspective: 1200,
          transformOrigin: "center top",
        });

        gsap.fromTo(
          card,
          { opacity: 0, y: 40, rotateX: -10 },
          {
            opacity: 1,
            y: 0,
            rotateX: 0,
            duration: 0.85,
            delay: index < 4 ? index * 0.06 : 0,
            ease: "power3.out",
            scrollTrigger: {
              trigger: card,
              start: "top 88%",
              once: true,
            },
            onComplete: () => {
              gsap.set(card, { clearProps: "transform" });
            },
          },
        );
      });

      gsap.to(".hero-float", {
        y: (index) => (index % 2 === 0 ? -10 : 10),
        duration: 3.6,
        ease: "sine.inOut",
        repeat: -1,
        yoyo: true,
        stagger: 0.18,
      });

      gsap.to(".ambient-orb", {
        yPercent: (index) => (index % 2 === 0 ? -5 : 6),
        xPercent: (index) => (index === 1 ? -4 : 4),
        duration: 10,
        ease: "sine.inOut",
        repeat: -1,
        yoyo: true,
        stagger: 0.35,
      });

      gsap.fromTo(
        ".adaptive-defense-result",
        { opacity: 0.6, scale: 0.98, y: 18 },
        {
          opacity: 1,
          scale: 1,
          y: 0,
          duration: 0.7,
          ease: "power2.out",
          scrollTrigger: {
            trigger: ".adaptive-defense-result",
            start: "top 88%",
            once: true,
          },
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

  const familyOptions = useMemo(
    () => Array.from(new Set(incidents.map((incident) => incident.family))).sort(),
    [incidents],
  );

  const filteredIncidents = useMemo(
    () =>
      selectedFamily
        ? incidents.filter((incident) => incident.family === selectedFamily)
        : incidents,
    [incidents, selectedFamily],
  );

  const filteredRecentRecords = useMemo(
    () =>
      summary?.recent_records.filter(
        (record) => !selectedFamily || record.incident_family === selectedFamily,
      ) ?? [],
    [selectedFamily, summary?.recent_records],
  );

  useEffect(() => {
    if (!selectedIncident) {
      return;
    }

    const refreshedIncident = incidents.find(
      (incident) => incident.incident_id === selectedIncident.incident_id,
    );

    if (!refreshedIncident) {
      setSelectedIncident(null);
      setIncidentRecords([]);
      return;
    }

    if (selectedFamily && refreshedIncident.family !== selectedFamily) {
      setSelectedIncident(null);
      setIncidentRecords([]);
      return;
    }

    setSelectedIncident(refreshedIncident);
  }, [incidents, selectedFamily, selectedIncident]);

  const visibleRecords = selectedIncident ? incidentRecords : filteredRecentRecords;

  if (loading && !summary) {
    return (
      <main className="min-h-screen bg-[#f7efe3] px-6 py-10 text-ink">
        <div className="mx-auto max-w-7xl animate-pulse rounded-[36px] border border-borderGlass/10 bg-panel/60 p-10 shadow-glass">
          <div className="h-16 rounded-3xl bg-panelSoft/80" />
          <div className="mt-8 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <div key={index} className="h-40 rounded-[28px] bg-panelSoft/80" />
            ))}
          </div>
        </div>
      </main>
    );
  }

  if (!summary) {
    return (
      <main className="min-h-screen bg-[#f7efe3] px-6 py-10 text-ink">
        <div className="mx-auto max-w-4xl rounded-[36px] border border-danger/25 bg-panel/80 p-10 shadow-glass">
          <p className="text-sm uppercase tracking-[0.3em] text-danger">Dashboard unavailable</p>
          <h1 className="mt-4 font-display text-4xl font-semibold">Could not load telemetry.</h1>
          <p className="mt-4 max-w-2xl text-base leading-7 text-muted">{error}</p>
          <button
            type="button"
            onClick={() => void refresh()}
            className="action-button mt-8 rounded-full border border-borderGlass/15 bg-panelSoft/80 px-5 py-3 text-sm uppercase tracking-[0.25em] text-ink transition hover:bg-panelSoft"
          >
            Retry
          </button>
        </div>
      </main>
    );
  }

  const latestRecord = summary.recent_records[0];

  async function handleIncidentSelection(incident: Incident) {
    if (selectedIncident?.incident_id === incident.incident_id) {
      setSelectedIncident(null);
      setIncidentRecords([]);
      return;
    }

    setSelectedFamily(incident.family);
    setSelectedIncident(incident);
    setIncidentLoading(true);

    try {
      const response = await getIncidentRecords(incident.incident_id);
      setIncidentRecords(response.records);
      window.requestAnimationFrame(() => {
        feedSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } finally {
      setIncidentLoading(false);
    }
  }

  function handleFamilyChange(family: string | null) {
    setSelectedFamily(family);
    if (!family || selectedIncident?.family !== family) {
      setSelectedIncident(null);
      setIncidentRecords([]);
    }
  }

  return (
    <main
      ref={dashboardRef}
      className="dashboard-shell min-h-screen bg-[#f7efe3] bg-grid bg-[length:54px_54px] px-4 py-4 font-body text-ink md:px-6 md:py-6"
    >
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="ambient-orb absolute left-[-12%] top-[-8%] h-80 w-80 rounded-full bg-[radial-gradient(circle_at_center,rgba(53,201,204,0.16),transparent_68%)] blur-3xl" />
        <div className="ambient-orb absolute right-[-8%] top-[14%] h-[28rem] w-[28rem] rounded-full bg-[radial-gradient(circle_at_center,rgba(255,106,72,0.12),transparent_70%)] blur-3xl" />
        <div className="ambient-orb absolute bottom-[-10%] left-[12%] h-72 w-72 rounded-full bg-[radial-gradient(circle_at_center,rgba(255,191,87,0.14),transparent_68%)] blur-3xl" />
      </div>

      <div className="relative mx-auto flex max-w-7xl flex-col gap-5">
        <section className="reveal-card overflow-hidden rounded-[34px] border border-borderGlass/15 bg-[linear-gradient(135deg,rgba(255,251,245,0.94),rgba(243,230,214,0.9))] p-6 shadow-glass backdrop-blur-xl md:p-8">
          <div className="flex flex-col gap-8 xl:flex-row xl:items-end xl:justify-between">
            <div className="max-w-3xl">
              <div className="interactive-chip inline-flex items-center gap-3 rounded-full border border-borderGlass/15 bg-white/55 px-4 py-2 text-xs uppercase tracking-[0.28em] text-muted">
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
              <div className="hero-float rounded-[28px] border border-borderGlass/12 bg-panelSoft/80 p-5">
                <p className="text-[0.68rem] uppercase tracking-[0.32em] text-muted">Socket</p>
                <div className="mt-4 flex items-center gap-3">
                  <span
                    className={`status-dot h-3 w-3 rounded-full ${connected ? "bg-success shadow-[0_0_20px_rgba(117,255,169,0.8)]" : "bg-danger shadow-[0_0_18px_rgba(255,106,72,0.8)]"}`}
                  />
                  <span className="font-display text-2xl font-semibold">
                    {connected ? "Live" : "Reconnecting"}
                  </span>
                </div>
              </div>

              <div className="hero-float rounded-[28px] border border-borderGlass/12 bg-panelSoft/80 p-5">
                <p className="text-[0.68rem] uppercase tracking-[0.32em] text-muted">Provider</p>
                <p className="mt-4 font-display text-2xl font-semibold capitalize">
                  {highlights.currentProvider}
                </p>
              </div>

              <div className="hero-float rounded-[28px] border border-borderGlass/12 bg-panelSoft/80 p-5">
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
          <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Attack Curve</p>
                <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
                  Threat score over time
                </h3>
              </div>
              <div className="rounded-full border border-borderGlass/12 bg-white/55 px-3 py-1 text-xs uppercase tracking-[0.25em] text-muted">
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
                  <CartesianGrid stroke={chartGridStroke} vertical={false} />
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatShortTimestamp}
                    stroke={chartAxisStroke}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke={chartAxisStroke}
                    tickLine={false}
                    axisLine={false}
                    domain={[0, 100]}
                  />
                  <Tooltip
                    contentStyle={chartTooltipStyle}
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
          <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
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
                      contentStyle={chartTooltipStyle}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-3">
                {riskPie.map((entry) => (
                  <div
                    key={entry.name}
                    className="interactive-item rounded-[20px] border border-borderGlass/10 bg-panelSoft/70 px-4 py-3"
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

          <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
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
                  <CartesianGrid stroke={chartGridStroke} vertical={false} />
                  <XAxis
                    dataKey="name"
                    stroke={chartAxisStroke}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke={chartAxisStroke}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip contentStyle={chartTooltipStyle} />
                  <Bar dataKey="value" radius={[12, 12, 0, 0]} fill="var(--accent)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
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
                  className="interactive-item rounded-[20px] border border-borderGlass/10 bg-panelSoft/70 px-4 py-3"
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

        <DashboardCopilotPanel
          loading={copilotLoading}
          response={copilotResponse}
          selectedFamily={selectedFamily}
          selectedIncident={selectedIncident}
          onSubmit={(question) =>
            runCopilotQuery(question, {
              family: selectedFamily,
              incidentId: selectedIncident?.incident_id ?? null,
            })
          }
        />

        <section
          ref={feedSectionRef}
          className="grid gap-5 xl:grid-cols-[1.15fr_0.85fr]"
        >
          <AttackFeedTable
            records={incidentLoading ? [] : visibleRecords}
            activeIncidentLabel={selectedIncident?.label ?? null}
            selectedFamily={selectedFamily}
            highlightedRequestIds={selectedIncident?.related_request_ids ?? []}
            onClearDrilldown={
              selectedIncident
                ? () => {
                    setSelectedIncident(null);
                    setIncidentRecords([]);
                  }
                : undefined
            }
          />

          <div className="grid gap-5">
            <IncidentsPanel
              incidents={filteredIncidents}
              familyOptions={familyOptions}
              selectedFamily={selectedFamily}
              selectedIncidentId={selectedIncident?.incident_id ?? null}
              onFamilyChange={handleFamilyChange}
              onSelectIncident={handleIncidentSelection}
            />

            <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
              <div className="mb-5 flex items-center justify-between">
                <div>
                  <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Sanitiser View</p>
                  <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
                    Before / after
                  </h3>
                </div>
                <div className="rounded-full border border-borderGlass/12 bg-white/55 px-3 py-1 text-xs uppercase tracking-[0.25em] text-muted">
                  {summary.latest_before_after.action_taken}
                </div>
              </div>

              <div className="grid gap-4">
                <div className="interactive-item rounded-[22px] border border-danger/20 bg-danger/10 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.28em] text-danger">Raw input</p>
                  <p className="mt-3 text-sm leading-7 text-ink/90">
                    {summary.latest_before_after.raw_input || "No traffic yet."}
                  </p>
                </div>
                <div className="interactive-item rounded-[22px] border border-accent/20 bg-accent/10 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.28em] text-accent">Sanitised input</p>
                  <p className="mt-3 text-sm leading-7 text-ink/90">
                    {summary.latest_before_after.sanitized_input || "Awaiting sanitised payload."}
                  </p>
                </div>
                <div className="interactive-item rounded-[22px] border border-success/20 bg-success/10 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.28em] text-success">Sanitised response</p>
                  <p className="mt-3 text-sm leading-7 text-ink/90">
                    {summary.latest_before_after.sanitized_response ||
                      "Blocked requests stop before provider execution."}
                  </p>
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  <div className="interactive-item rounded-[22px] border border-borderGlass/10 bg-panelSoft/70 p-4">
                    <p className="text-[0.68rem] uppercase tracking-[0.28em] text-muted">
                      Intent routing
                    </p>
                    <p className="mt-3 font-display text-xl text-ink">
                      {latestRecord?.sql_intent_token || "UNKNOWN_INTENT"}
                    </p>
                    <p className="mt-2 text-sm text-muted">
                      {latestRecord?.intent_source || "rule"} with{" "}
                      {formatIntentConfidence(latestRecord?.intent_confidence)} confidence
                    </p>
                  </div>

                  <div className="interactive-item rounded-[22px] border border-borderGlass/10 bg-panelSoft/70 p-4">
                    <p className="text-[0.68rem] uppercase tracking-[0.28em] text-muted">
                      Firewall explanation
                    </p>
                    <p className="mt-3 text-sm leading-7 text-ink/90">
                      {latestRecord?.block_explanation ||
                        "Latest request passed normally, so no human-readable block explanation was needed."}
                    </p>
                  </div>
                </div>

                {latestRecord?.safe_rewrite ? (
                  <div className="interactive-item rounded-[22px] border border-accent/20 bg-accent/10 p-4">
                    <p className="text-[0.68rem] uppercase tracking-[0.28em] text-accent">
                      Suggested safe rewrite
                    </p>
                    <p className="mt-3 text-sm leading-7 text-ink/90">{latestRecord.safe_rewrite}</p>
                  </div>
                ) : null}
              </div>
            </div>

            <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
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
                  <div className="rounded-[22px] border border-borderGlass/10 bg-panelSoft/70 px-4 py-6 text-sm text-muted">
                    No suspicious sessions yet. Launch a red-team scenario to light this panel up.
                  </div>
                ) : (
                  summary.suspicious_sessions.map((session) => (
                    <div
                      key={session.session_id}
                      className="interactive-item rounded-[22px] border border-borderGlass/10 bg-panelSoft/70 px-4 py-4"
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

          <div className="reveal-card rounded-[28px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-[0.68rem] uppercase tracking-[0.35em] text-muted">Latency Monitor</p>
                <h3 className="mt-3 font-display text-2xl font-semibold text-ink">
                  Middleware overhead
                </h3>
              </div>
              <div className="rounded-full border border-borderGlass/12 bg-white/55 px-3 py-1 text-xs uppercase tracking-[0.25em] text-muted">
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
                  <CartesianGrid stroke={chartGridStroke} vertical={false} />
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatShortTimestamp}
                    stroke={chartAxisStroke}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke={chartAxisStroke}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip contentStyle={chartTooltipStyle} labelFormatter={formatShortTimestamp} />
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

        <div className="adaptive-defense-result">
          <AdaptiveDefensePanel
            input={adaptiveInput}
            result={adaptiveSimulation}
            loading={adaptiveSimulating}
            onInputChange={setAdaptiveInput}
            onRun={runAdaptiveSimulation}
          />
        </div>

        {error ? (
          <div className="reveal-card rounded-[24px] border border-danger/20 bg-danger/10 px-5 py-4 text-sm text-danger">
            {error}
          </div>
        ) : null}
      </div>
    </main>
  );
}
