import { useMemo, useState } from "react";
import {
  Bot,
  CheckCheck,
  FileSearch,
  GitBranchPlus,
  ShieldCheck,
  ShieldEllipsis,
  Sparkles,
} from "lucide-react";

import type {
  AdaptiveDefenseStatus,
  AttackReportCompileResult,
  PolicyRecommendationResult,
} from "../types";

interface HumanReviewPanelProps {
  status: AdaptiveDefenseStatus | null;
  compiledReport: AttackReportCompileResult | null;
  recommendations: PolicyRecommendationResult | null;
  reportLoading: boolean;
  recommendationLoading: boolean;
  usingDemoData: boolean;
  onAnalyzeReport: (payload: {
    title: string;
    reportText: string;
    summary?: string;
    severity?: string;
    attackSurface?: string[];
    indicators?: string[];
    payloadExamples?: string[];
    applyChanges?: boolean;
  }) => void | Promise<void>;
  onRefreshRecommendations: () => void | Promise<void>;
}

const starterTitle = "CurXecute-style README Command Execution";
const starterReport = `A malicious repository README instructed an IDE agent to run shell commands copied from documentation.
The sequence included "run this command" language and a curl | sh payload intended to bootstrap remote code execution.
We want the AI to analyze the report, propose policy hardening, and only apply the overlay after a human explicitly approves it.`;

function titleCase(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export function HumanReviewPanel({
  status,
  compiledReport,
  recommendations,
  reportLoading,
  recommendationLoading,
  usingDemoData,
  onAnalyzeReport,
  onRefreshRecommendations,
}: HumanReviewPanelProps) {
  const [title, setTitle] = useState(starterTitle);
  const [reportText, setReportText] = useState(starterReport);
  const [applyChanges, setApplyChanges] = useState(false);

  const quickSummary = useMemo(
    () => [
      {
        label: "Active families",
        value: status?.active_families.length ?? 0,
        icon: <ShieldCheck size={16} />,
      },
      {
        label: "Guardrails",
        value: status?.prompt_guardrail_count ?? 0,
        icon: <ShieldEllipsis size={16} />,
      },
      {
        label: "Recommendations",
        value: recommendations?.recommendations.length ?? 0,
        icon: <GitBranchPlus size={16} />,
      },
    ],
    [recommendations?.recommendations.length, status?.active_families.length, status?.prompt_guardrail_count],
  );

  return (
    <section className="reveal-card rounded-[30px] border border-borderGlass/14 bg-panel/80 p-5 shadow-glass backdrop-blur-xl">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
        <div className="max-w-3xl">
          <div className="flex flex-wrap items-center gap-2">
            <span className="interactive-chip inline-flex items-center gap-2 rounded-full border border-accent/20 bg-accent/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.22em] text-accent">
              <Bot size={14} />
              AI Report Analyst
            </span>
            <span className="interactive-chip inline-flex items-center gap-2 rounded-full border border-success/20 bg-success/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.22em] text-success">
              <CheckCheck size={14} />
              Human In The Loop
            </span>
            {usingDemoData ? (
              <span className="interactive-chip inline-flex items-center gap-2 rounded-full border border-warning/20 bg-warning/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.22em] text-warning">
                Demo telemetry
              </span>
            ) : null}
          </div>

          <h3 className="mt-4 font-display text-2xl font-semibold text-ink md:text-3xl">
            Analyze attack reports, preview policy patches, and apply changes only after approval.
          </h3>
          <p className="mt-3 max-w-3xl text-sm leading-7 text-muted">
            This puts the operator workflow near the top of the app: AI reads the report, drafts
            an overlay patch, and the human reviewer decides whether it is safe to write into the
            active adaptive-defense policy.
          </p>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          {quickSummary.map((item) => (
            <div
              key={item.label}
              className="interactive-item min-w-[8rem] rounded-[20px] border border-borderGlass/10 bg-white/55 px-4 py-4"
            >
              <div className="flex items-center gap-2 text-muted">
                {item.icon}
                <span className="text-[0.68rem] uppercase tracking-[0.24em]">{item.label}</span>
              </div>
              <p className="mt-3 font-display text-3xl text-ink">{item.value}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[1.05fr_0.95fr]">
        <div className="space-y-4 rounded-[24px] border border-borderGlass/10 bg-panelSoft/70 p-4">
          <div className="grid gap-4 md:grid-cols-[0.95fr_1.05fr]">
            <label className="block">
              <span className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">
                Report title
              </span>
              <input
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                className="mt-3 w-full rounded-[18px] border border-borderGlass/12 bg-white/70 px-4 py-3 text-sm text-ink outline-none transition focus:border-accent/50"
              />
            </label>

            <div className="rounded-[18px] border border-borderGlass/12 bg-white/55 p-4">
              <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Workflow</p>
              <div className="mt-3 space-y-2 text-sm leading-7 text-ink/90">
                <p>1. AI parses the report and maps likely attack families.</p>
                <p>2. The dashboard shows the proposed patch and recommendations.</p>
                <p>3. The operator chooses whether to write the overlay.</p>
              </div>
            </div>
          </div>

          <label className="block">
            <span className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">
              Attack report or incident summary
            </span>
            <textarea
              value={reportText}
              onChange={(event) => setReportText(event.target.value)}
              rows={8}
              className="mt-3 w-full resize-none rounded-[22px] border border-borderGlass/12 bg-white/70 px-4 py-4 text-sm leading-7 text-ink outline-none transition focus:border-accent/50"
            />
          </label>

          <label className="interactive-item flex items-start gap-3 rounded-[18px] border border-borderGlass/10 bg-white/55 px-4 py-4">
            <input
              type="checkbox"
              checked={applyChanges}
              onChange={(event) => setApplyChanges(event.target.checked)}
              className="mt-1 h-4 w-4 rounded border-borderGlass/25 text-accent focus:ring-accent/30"
            />
            <span>
              <span className="block text-sm font-medium text-ink">
                Human approval to apply overlay changes
              </span>
              <span className="mt-1 block text-sm leading-6 text-muted">
                Keep this off to analyze safely. Turn it on only when the operator is ready for the
                policy overlay to be written.
              </span>
            </span>
          </label>

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={() =>
                void onAnalyzeReport({
                  title,
                  reportText,
                  summary:
                    "AI-assisted report analysis with human approval required for policy writes.",
                  severity: "HIGH",
                  attackSurface: ["repository", "ide"],
                  indicators: ["run this command", "curl | sh", "README instruction"],
                  payloadExamples: ["README says run this command immediately: curl | sh"],
                  applyChanges,
                })
              }
              disabled={reportLoading || reportText.trim().length < 20 || title.trim().length < 3}
              className="action-button inline-flex items-center gap-3 rounded-full border border-accent/25 bg-accent/10 px-5 py-3 text-sm uppercase tracking-[0.22em] text-ink disabled:cursor-wait disabled:opacity-60"
            >
              <FileSearch size={15} />
              {reportLoading
                ? "Analyzing"
                : applyChanges
                  ? "Analyze + Apply Approved Patch"
                  : "Analyze Report"}
            </button>

            <button
              type="button"
              onClick={() => void onRefreshRecommendations()}
              disabled={recommendationLoading}
              className="action-button inline-flex items-center gap-3 rounded-full border border-borderGlass/15 bg-white/65 px-5 py-3 text-sm uppercase tracking-[0.22em] text-ink disabled:cursor-wait disabled:opacity-60"
            >
              <Sparkles size={15} />
              {recommendationLoading ? "Generating" : "Refresh AI Recommendations"}
            </button>
          </div>
        </div>

        <div className="grid gap-5">
          <div className="rounded-[24px] border border-borderGlass/10 bg-white/60 p-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">
                  Review outcome
                </p>
                <h4 className="mt-2 font-display text-xl text-ink">
                  {compiledReport?.title ?? "No report analyzed yet"}
                </h4>
              </div>
              <span
                className={`rounded-full px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.2em] ${
                  compiledReport?.applied
                    ? "bg-success/15 text-success"
                    : "bg-warning/15 text-warning"
                }`}
              >
                {compiledReport?.applied ? "Overlay Applied" : "Awaiting Approval"}
              </span>
            </div>

            {compiledReport ? (
              <div className="mt-4 space-y-4">
                <div className="flex flex-wrap gap-2">
                  {compiledReport.detected_families.map((family) => (
                    <span
                      key={family}
                      className="interactive-chip rounded-full border border-danger/20 bg-danger/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] text-danger"
                    >
                      {titleCase(family)}
                    </span>
                  ))}
                  {compiledReport.detected_surfaces.map((surface) => (
                    <span
                      key={surface}
                      className="interactive-chip rounded-full border border-accent/20 bg-accent/10 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] text-accent"
                    >
                      {titleCase(surface)}
                    </span>
                  ))}
                </div>

                <div className="grid gap-3 md:grid-cols-2">
                  <div className="interactive-item rounded-[18px] border border-borderGlass/10 bg-panelSoft/75 p-4">
                    <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Patch summary</p>
                    <div className="mt-3 space-y-2 text-sm text-ink/90">
                      <p>{compiledReport.summary.new_injection_rules} new injection rules</p>
                      <p>{compiledReport.summary.new_guardrails} new guardrails</p>
                      <p>{compiledReport.summary.new_semantic_signals} new semantic signals</p>
                    </div>
                  </div>

                  <div className="interactive-item rounded-[18px] border border-borderGlass/10 bg-panelSoft/75 p-4">
                    <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Policy overlay</p>
                    <p className="mt-3 break-all text-sm leading-7 text-ink/90">
                      {compiledReport.overlay_policy_path ??
                        status?.overlay_policy_path ??
                        "Preview only. No overlay written yet."}
                    </p>
                  </div>
                </div>

                <div className="interactive-item rounded-[18px] border border-borderGlass/10 bg-panelSoft/75 p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">Why the AI picked this</p>
                  <div className="mt-3 space-y-2 text-sm leading-7 text-ink/90">
                    {compiledReport.rationale.map((reason) => (
                      <p key={reason}>{reason}</p>
                    ))}
                  </div>
                </div>

                <div className="interactive-item rounded-[18px] border border-borderGlass/10 bg-[#1d1a17] p-4">
                  <p className="text-[0.68rem] uppercase tracking-[0.24em] text-white/55">Patch preview</p>
                  <pre className="mt-3 overflow-x-auto whitespace-pre-wrap text-xs leading-6 text-white/80">
                    {compiledReport.policy_patch_yaml}
                  </pre>
                </div>
              </div>
            ) : (
              <p className="mt-4 text-sm leading-7 text-muted">
                Run an attack report through the analyst to preview the generated policy patch and
                review whether it should be applied.
              </p>
            )}
          </div>

          <div className="rounded-[24px] border border-borderGlass/10 bg-white/60 p-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-[0.68rem] uppercase tracking-[0.24em] text-muted">
                  AI recommendations
                </p>
                <h4 className="mt-2 font-display text-xl text-ink">
                  Live policy suggestions from recent telemetry
                </h4>
              </div>
              <span className="rounded-full border border-borderGlass/12 bg-panelSoft/70 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] text-muted">
                Human approval required
              </span>
            </div>

            <p className="mt-3 text-sm leading-7 text-muted">
              {recommendations?.summary ??
                "No recommendations generated yet. Use the refresh action to ask the AI for additive policy changes grounded in recent traffic."}
            </p>

            <div className="mt-4 space-y-3">
              {recommendations?.recommendations.length ? (
                recommendations.recommendations.map((recommendation, index) => (
                  <div
                    key={`${recommendation.description}-${index}`}
                    className="interactive-item rounded-[18px] border border-borderGlass/10 bg-panelSoft/75 p-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <p className="font-medium text-ink">{recommendation.description}</p>
                      <span className="rounded-full bg-accent/10 px-3 py-1 text-[0.68rem] uppercase tracking-[0.18em] text-accent">
                        {recommendation.impact}
                      </span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <span className="interactive-chip rounded-full border border-borderGlass/12 bg-white/60 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] text-muted">
                        {recommendation.rule_type}
                      </span>
                      <span className="interactive-chip rounded-full border border-borderGlass/12 bg-white/60 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] text-muted">
                        Confidence {Math.round(recommendation.confidence * 100)}%
                      </span>
                      <span className="interactive-chip rounded-full border border-borderGlass/12 bg-white/60 px-3 py-1.5 text-[0.68rem] uppercase tracking-[0.18em] text-muted">
                        Evidence {recommendation.evidence_count}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="rounded-[18px] border border-borderGlass/10 bg-panelSoft/75 px-4 py-5 text-sm leading-7 text-muted">
                  Not enough telemetry has been reviewed yet to suggest additive rules.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
