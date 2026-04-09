"use client";

import { useEffect, useState } from "react";
import { RotateCcw, CheckCircle2, AlertTriangle, TrendingUp } from "lucide-react";
import { RiskBadge } from "@/components/common/RiskBadge";
import { MetricCard } from "@/components/common/MetricCard";
import { AnalyticsSummary } from "./AnalyticsSummary";
import { DDoSSuitePanel } from "./DDoSSuitePanel";
import type { WatchGuardResult } from "@/lib/types";

const CLIENT_ID = process.env.NEXT_PUBLIC_DEFAULT_CLIENT_ID ?? "egs";

interface AnalyticsData {
  total_events: number;
  top_sources: Array<{ src_ip: string; count: number; pct: number }>;
  segments: Array<{ segment: string; count: number; pct: number }>;
  protocols: Array<{ protocol: string; count: number; pct: number }>;
  by_day: Array<{ date: string; count: number }>;
  peak_day?: string;
  peak_events?: number;
  date_range?: { start?: string; end?: string };
}

interface InvestigationResultsProps {
  result: WatchGuardResult;
  onReset: () => void;
}

export function InvestigationResults({ result, onReset }: InvestigationResultsProps) {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [analyticsLoading, setAnalyticsLoading] = useState(true);

  // Load analytics asynchronously after results appear
  useEffect(() => {
    setAnalyticsLoading(true);
    fetch("/ui/api/analytics", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        workspace_id: result.workspace_id,
        client_id: CLIENT_ID,
      }),
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => setAnalytics(data))
      .catch(() => setAnalytics(null))
      .finally(() => setAnalyticsLoading(false));
  }, [result.workspace_id]);

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-lg font-semibold text-foreground">{result.workspace_id}</h2>
            <RiskBadge severity={result.overall_severity} />
            {result.incident_detected ? (
              <span className="inline-flex items-center gap-1 rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-xs text-red-400">
                <AlertTriangle className="size-3" /> Incident detected
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-400">
                <CheckCircle2 className="size-3" /> Clean
              </span>
            )}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Case {result.case_id} · Run {result.run_id} · Confidence{" "}
            {Math.round(result.confidence * 100)}%
          </p>
        </div>
        <button
          onClick={onReset}
          className="flex shrink-0 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        >
          <RotateCcw className="size-3.5" /> New investigation
        </button>
      </div>

      {/* Summary metrics */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          label="Severity"
          value={result.overall_severity.toUpperCase()}
          accent={["critical", "high"].includes(result.overall_severity)}
        />
        <MetricCard
          label="NIST Phase"
          value={result.nist_phase}
          icon={<TrendingUp className="size-4" />}
        />
        <MetricCard label="Top Attacker" value={result.top_attacker_ip ?? "—"} />
        <MetricCard
          label="Multi-stage"
          value={result.multi_stage_attack ? "Yes" : "No"}
          accent={result.multi_stage_attack}
        />
      </div>

      {/* Analytics charts — loads after main result */}
      {(analyticsLoading || analytics) && (
        <AnalyticsSummary data={analytics ?? emptyAnalytics()} loading={analyticsLoading} />
      )}

      {/* DDoS suite panel — collapsible */}
      <DDoSSuitePanel
        byDay={analytics?.by_day ?? []}
        segments={analytics?.segments ?? []}
        loading={analyticsLoading}
      />

      {/* Incident categories */}
      {result.incident_categories.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Incident Categories
          </h3>
          <div className="flex flex-wrap gap-2">
            {result.incident_categories.map((cat) => (
              <span
                key={cat}
                className="rounded-full border border-orange-500/30 bg-orange-500/10 px-3 py-1 text-xs font-medium text-orange-400"
              >
                {cat}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Evidence summary */}
      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Evidence Summary
        </h3>
        <p className="text-sm leading-relaxed text-foreground">{result.evidence_summary}</p>
      </div>

      {/* Recommended actions */}
      {result.recommended_actions.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Recommended Actions
          </h3>
          <ul className="space-y-2">
            {result.recommended_actions.map((action, i) => (
              <li key={i} className="flex gap-2.5 text-sm text-foreground">
                <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-medium text-primary">
                  {i + 1}
                </span>
                {action}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function emptyAnalytics(): AnalyticsData {
  return {
    total_events: 0,
    top_sources: [],
    segments: [],
    protocols: [],
    by_day: [],
  };
}
