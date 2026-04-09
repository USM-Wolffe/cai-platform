"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { MetricCard } from "@/components/common/MetricCard";
import { Wifi, Shield } from "lucide-react";

interface TopSource {
  src_ip: string;
  count: number;
  pct: number;
}

interface Protocol {
  protocol: string;
  count: number;
  pct: number;
}

interface AnalyticsData {
  total_events: number;
  top_sources: TopSource[];
  segments: Array<{ segment: string; count: number; pct: number }>;
  protocols: Protocol[];
  date_range?: { start?: string; end?: string };
  peak_day?: string;
  peak_events?: number;
}

interface AnalyticsSummaryProps {
  data: AnalyticsData;
  loading?: boolean;
}

const BLUE_SHADES = [
  "#3b82f6",
  "#2563eb",
  "#1d4ed8",
  "#1e40af",
  "#1e3a8a",
];

export function AnalyticsSummary({ data, loading }: AnalyticsSummaryProps) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {[0, 1].map((i) => (
          <div key={i} className="h-48 animate-pulse rounded-xl border border-border bg-card" />
        ))}
      </div>
    );
  }

  const topSources = data.top_sources.slice(0, 8);
  const protocols = data.protocols.slice(0, 6);
  const daysSpanned =
    data.date_range?.start && data.date_range?.end
      ? Math.max(
          1,
          Math.round(
            (new Date(data.date_range.end).getTime() -
              new Date(data.date_range.start).getTime()) /
              86_400_000,
          ),
        )
      : null;

  return (
    <div className="flex flex-col gap-4">
      {/* Metric row */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          label="Total Events"
          value={formatNum(data.total_events)}
          icon={<Wifi className="size-4" />}
        />
        <MetricCard
          label="Unique Attackers"
          value={data.top_sources.length}
          accent={data.top_sources.length > 5}
        />
        <MetricCard
          label="Peak Day"
          value={data.peak_day ? formatDate(data.peak_day) : "—"}
          sub={data.peak_events ? `${formatNum(data.peak_events)} events` : undefined}
          accent
        />
        <MetricCard
          label="Period"
          value={daysSpanned !== null ? `${daysSpanned}d` : "—"}
          icon={<Shield className="size-4" />}
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Top source IPs */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="mb-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Top Attacking IPs
          </h3>
          {topSources.length === 0 ? (
            <p className="text-xs text-muted-foreground">No data available.</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart
                data={topSources.map((s) => ({ name: s.src_ip, events: s.count, pct: s.pct }))}
                layout="vertical"
                margin={{ left: 0, right: 24, top: 0, bottom: 0 }}
              >
                <XAxis type="number" tick={{ fill: "#71717a", fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={110}
                  tick={{ fill: "#a1a1aa", fontSize: 10, fontFamily: "monospace" }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "#18181b",
                    border: "1px solid #3f3f46",
                    borderRadius: "8px",
                    fontSize: 12,
                  }}
                  itemStyle={{ color: "#e4e4e7" }}
                  formatter={(v, _n, p) => [`${formatNum(Number(v))} (${(p.payload as {pct?: number}).pct?.toFixed(1)}%)`, "Events"]}
                />
                <Bar dataKey="events" radius={[0, 4, 4, 0]}>
                  {topSources.map((_, i) => (
                    <Cell key={i} fill={BLUE_SHADES[i % BLUE_SHADES.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Protocol breakdown */}
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="mb-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Protocol Distribution
          </h3>
          {protocols.length === 0 ? (
            <p className="text-xs text-muted-foreground">No data available.</p>
          ) : (
            <div className="space-y-3">
              {protocols.map((p, i) => (
                <div key={p.protocol} className="flex flex-col gap-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium uppercase text-foreground">{p.protocol}</span>
                    <span className="tabular-nums text-muted-foreground">
                      {formatNum(p.count)} ({p.pct?.toFixed(1)}%)
                    </span>
                  </div>
                  <div className="relative h-2 overflow-hidden rounded-full bg-secondary">
                    <div
                      className="absolute inset-y-0 left-0 rounded-full transition-all"
                      style={{
                        width: `${Math.min(p.pct ?? 0, 100)}%`,
                        background: BLUE_SHADES[i % BLUE_SHADES.length],
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function formatNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  } catch {
    return iso;
  }
}
