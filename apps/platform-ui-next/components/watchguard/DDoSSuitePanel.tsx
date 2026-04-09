"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import { cn } from "@/lib/utils";

interface DayPoint {
  date: string;
  count: number;
}

interface Segment {
  segment: string;
  count: number;
  pct: number;
}

interface DDoSSuitePanelProps {
  byDay: DayPoint[];
  segments: Segment[];
  loading?: boolean;
}

export function DDoSSuitePanel({ byDay, segments, loading }: DDoSSuitePanelProps) {
  const [open, setOpen] = useState(false);

  return (
    <div className="rounded-xl border border-border bg-card overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-5 py-4 text-sm font-medium text-foreground hover:bg-accent/30 transition-colors"
      >
        <span>DDoS Detailed Analysis</span>
        <ChevronDown
          className={cn("size-4 text-muted-foreground transition-transform", open && "rotate-180")}
        />
      </button>

      {open && (
        <div className="border-t border-border px-5 pb-5 pt-4 flex flex-col gap-6">
          {loading ? (
            <div className="h-40 animate-pulse rounded-lg bg-muted" />
          ) : (
            <>
              {/* Temporal chart */}
              {byDay.length > 0 && (
                <div>
                  <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Events per Day
                  </h4>
                  <ResponsiveContainer width="100%" height={180}>
                    <LineChart
                      data={byDay.map((d) => ({
                        date: formatShortDate(d.date),
                        events: d.count,
                      }))}
                      margin={{ left: 0, right: 8, top: 4, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                      <XAxis
                        dataKey="date"
                        tick={{ fill: "#71717a", fontSize: 10 }}
                        tickLine={false}
                        axisLine={false}
                      />
                      <YAxis
                        tick={{ fill: "#71717a", fontSize: 10 }}
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={(v) => formatNum(v)}
                        width={48}
                      />
                      <Tooltip
                        contentStyle={{
                          background: "#18181b",
                          border: "1px solid #3f3f46",
                          borderRadius: "8px",
                          fontSize: 12,
                        }}
                        itemStyle={{ color: "#e4e4e7" }}
                        formatter={(v) => [formatNum(Number(v)), "Events"]}
                      />
                      <Line
                        type="monotone"
                        dataKey="events"
                        stroke="#3b82f6"
                        strokeWidth={2}
                        dot={false}
                        activeDot={{ r: 4, fill: "#3b82f6" }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* /16 Segments */}
              {segments.length > 0 && (
                <div>
                  <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Top /16 Network Segments
                  </h4>
                  <div className="space-y-2">
                    {segments.slice(0, 8).map((seg, i) => (
                      <div key={seg.segment} className="flex items-center gap-3 text-xs">
                        <span className="w-36 shrink-0 font-mono text-muted-foreground">
                          {seg.segment}
                        </span>
                        <div className="relative flex-1 h-1.5 overflow-hidden rounded-full bg-secondary">
                          <div
                            className="absolute inset-y-0 left-0 rounded-full bg-blue-500"
                            style={{ width: `${Math.min(seg.pct ?? 0, 100)}%`, opacity: 1 - i * 0.08 }}
                          />
                        </div>
                        <span className="w-16 shrink-0 tabular-nums text-right text-muted-foreground">
                          {seg.pct?.toFixed(1)}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {byDay.length === 0 && segments.length === 0 && (
                <p className="text-xs text-muted-foreground">No detailed analytics data available.</p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function formatShortDate(iso: string): string {
  try {
    const d = new Date(iso);
    return `${d.getMonth() + 1}/${d.getDate()}`;
  } catch {
    return iso;
  }
}

function formatNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}
