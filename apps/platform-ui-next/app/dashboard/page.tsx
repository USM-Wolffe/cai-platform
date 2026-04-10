"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Shield, Mail, FolderOpen, Activity, AlertTriangle } from "lucide-react";
import { MetricCard } from "@/components/common/MetricCard";
import { StatusBadge } from "@/components/common/StatusBadge";
import { RiskBadge } from "@/components/common/RiskBadge";
import { api } from "@/lib/api";
import type { Case, Severity } from "@/lib/types";

const CLIENT_ID = process.env.NEXT_PUBLIC_DEFAULT_CLIENT_ID ?? "egs";

export default function DashboardPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<{ cases: Array<{ case: Case }> }>(`cases?client_id=${CLIENT_ID}&limit=10`)
      .then((r) => setCases((r.cases ?? []).map((item) => item.case)))
      .catch(() => setCases([]))
      .finally(() => setLoading(false));
  }, []);

  const totalCases = cases.length;
  const activeCases = cases.filter((c) => c.status === "open").length;
  const phishingCases = cases.filter(
    (c) =>
      c.title?.toLowerCase().includes("phishing") ||
      String(c.metadata?.source ?? "").includes("phishing"),
  ).length;

  const highestSeverity: Severity =
    cases.some((c) => String(c.metadata?.severity ?? "") === "critical")
      ? "critical"
      : cases.some((c) => String(c.metadata?.severity ?? "") === "high")
        ? "high"
        : cases.some((c) => String(c.metadata?.severity ?? "") === "medium")
          ? "medium"
          : "unknown";

  return (
    <div className="flex flex-col gap-8 p-8">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-foreground">Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">Security operations overview</p>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard
          label="Total Cases"
          value={loading ? "—" : totalCases}
          icon={<FolderOpen className="size-4" />}
        />
        <MetricCard
          label="Active"
          value={loading ? "—" : activeCases}
          icon={<Activity className="size-4" />}
          accent={activeCases > 0}
        />
        <MetricCard
          label="Highest Risk"
          value={loading ? "—" : highestSeverity.toUpperCase()}
          icon={<AlertTriangle className="size-4" />}
          accent={["critical", "high"].includes(highestSeverity)}
        />
        <MetricCard
          label="Phishing"
          value={loading ? "—" : phishingCases}
          icon={<Mail className="size-4" />}
        />
      </div>

      {/* Quick actions */}
      <div className="flex gap-3">
        <Link
          href="/watchguard"
          className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
        >
          <Shield className="size-4" />
          New WatchGuard Investigation
        </Link>
        <Link
          href="/phishing"
          className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-accent"
        >
          <Mail className="size-4" />
          Analyze Email
        </Link>
      </div>

      {/* Recent cases table */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">Recent Investigations</h2>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
            Loading…
          </div>
        ) : cases.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
            <p className="text-sm text-muted-foreground">No investigations yet.</p>
            <Link href="/watchguard" className="text-sm text-primary hover:underline">
              Start your first investigation →
            </Link>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                {["Title", "Type", "Status", "Risk", "Date"].map((h) => (
                  <th
                    key={h}
                    className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => {
                const isWG =
                  c.title?.toLowerCase().includes("watchguard") ||
                  String(c.metadata?.source ?? "") === "watchguard";
                const severity = (c.metadata?.severity as Severity) ?? "unknown";
                return (
                  <tr
                    key={c.case_id}
                    className="border-b border-border last:border-0 hover:bg-accent/20 transition-colors"
                  >
                    <td className="px-5 py-3 font-medium text-foreground">
                      <span className="line-clamp-1 max-w-xs">{c.title ?? c.case_id}</span>
                    </td>
                    <td className="px-5 py-3 text-muted-foreground">
                      {isWG ? "WatchGuard" : "Phishing"}
                    </td>
                    <td className="px-5 py-3">
                      <StatusBadge
                        status={
                          c.status as "open" | "completed" | "failed" | "running" | "pending"
                        }
                      />
                    </td>
                    <td className="px-5 py-3">
                      {severity !== "unknown" && <RiskBadge severity={severity} />}
                    </td>
                    <td className="px-5 py-3 text-muted-foreground">
                      {new Date(c.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
