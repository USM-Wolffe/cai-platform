import { ShieldAlert, ShieldCheck } from "lucide-react";
import { RiskBadge } from "@/components/common/RiskBadge";
import type { Severity } from "@/lib/types";

interface VerdictCardProps {
  severity: Severity;
  score: number;
  action: string;
  summary: string;
}

export function VerdictCard({ severity, score, action, summary }: VerdictCardProps) {
  const isDangerous = ["critical", "high", "medium"].includes(severity);

  return (
    <div className="rounded-xl border border-border bg-card p-6 flex flex-col gap-4">
      <div className="flex items-center gap-3">
        {isDangerous ? (
          <ShieldAlert className="size-8 text-orange-400 shrink-0" />
        ) : (
          <ShieldCheck className="size-8 text-emerald-400 shrink-0" />
        )}
        <div>
          <RiskBadge severity={severity} size="lg" />
          <p className="mt-1 text-xs text-muted-foreground">Score: {score} pts</p>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background px-4 py-2.5">
        <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Recommended Action
        </p>
        <p className="mt-0.5 text-sm font-semibold text-foreground">{action}</p>
      </div>

      <p className="text-sm text-muted-foreground leading-relaxed">{summary}</p>
    </div>
  );
}
