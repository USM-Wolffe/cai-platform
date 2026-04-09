import { cn } from "@/lib/utils";
import type { PhishingRule, Severity } from "@/lib/types";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "border-red-500/30 bg-red-500/10 text-red-400",
  high: "border-orange-500/30 bg-orange-500/10 text-orange-400",
  medium: "border-amber-500/30 bg-amber-500/10 text-amber-400",
  low: "border-blue-500/30 bg-blue-500/10 text-blue-400",
  clean: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  unknown: "border-zinc-500/30 bg-zinc-500/10 text-zinc-400",
};

interface RulesListProps {
  rules: PhishingRule[];
}

export function RulesList({ rules }: RulesListProps) {
  if (rules.length === 0) return null;

  return (
    <div className="rounded-xl border border-border bg-card p-5 flex flex-col gap-3">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        Rules Triggered ({rules.length})
      </h3>
      <div className="space-y-2">
        {rules.map((rule) => (
          <div
            key={rule.rule_id}
            className={cn(
              "rounded-lg border px-3 py-2.5 flex items-start gap-2.5",
              SEVERITY_STYLES[rule.severity] ?? SEVERITY_STYLES.unknown,
            )}
          >
            <span className="mt-0.5 text-xs font-bold uppercase shrink-0">{rule.severity}</span>
            <div>
              <p className="text-sm font-medium">{rule.name}</p>
              {rule.description && (
                <p className="text-xs opacity-80 mt-0.5">{rule.description}</p>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
