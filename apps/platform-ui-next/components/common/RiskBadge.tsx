import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const STYLES: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  clean: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  unknown: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

interface RiskBadgeProps {
  severity: Severity;
  size?: "sm" | "lg";
  className?: string;
}

export function RiskBadge({ severity, size = "sm", className }: RiskBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border font-semibold uppercase tracking-wider",
        size === "sm" ? "px-2 py-0.5 text-xs" : "px-4 py-1.5 text-sm",
        STYLES[severity] ?? STYLES.unknown,
        className,
      )}
    >
      {severity}
    </span>
  );
}
