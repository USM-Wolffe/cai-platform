import { cn } from "@/lib/utils";

type Status = "open" | "running" | "completed" | "failed" | "pending";

const STYLES: Record<Status, string> = {
  open: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  running: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  completed: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  failed: "bg-red-500/15 text-red-400 border-red-500/30",
  pending: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

const DOTS: Record<Status, string> = {
  open: "bg-blue-400",
  running: "bg-amber-400 animate-pulse",
  completed: "bg-emerald-400",
  failed: "bg-red-400",
  pending: "bg-zinc-400",
};

interface StatusBadgeProps {
  status: Status;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium",
        STYLES[status] ?? STYLES.pending,
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", DOTS[status] ?? DOTS.pending)} />
      {status}
    </span>
  );
}
