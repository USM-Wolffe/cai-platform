import type { SuspiciousURL } from "@/lib/types";
import { ExternalLink } from "lucide-react";

interface URLSignalsProps {
  urls: SuspiciousURL[];
}

export function URLSignals({ urls }: URLSignalsProps) {
  if (urls.length === 0) return null;

  return (
    <div className="rounded-xl border border-border bg-card p-5 flex flex-col gap-3">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        Suspicious URLs ({urls.length})
      </h3>
      <div className="space-y-3">
        {urls.map((u, i) => (
          <div key={i} className="flex flex-col gap-1.5">
            <div className="flex items-center gap-1.5 font-mono text-xs text-orange-400 break-all">
              <ExternalLink className="size-3 shrink-0" />
              {u.url}
            </div>
            {u.reasons.length > 0 && (
              <div className="flex flex-wrap gap-1.5 ml-4">
                {u.reasons.map((r, j) => (
                  <span
                    key={j}
                    className="rounded-full border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-xs text-orange-400"
                  >
                    {r}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
