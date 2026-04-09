"use client";

import { cn } from "@/lib/utils";
import type { InvestigationState } from "@/hooks/useInvestigation";

const STEPS = [
  "Setting up case",
  "Attaching traffic logs",
  "Attaching alarm logs",
  "Creating run",
  "Normalizing events",
  "Detecting failed auth",
  "Detecting lateral movement",
  "Detecting privilege escalation",
  "Detecting DNS anomalies",
  "Detecting active threats",
  "Cross-source correlation",
  "AI synthesis",
];

interface InvestigationProgressProps {
  state: InvestigationState;
}

export function InvestigationProgress({ state }: InvestigationProgressProps) {
  const pct = state.stepsTotal > 0 ? (state.stepsDone / state.stepsTotal) * 100 : 0;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <p className="mb-1.5 text-sm font-medium text-foreground">{state.stepLabel || "Processing…"}</p>
        <div className="relative h-2 overflow-hidden rounded-full bg-secondary">
          <div
            className="absolute inset-y-0 left-0 rounded-full bg-primary transition-all duration-500"
            style={{ width: `${pct}%` }}
          />
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          {state.stepsDone} / {state.stepsTotal} steps
        </p>
      </div>

      <div className="space-y-1.5">
        {STEPS.slice(0, state.stepsTotal).map((step, i) => {
          const done = i < state.stepsDone;
          const active = i === state.stepsDone;
          return (
            <div key={step} className="flex items-center gap-2.5">
              <span
                className={cn(
                  "flex size-5 shrink-0 items-center justify-center rounded-full text-xs font-medium",
                  done
                    ? "bg-primary text-primary-foreground"
                    : active
                      ? "border-2 border-primary text-primary"
                      : "border border-border text-muted-foreground",
                )}
              >
                {done ? "✓" : i + 1}
              </span>
              <span
                className={cn(
                  "text-xs",
                  done ? "text-muted-foreground line-through" : active ? "text-foreground font-medium" : "text-muted-foreground",
                )}
              >
                {step}
              </span>
              {active && (
                <span className="ml-auto flex items-center gap-1 text-xs text-primary">
                  <span className="inline-block size-1.5 animate-pulse rounded-full bg-primary" />
                  running
                </span>
              )}
            </div>
          );
        })}
      </div>

      <p className="text-xs text-muted-foreground">
        This may take 3–8 minutes depending on log volume.
      </p>
    </div>
  );
}
