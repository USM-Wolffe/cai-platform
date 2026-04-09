"use client";

import { useState, useCallback } from "react";
import type { WatchGuardResult, InvestigationPhase } from "@/lib/types";

const CLIENT_ID = process.env.NEXT_PUBLIC_DEFAULT_CLIENT_ID ?? "egs";

export interface InvestigationState {
  phase: InvestigationPhase;
  stepLabel: string;
  stepsDone: number;
  stepsTotal: number;
  result: WatchGuardResult | null;
  error: string | null;
}

const IDLE: InvestigationState = {
  phase: "idle",
  stepLabel: "",
  stepsDone: 0,
  stepsTotal: 9,
  result: null,
  error: null,
};

export function useInvestigation() {
  const [state, setState] = useState<InvestigationState>(IDLE);

  const start = useCallback(async (workspaceId: string) => {
    setState({
      phase: "staging",
      stepLabel: "Setting up case…",
      stepsDone: 0,
      stepsTotal: 9,
      result: null,
      error: null,
    });

    try {
      // Call the investigation route (basePath /ui is the browser prefix for the page,
      // but fetch with absolute path needs it too since basePath isn't auto-prepended for fetch)
      const res = await fetch(`/ui/api/investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ workspace_id: workspaceId, client_id: CLIENT_ID }),
      });

      if (!res.ok) {
        throw new Error(`Investigation failed: ${res.status}`);
      }

      // Stream progress if available, otherwise poll
      const data = await res.json();
      setState({
        phase: "done",
        stepLabel: "Complete",
        stepsDone: 9,
        stepsTotal: 9,
        result: data as WatchGuardResult,
        error: null,
      });
    } catch (e) {
      setState((prev) => ({
        ...prev,
        phase: "error",
        error: e instanceof Error ? e.message : "Unknown error",
      }));
    }
  }, []);

  const reset = useCallback(() => setState(IDLE), []);

  return { state, start, reset };
}
