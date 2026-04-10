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
  cachedAt: string | null;
  error: string | null;
}

const IDLE: InvestigationState = {
  phase: "idle",
  stepLabel: "",
  stepsDone: 0,
  stepsTotal: 9,
  result: null,
  cachedAt: null,
  error: null,
};

export function useInvestigation() {
  const [state, setState] = useState<InvestigationState>(IDLE);

  /** Load a previous result without re-running the pipeline. */
  const loadCached = useCallback(async (workspaceId: string) => {
    setState({ ...IDLE, phase: "idle" });
    try {
      const res = await fetch(
        `/ui/api/investigate?workspace_id=${encodeURIComponent(workspaceId)}&client_id=${CLIENT_ID}`,
      );
      if (!res.ok) return;
      const data = await res.json();
      if (data.cached) {
        const { _cached_at, ...result } = data.cached as WatchGuardResult & { _cached_at?: string };
        setState({
          phase: "done",
          stepLabel: "Complete",
          stepsDone: 9,
          stepsTotal: 9,
          result: result as WatchGuardResult,
          cachedAt: _cached_at ?? null,
          error: null,
        });
      }
    } catch {
      // silent — no cached result available
    }
  }, []);

  /** Run a fresh investigation from scratch. */
  const start = useCallback(async (workspaceId: string) => {
    setState({
      phase: "staging",
      stepLabel: "Setting up case…",
      stepsDone: 0,
      stepsTotal: 9,
      result: null,
      cachedAt: null,
      error: null,
    });

    try {
      const res = await fetch(`/ui/api/investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ workspace_id: workspaceId, client_id: CLIENT_ID }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.error ?? `Investigation failed: ${res.status}`);
      }

      const data = await res.json();
      setState({
        phase: "done",
        stepLabel: "Complete",
        stepsDone: 9,
        stepsTotal: 9,
        result: data as WatchGuardResult,
        cachedAt: null,
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

  return { state, start, loadCached, reset };
}
