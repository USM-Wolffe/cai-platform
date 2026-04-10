"use client";

import { useState, useCallback } from "react";
import { api } from "@/lib/api";
import type { PhishingResult } from "@/lib/types";

const CLIENT_ID = process.env.NEXT_PUBLIC_DEFAULT_CLIENT_ID ?? "egs";

export type PhishingPhase = "idle" | "analyzing" | "done" | "error";

export interface PhishingState {
  phase: PhishingPhase;
  result: PhishingResult | null;
  error: string | null;
}

const IDLE: PhishingState = { phase: "idle", result: null, error: null };

export function usePhishing() {
  const [state, setState] = useState<PhishingState>(IDLE);

  const analyze = useCallback(async (rawJson: string) => {
    setState({ phase: "analyzing", result: null, error: null });

    try {
      let payload: unknown;
      try {
        payload = JSON.parse(rawJson);
      } catch {
        throw new Error("Invalid JSON. Please paste valid email JSON.");
      }

      // 1. Create case
      const { case: newCase } = await api.post<{ case: { case_id: string } }>("cases", {
        client_id: CLIENT_ID,
        workflow_type: "log_investigation",
        title: `Phishing analysis — ${new Date().toISOString()}`,
        summary: "Automated phishing email investigation.",
      });

      // 2. Attach input artifact
      const { artifact } = await api.post<{ artifact: { artifact_id: string } }>(
        `cases/${newCase.case_id}/artifacts/input`,
        { payload },
      );

      // 3. Create run
      const { run } = await api.post<{ run: { run_id: string } }>("runs", {
        case_id: newCase.case_id,
        backend_id: "phishing_email",
        input_artifact_ids: [artifact.artifact_id],
      });

      // 4. Run phishing assessment observation
      const obs = await api.post<{ artifacts: Array<{ artifact_id: string }> }>(
        `runs/${run.run_id}/observations/phishing-email-basic-assessment`,
        { input_artifact_id: artifact.artifact_id },
      );

      // 5. Fetch result artifact content
      const resultArtifactId = obs.artifacts?.[0]?.artifact_id;
      if (!resultArtifactId) throw new Error("No result artifact returned.");

      const content = await api.get<PhishingResult>(
        `artifacts/${resultArtifactId}/content`,
      );

      setState({ phase: "done", result: content, error: null });
    } catch (e) {
      setState({
        phase: "error",
        result: null,
        error: e instanceof Error ? e.message : "Unknown error",
      });
    }
  }, []);

  const reset = useCallback(() => setState(IDLE), []);

  return { state, analyze, reset };
}
