"use client";

import { useState } from "react";
import { PlayCircle, Shield, Upload, FolderOpen } from "lucide-react";
import { WorkspaceSelector } from "@/components/watchguard/WorkspaceSelector";
import { UploadZone } from "@/components/watchguard/UploadZone";
import { InvestigationProgress } from "@/components/watchguard/InvestigationProgress";
import { InvestigationResults } from "@/components/watchguard/InvestigationResults";
import { useInvestigation } from "@/hooks/useInvestigation";
import { cn } from "@/lib/utils";

type InputMode = "select" | "upload";

export default function WatchGuardPage() {
  const [mode, setMode] = useState<InputMode>("select");
  const [workspaceId, setWorkspaceId] = useState("");
  const [uploadWorkspaceId, setUploadWorkspaceId] = useState("");
  const { state, start, reset } = useInvestigation();

  // After a ZIP is staged, switch to select mode with the workspace pre-filled
  const handleStaged = (wsId: string) => {
    setWorkspaceId(wsId);
    setMode("select");
  };

  const activeWorkspace = mode === "select" ? workspaceId : uploadWorkspaceId;
  const canStart = activeWorkspace.trim() !== "" && state.phase === "idle";

  if (state.phase === "done" && state.result) {
    return (
      <div className="flex flex-col gap-8 p-8">
        <div>
          <h1 className="text-xl font-semibold text-foreground">WatchGuard Investigation</h1>
          <p className="mt-1 text-sm text-muted-foreground">Blue team analysis results</p>
        </div>
        <InvestigationResults result={state.result} onReset={reset} />
      </div>
    );
  }

  if (["staging", "detecting", "synthesizing"].includes(state.phase)) {
    return (
      <div className="flex flex-col gap-8 p-8">
        <div>
          <h1 className="text-xl font-semibold text-foreground">WatchGuard Investigation</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Analyzing workspace{" "}
            <span className="font-medium text-foreground">{activeWorkspace}</span>
          </p>
        </div>
        <div className="max-w-md">
          <InvestigationProgress state={state} />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8 p-8">
      <div>
        <h1 className="text-xl font-semibold text-foreground">WatchGuard Investigation</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Seleccioná un workspace existente o subí un nuevo ZIP
        </p>
      </div>

      <div className="max-w-lg">
        <div className="rounded-xl border border-border bg-card p-6 flex flex-col gap-5">
          <div className="flex items-center gap-2 text-sm font-medium text-foreground">
            <Shield className="size-4 text-primary" />
            Start Investigation
          </div>

          {/* Mode toggle */}
          <div className="flex rounded-lg border border-border overflow-hidden text-sm">
            {(
              [
                { id: "select", label: "Existing workspace", icon: FolderOpen },
                { id: "upload", label: "Upload new ZIP", icon: Upload },
              ] as const
            ).map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => setMode(id)}
                className={cn(
                  "flex flex-1 items-center justify-center gap-1.5 px-3 py-2 transition-colors",
                  mode === id
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )}
              >
                <Icon className="size-3.5" />
                {label}
              </button>
            ))}
          </div>

          {/* Select mode */}
          {mode === "select" && (
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Workspace
              </label>
              <WorkspaceSelector value={workspaceId} onChange={setWorkspaceId} />
            </div>
          )}

          {/* Upload mode */}
          {mode === "upload" && (
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Workspace ID
                </label>
                <input
                  placeholder="e.g. workspace-01"
                  value={uploadWorkspaceId}
                  onChange={(e) => setUploadWorkspaceId(e.target.value)}
                  className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none transition-colors"
                />
              </div>
              <UploadZone
                workspaceId={uploadWorkspaceId}
                onStaged={handleStaged}
              />
            </div>
          )}

          {state.phase === "error" && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
              {state.error}
            </div>
          )}

          <button
            disabled={!canStart}
            onClick={() => start(activeWorkspace.trim())}
            className="flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <PlayCircle className="size-4" />
            Launch Investigation
          </button>
        </div>
      </div>
    </div>
  );
}
