"use client";

import { useCallback, useRef, useState } from "react";
import { Upload, FileArchive, X, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";

export type UploadPhase = "idle" | "uploading" | "staging" | "done" | "error";

interface UploadZoneProps {
  workspaceId: string;
  onStaged: (workspaceId: string) => void;
}

const CLIENT_ID = process.env.NEXT_PUBLIC_DEFAULT_CLIENT_ID ?? "egs";

export function UploadZone({ workspaceId, onStaged }: UploadZoneProps) {
  const [phase, setPhase] = useState<UploadPhase>("idle");
  const [progress, setProgress] = useState(0);
  const [fileName, setFileName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    async (file: File) => {
      if (!file.name.endsWith(".zip")) {
        setError("Only .zip files are supported.");
        return;
      }
      if (!workspaceId.trim()) {
        setError("Enter a workspace ID before uploading.");
        return;
      }

      setFileName(file.name);
      setError(null);
      setPhase("uploading");
      setProgress(0);

      try {
        // 1. Get presigned URL
        const urlRes = await fetch(
          `/ui/api/proxy/s3/presigned-upload-url?workspace_id=${encodeURIComponent(workspaceId)}`,
        );
        if (!urlRes.ok) throw new Error(`Failed to get upload URL: ${urlRes.status}`);
        const { presigned_url } = await urlRes.json();

        // 2. PUT file to S3 with progress tracking via XHR
        await uploadWithProgress(presigned_url, file, (pct) => setProgress(pct));

        // 3. Trigger staging
        setPhase("staging");
        setProgress(100);

        const stageRes = await fetch("/ui/api/stage", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ workspace_id: workspaceId, client_id: CLIENT_ID }),
        });
        if (!stageRes.ok) {
          const err = await stageRes.json().catch(() => ({ error: stageRes.statusText }));
          throw new Error(err.error ?? "Staging failed");
        }

        setPhase("done");
        onStaged(workspaceId);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Upload failed");
        setPhase("error");
      }
    },
    [workspaceId, onStaged],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const reset = () => {
    setPhase("idle");
    setProgress(0);
    setFileName(null);
    setError(null);
  };

  if (phase === "done") {
    return (
      <div className="flex items-center gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
        <CheckCircle2 className="size-4 shrink-0" />
        <span>
          <span className="font-medium">{fileName}</span> staged successfully for workspace{" "}
          <span className="font-medium">{workspaceId}</span>.
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div
        className={cn(
          "relative flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors",
          dragging
            ? "border-primary bg-primary/10"
            : "border-border hover:border-primary/50 hover:bg-accent/30",
          (phase === "uploading" || phase === "staging") && "pointer-events-none opacity-80",
        )}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => phase === "idle" && inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".zip"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
            e.target.value = "";
          }}
        />

        {phase === "idle" && (
          <>
            <Upload className="size-8 text-muted-foreground" />
            <div>
              <p className="text-sm font-medium text-foreground">
                Drop WatchGuard ZIP here
              </p>
              <p className="mt-0.5 text-xs text-muted-foreground">
                or click to browse — .zip files only
              </p>
            </div>
          </>
        )}

        {(phase === "uploading" || phase === "staging") && (
          <>
            <FileArchive className="size-8 text-primary" />
            <div className="w-full max-w-xs">
              <p className="mb-1.5 text-sm font-medium text-foreground">
                {phase === "uploading" ? `Uploading ${fileName}…` : "Staging workspace…"}
              </p>
              <div className="relative h-1.5 overflow-hidden rounded-full bg-secondary">
                <div
                  className="absolute inset-y-0 left-0 rounded-full bg-primary transition-all duration-300"
                  style={{
                    width: phase === "staging" ? "100%" : `${progress}%`,
                    animation: phase === "staging" ? "pulse 1.5s ease-in-out infinite" : "none",
                  }}
                />
              </div>
              {phase === "uploading" && (
                <p className="mt-1 text-xs text-muted-foreground text-right">{progress}%</p>
              )}
            </div>
          </>
        )}
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
          <X className="size-3.5 shrink-0" />
          {error}
          <button onClick={reset} className="ml-auto underline hover:no-underline">
            Retry
          </button>
        </div>
      )}
    </div>
  );
}

function uploadWithProgress(
  url: string,
  file: File,
  onProgress: (pct: number) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
    });
    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve();
      else reject(new Error(`S3 upload failed: ${xhr.status}`));
    });
    xhr.addEventListener("error", () => reject(new Error("Network error during upload")));
    xhr.open("PUT", url);
    xhr.setRequestHeader("Content-Type", "application/zip");
    xhr.send(file);
  });
}
