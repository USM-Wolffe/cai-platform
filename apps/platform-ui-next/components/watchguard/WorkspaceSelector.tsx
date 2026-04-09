"use client";

import { useEffect, useState } from "react";
import { ChevronDown, Plus, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface WorkspaceSelectorProps {
  value: string;
  onChange: (id: string) => void;
}

export function WorkspaceSelector({ value, onChange }: WorkspaceSelectorProps) {
  const [open, setOpen] = useState(false);
  const [workspaces, setWorkspaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [custom, setCustom] = useState("");

  useEffect(() => {
    if (!open || workspaces.length > 0) return;
    setLoading(true);
    fetch("/ui/api/proxy/s3/workspaces")
      .then((r) => r.json())
      .then((data) => setWorkspaces(data.workspaces ?? []))
      .catch(() => setWorkspaces([]))
      .finally(() => setLoading(false));
  }, [open, workspaces.length]);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "flex w-full items-center justify-between rounded-lg border border-border bg-background px-3 py-2 text-sm transition-colors",
          "hover:border-primary/50 focus:outline-none focus:border-primary",
          value ? "text-foreground" : "text-muted-foreground",
        )}
      >
        <span>{value || "Select workspace…"}</span>
        <ChevronDown
          className={cn("size-4 text-muted-foreground transition-transform", open && "rotate-180")}
        />
      </button>

      {open && (
        <div className="absolute z-10 mt-1 w-full rounded-lg border border-border bg-card shadow-lg">
          {loading && (
            <div className="flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground">
              <Loader2 className="size-3 animate-spin" /> Loading workspaces…
            </div>
          )}
          {!loading && workspaces.length === 0 && (
            <div className="px-3 py-2 text-xs text-muted-foreground">
              No staged workspaces found. Upload a ZIP first.
            </div>
          )}
          {workspaces.map((ws) => (
            <button
              key={ws}
              type="button"
              onClick={() => {
                onChange(ws);
                setOpen(false);
              }}
              className={cn(
                "flex w-full items-center px-3 py-2 text-sm transition-colors hover:bg-accent",
                ws === value && "text-primary font-medium",
              )}
            >
              {ws}
            </button>
          ))}

          {/* Manual entry */}
          <div className="border-t border-border p-2">
            <div className="flex gap-2">
              <input
                placeholder="Type workspace ID…"
                value={custom}
                onChange={(e) => setCustom(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && custom.trim()) {
                    onChange(custom.trim());
                    setOpen(false);
                  }
                }}
                className="flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary"
              />
              <button
                type="button"
                disabled={!custom.trim()}
                onClick={() => {
                  if (custom.trim()) {
                    onChange(custom.trim());
                    setOpen(false);
                  }
                }}
                className="flex items-center gap-1 rounded-md bg-primary px-2 py-1.5 text-xs font-medium text-primary-foreground disabled:opacity-50"
              >
                <Plus className="size-3" /> Use
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
