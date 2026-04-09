"use client";

import { useEffect, useState } from "react";
import { X, ExternalLink } from "lucide-react";
import { cn } from "@/lib/utils";
import { StatusBadge } from "@/components/common/StatusBadge";
import type { Case } from "@/lib/types";
import { api } from "@/lib/api";

const CLIENT_ID = process.env.NEXT_PUBLIC_DEFAULT_CLIENT_ID ?? "egs";

interface CasesSheetProps {
  open: boolean;
  onClose: () => void;
}

export function CasesSheet({ open, onClose }: CasesSheetProps) {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    api
      .get<{ cases: Case[] }>(`cases?client_id=${CLIENT_ID}&limit=20`)
      .then((r) => setCases(r.cases ?? []))
      .catch(() => setCases([]))
      .finally(() => setLoading(false));
  }, [open]);

  return (
    <>
      {/* Backdrop */}
      <div
        className={cn(
          "fixed inset-0 z-40 bg-black/50 transition-opacity",
          open ? "opacity-100" : "pointer-events-none opacity-0",
        )}
        onClick={onClose}
      />

      {/* Sheet */}
      <aside
        className={cn(
          "fixed inset-y-0 right-0 z-50 flex w-80 flex-col border-l border-border bg-card shadow-2xl transition-transform duration-300",
          open ? "translate-x-0" : "translate-x-full",
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">Case History</h2>
          <button
            onClick={onClose}
            className="rounded-lg p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          {loading && (
            <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
              Loading…
            </div>
          )}
          {!loading && cases.length === 0 && (
            <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
              No cases found.
            </div>
          )}
          {!loading &&
            cases.map((c) => (
              <CaseRow key={c.case_id} case={c} />
            ))}
        </div>
      </aside>
    </>
  );
}

function CaseRow({ case: c }: { case: Case }) {
  const isWatchGuard = c.title?.toLowerCase().includes("watchguard") ||
    c.metadata?.source === "watchguard";
  const age = timeAgo(c.created_at);

  return (
    <div className="flex flex-col gap-1.5 border-b border-border px-5 py-3.5 hover:bg-accent/30 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <p className="line-clamp-1 text-sm font-medium text-foreground">
          {c.title ?? c.case_id}
        </p>
        <ExternalLink className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
      </div>
      <div className="flex items-center gap-2">
        <StatusBadge status={c.status as "open" | "completed" | "failed" | "running" | "pending"} />
        <span className="text-xs text-muted-foreground">{isWatchGuard ? "WatchGuard" : "Phishing"}</span>
        <span className="ml-auto text-xs text-muted-foreground">{age}</span>
      </div>
    </div>
  );
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}
