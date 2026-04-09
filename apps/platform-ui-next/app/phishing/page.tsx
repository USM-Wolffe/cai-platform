"use client";

import { useState } from "react";
import { Mail, Search, RotateCcw, Loader2 } from "lucide-react";
import { VerdictCard } from "@/components/phishing/VerdictCard";
import { RulesList } from "@/components/phishing/RulesList";
import { URLSignals } from "@/components/phishing/URLSignals";
import { usePhishing } from "@/hooks/usePhishing";

const PLACEHOLDER = `{
  "from": "noreply@suspicious-domain.xyz",
  "subject": "URGENT: Account verification required",
  "body": "Click here to verify your account...",
  "urls": ["http://198.51.100.7/login"],
  "reply_to": "attacker@other-domain.com"
}`;

export default function PhishingPage() {
  const [input, setInput] = useState("");
  const { state, analyze, reset } = usePhishing();

  return (
    <div className="flex flex-col gap-8 p-8">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-foreground">Phishing Analysis</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Paste email JSON to get an AI-powered phishing verdict
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Input panel */}
        <div className="flex flex-col gap-4">
          <div className="rounded-xl border border-border bg-card p-5 flex flex-col gap-4">
            <div className="flex items-center gap-2 text-sm font-medium text-foreground">
              <Mail className="size-4 text-primary" />
              Email Input
            </div>

            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={PLACEHOLDER}
              rows={14}
              className="w-full resize-none rounded-lg border border-border bg-background px-3 py-2.5 font-mono text-xs text-foreground placeholder:text-muted-foreground/50 focus:border-primary focus:outline-none transition-colors"
            />

            {state.phase === "error" && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                {state.error}
              </div>
            )}

            <div className="flex gap-2">
              <button
                disabled={!input.trim() || state.phase === "analyzing"}
                onClick={() => analyze(input)}
                className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {state.phase === "analyzing" ? (
                  <>
                    <Loader2 className="size-4 animate-spin" />
                    Analyzing…
                  </>
                ) : (
                  <>
                    <Search className="size-4" />
                    Investigate
                  </>
                )}
              </button>
              {state.phase !== "idle" && (
                <button
                  onClick={() => { reset(); setInput(""); }}
                  className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-2 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                >
                  <RotateCcw className="size-3.5" />
                  Reset
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Results panel */}
        <div className="flex flex-col gap-4">
          {state.phase === "idle" && (
            <div className="flex h-full items-center justify-center rounded-xl border border-dashed border-border py-16 text-center">
              <div className="flex flex-col items-center gap-2">
                <Mail className="size-8 text-muted-foreground/40" />
                <p className="text-sm text-muted-foreground">Results will appear here</p>
              </div>
            </div>
          )}

          {state.phase === "analyzing" && (
            <div className="flex h-full items-center justify-center rounded-xl border border-border bg-card py-16">
              <div className="flex flex-col items-center gap-3">
                <Loader2 className="size-8 animate-spin text-primary" />
                <p className="text-sm text-muted-foreground">Analyzing email…</p>
              </div>
            </div>
          )}

          {state.phase === "done" && state.result && (
            <>
              <VerdictCard
                severity={state.result.verdict}
                score={state.result.score}
                action={state.result.action}
                summary={state.result.summary}
              />
              <RulesList rules={state.result.rules_triggered} />
              <URLSignals urls={state.result.suspicious_urls} />
            </>
          )}

          {state.phase === "error" && (
            <div className="flex h-full items-center justify-center rounded-xl border border-red-500/30 bg-red-500/5 py-16">
              <p className="text-sm text-red-400">Analysis failed. Check the error above.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
