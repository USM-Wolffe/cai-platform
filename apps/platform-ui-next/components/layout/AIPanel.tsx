"use client";

import { useEffect, useRef, useState } from "react";
import { X, Send, Sparkles, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface AIPanelContext {
  workspace_id?: string;
  case_id?: string;
  run_id?: string;
  page?: string;
}

interface AIPanelProps {
  context?: AIPanelContext;
}

const CLIENT_ID = process.env.NEXT_PUBLIC_DEFAULT_CLIENT_ID ?? "egs";

export function AIPanel({ context }: AIPanelProps) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Scroll to bottom on new message
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  // Focus input when panel opens
  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 150);
  }, [open]);

  const send = async () => {
    const text = input.trim();
    if (!text || loading) return;

    const userMsg: Message = { role: "user", content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const res = await fetch("/ui/api/ai", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: text,
          client_id: CLIENT_ID,
          context: context ?? {},
          history: messages.map((m) => ({ role: m.role, content: m.content })),
        }),
      });

      const data = await res.json();
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: data.reply ?? "No response received." },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Connection error. Please try again." },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const contextLabel =
    context?.workspace_id
      ? `workspace: ${context.workspace_id}`
      : context?.page ?? "no context";

  return (
    <>
      {/* Floating toggle button */}
      <button
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "fixed bottom-6 right-6 z-50 flex items-center gap-1.5 rounded-full px-4 py-2.5 text-sm font-semibold shadow-lg transition-all",
          open
            ? "bg-zinc-700 text-zinc-200 hover:bg-zinc-600"
            : "bg-primary text-primary-foreground hover:bg-primary/90",
        )}
      >
        <Sparkles className="size-4" />
        {open ? "Close AI" : "AI"}
        {messages.length > 0 && !open && (
          <span className="ml-0.5 flex size-4 items-center justify-center rounded-full bg-white/20 text-xs">
            {messages.length}
          </span>
        )}
      </button>

      {/* Slide-in panel */}
      <aside
        className={cn(
          "fixed inset-y-0 right-0 z-40 flex w-96 flex-col border-l border-border bg-card shadow-2xl transition-transform duration-300",
          open ? "translate-x-0" : "translate-x-full",
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div>
            <div className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
              <Sparkles className="size-4 text-primary" />
              AI Assistant
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">{contextLabel}</p>
          </div>
          <button
            onClick={() => setOpen(false)}
            className="rounded-lg p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {messages.length === 0 && (
            <div className="flex flex-col items-center gap-2 py-12 text-center">
              <Sparkles className="size-6 text-muted-foreground/40" />
              <p className="text-xs text-muted-foreground">
                Ask anything about the current investigation or workspace.
              </p>
              {context?.workspace_id && (
                <div className="mt-2 flex flex-col gap-1.5 w-full text-left">
                  {[
                    "¿Cuáles son los IPs más activos?",
                    "¿Hay signos de DDoS?",
                    "¿Qué acción recomendás?",
                  ].map((q) => (
                    <button
                      key={q}
                      onClick={() => {
                        setInput(q);
                        inputRef.current?.focus();
                      }}
                      className="rounded-lg border border-border bg-background px-3 py-2 text-xs text-left text-muted-foreground hover:border-primary/50 hover:text-foreground transition-colors"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {messages.map((msg, i) => (
            <div
              key={i}
              className={cn(
                "flex flex-col gap-1",
                msg.role === "user" ? "items-end" : "items-start",
              )}
            >
              <div
                className={cn(
                  "max-w-[85%] rounded-xl px-3.5 py-2.5 text-sm leading-relaxed",
                  msg.role === "user"
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-secondary-foreground",
                )}
              >
                {msg.content}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex items-start">
              <div className="rounded-xl bg-secondary px-3.5 py-2.5">
                <Loader2 className="size-4 animate-spin text-muted-foreground" />
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div className="border-t border-border p-4">
          <div className="flex gap-2">
            <input
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  send();
                }
              }}
              placeholder="Preguntá algo…"
              disabled={loading}
              className="flex-1 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none transition-colors disabled:opacity-50"
            />
            <button
              onClick={send}
              disabled={!input.trim() || loading}
              className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-40"
            >
              <Send className="size-4" />
            </button>
          </div>
          {messages.length > 0 && (
            <button
              onClick={() => setMessages([])}
              className="mt-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              Clear conversation
            </button>
          )}
        </div>
      </aside>
    </>
  );
}
